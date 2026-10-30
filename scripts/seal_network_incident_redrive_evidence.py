#!/usr/bin/env python3
"""Seal paired redrive evidence with an asymmetric AWS KMS key."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import re
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    from scripts.run_network_incident_redrive_canary import (
        AUTHORIZATION_ID_PATTERN,
        PreflightAuthorization,
        RedriveRoute,
    )
    from scripts.verify_network_incident_route import AwsCli, AwsClient, _parse_arn
except ModuleNotFoundError:  # Direct execution from the scripts directory.
    from run_network_incident_redrive_canary import (
        AUTHORIZATION_ID_PATTERN,
        PreflightAuthorization,
        RedriveRoute,
    )
    from verify_network_incident_route import AwsCli, AwsClient, _parse_arn


EVIDENCE_KIND = "network-incident-redrive-evidence"
SIGNING_ALGORITHM = "ECDSA_SHA_256"
KEY_SPEC = "ECC_NIST_P256"
KEY_ID_PATTERN = re.compile(
    r"(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|mrk-[0-9a-f]{32})"
)
CANARY_FIELDS = frozenset(
    {
        "observed",
        "preflight_sha256",
        "route_sha256",
        "run_id",
        "schema_version",
        "status",
    }
)


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise ValueError("redrive evidence is not canonicalizable") from exc


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("redrive evidence JSON contains duplicate keys")
        result[key] = value
    return result


def _load(path: str | Path) -> Any:
    source = Path(path)
    if not source.is_file():
        raise ValueError(
            f"redrive evidence input does not exist or is not a file: {source}"
        )
    try:
        return json.loads(
            source.read_text(encoding="utf-8"), object_pairs_hook=_unique_object
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("cannot read redrive evidence JSON") from exc


@dataclass(frozen=True)
class EvidencePair:
    authorization_id: str
    run_id: str
    route_sha256: str
    preflight_sha256: str
    canary_sha256: str

    @classmethod
    def from_documents(
        cls,
        route: RedriveRoute,
        preflight: Any,
        canary: Any,
        authorization_id: str,
    ) -> EvidencePair:
        authorization = PreflightAuthorization.from_document(
            preflight, route, authorization_id
        )
        if not isinstance(canary, dict) or set(canary) != CANARY_FIELDS:
            raise ValueError("canary receipt fields do not match the sealing schema")
        if canary.get("status") != "pass" or canary.get("schema_version") != 2:
            raise ValueError("canary receipt is not a passing supported result")
        if canary.get("route_sha256") != route.digest():
            raise ValueError("canary receipt does not match the reviewed queue route")
        if canary.get("preflight_sha256") != authorization.receipt_sha256:
            raise ValueError("canary receipt is not linked to the supplied preflight")
        run_id = canary.get("run_id")
        if (
            not isinstance(run_id, str)
            or AUTHORIZATION_ID_PATTERN.fullmatch(run_id) is None
        ):
            raise ValueError("canary receipt run_id is not a stable identifier")
        observed = canary.get("observed")
        if not isinstance(observed, dict) or not observed:
            raise ValueError("canary receipt has no bounded observation evidence")
        return cls(
            authorization_id=authorization.authorization_id,
            run_id=run_id,
            route_sha256=route.digest(),
            preflight_sha256=authorization.receipt_sha256,
            canary_sha256=hashlib.sha256(_canonical(canary)).hexdigest(),
        )


@dataclass(frozen=True)
class KmsSigningKey:
    arn: str
    key_id: str
    public_key_base64: str
    public_key_sha256: str
    revision_sha256: str
    region: str

    @classmethod
    def inspect(
        cls, aws: AwsClient, key_arn: str, route: RedriveRoute
    ) -> KmsSigningKey:
        parsed = _parse_arn(key_arn, expected_service="kms")
        if (
            parsed[0] != route.partition
            or parsed[2] != route.region
            or parsed[3] != route.account_id
            or not parsed[4].startswith("key/")
        ):
            raise ValueError(
                "evidence signing key must be a key ARN in the drill partition, Region and account"
            )
        arn_key_id = parsed[4].removeprefix("key/")
        if KEY_ID_PATTERN.fullmatch(arn_key_id) is None:
            raise ValueError("evidence signing key ARN has an invalid key ID")

        metadata = aws.call(
            "kms", "describe-key", key_id=key_arn, region=route.region
        ).get("KeyMetadata")
        if not isinstance(metadata, dict):
            raise RuntimeError(  # noqa: TRY004 - malformed provider response, not caller type
                "AWS KMS returned invalid signing-key metadata"
            )
        key_id = metadata.get("KeyId")
        if (
            metadata.get("Arn") != key_arn
            or key_id != arn_key_id
            or metadata.get("Enabled") is not True
            or metadata.get("KeyState") != "Enabled"
            or metadata.get("KeyManager") != "CUSTOMER"
            or metadata.get("KeyUsage") != "SIGN_VERIFY"
            or metadata.get("KeySpec") != KEY_SPEC
            or SIGNING_ALGORITHM not in metadata.get("SigningAlgorithms", [])
        ):
            raise RuntimeError("AWS KMS signing key differs from the reviewed contract")

        public = aws.call("kms", "get-public-key", key_id=key_arn, region=route.region)
        public_key = _base64(public.get("PublicKey"), "AWS KMS public key")
        if (
            public.get("KeyId") not in {key_arn, key_id}
            or public.get("KeyUsage") != "SIGN_VERIFY"
            or public.get("KeySpec") != KEY_SPEC
            or SIGNING_ALGORITHM not in public.get("SigningAlgorithms", [])
            or not 64 <= len(public_key) <= 1024
        ):
            raise RuntimeError(
                "AWS KMS public key response differs from the reviewed contract"
            )
        public_key_sha256 = hashlib.sha256(public_key).hexdigest()
        revision = {
            "key_arn": key_arn,
            "key_id": key_id,
            "key_spec": KEY_SPEC,
            "key_usage": "SIGN_VERIFY",
            "provider": "aws-kms",
            "public_key_sha256": public_key_sha256,
            "signing_algorithm": SIGNING_ALGORITHM,
        }
        return cls(
            arn=key_arn,
            key_id=key_id,
            public_key_base64=base64.b64encode(public_key).decode("ascii"),
            public_key_sha256=public_key_sha256,
            revision_sha256=hashlib.sha256(_canonical(revision)).hexdigest(),
            region=route.region,
        )

    def seal(self, aws: AwsClient, pair: EvidencePair) -> dict[str, object]:
        claims = {
            "authorization_id": pair.authorization_id,
            "canary_sha256": pair.canary_sha256,
            "key_arn": self.arn,
            "key_revision_sha256": self.revision_sha256,
            "kind": EVIDENCE_KIND,
            "preflight_sha256": pair.preflight_sha256,
            "public_key_sha256": self.public_key_sha256,
            "route_sha256": pair.route_sha256,
            "run_id": pair.run_id,
            "schema_version": 1,
            "signing_algorithm": SIGNING_ALGORITHM,
        }
        message = _canonical(claims)
        if len(message) > 4096:
            raise ValueError(
                "redrive evidence claims exceed the AWS KMS raw-message limit"
            )
        with tempfile.NamedTemporaryFile() as message_file:
            message_file.write(message)
            message_file.flush()
            response = aws.call(
                "kms",
                "sign",
                key_id=self.arn,
                message=f"fileb://{message_file.name}",
                message_type="RAW",
                signing_algorithm=SIGNING_ALGORITHM,
                region=self.region,
            )
            signature = _base64(response.get("Signature"), "AWS KMS signature")
            if (
                response.get("KeyId") not in {self.arn, self.key_id}
                or response.get("SigningAlgorithm") != SIGNING_ALGORITHM
                or not 64 <= len(signature) <= 144
            ):
                raise RuntimeError(
                    "AWS KMS signing response differs from the reviewed contract"
                )
            with tempfile.NamedTemporaryFile() as signature_file:
                signature_file.write(signature)
                signature_file.flush()
                verification = aws.call(
                    "kms",
                    "verify",
                    key_id=self.arn,
                    message=f"fileb://{message_file.name}",
                    message_type="RAW",
                    signature=f"fileb://{signature_file.name}",
                    signing_algorithm=SIGNING_ALGORITHM,
                    region=self.region,
                )
        if (
            verification.get("KeyId") not in {self.arn, self.key_id}
            or verification.get("SigningAlgorithm") != SIGNING_ALGORITHM
            or verification.get("SignatureValid") is not True
        ):
            raise RuntimeError("AWS KMS did not verify the evidence signature")
        return {
            "claims": claims,
            "signature": {
                "encoding": "base64",
                "value": base64.b64encode(signature).decode("ascii"),
            },
            "verification_key": {
                "encoding": "base64-der-subject-public-key-info",
                "value": self.public_key_base64,
            },
        }


def _base64(value: object, label: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise RuntimeError(f"{label} is missing")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise RuntimeError(f"{label} is not canonical base64") from exc
    if base64.b64encode(decoded).decode("ascii") != value:
        raise RuntimeError(f"{label} is not canonical base64")
    return decoded


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Seal linked redrive receipts with the reviewed AWS KMS signing key."
    )
    parser.add_argument("route_json")
    parser.add_argument("--preflight-receipt", required=True)
    parser.add_argument("--canary-receipt", required=True)
    parser.add_argument("--authorization-id", required=True)
    parser.add_argument("--kms-key-arn", required=True)
    parser.add_argument("--aws-cli", default="aws")
    parser.add_argument("--timeout-seconds", type=int, default=30)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        route = RedriveRoute.from_document(_load(args.route_json))
        pair = EvidencePair.from_documents(
            route,
            _load(args.preflight_receipt),
            _load(args.canary_receipt),
            args.authorization_id,
        )
        aws = AwsCli(executable=args.aws_cli, timeout_seconds=args.timeout_seconds)
        key = KmsSigningKey.inspect(aws, args.kms_key_arn, route)
        envelope = key.seal(aws, pair)
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"refusing to seal redrive evidence: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(envelope, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
