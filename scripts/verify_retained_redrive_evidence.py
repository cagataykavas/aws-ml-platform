#!/usr/bin/env python3
"""Independently verify one exact retained redrive-evidence object version."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import re
import subprocess
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

try:
    from scripts.archive_network_incident_redrive_evidence import (
        ARCHIVE_KIND,
        SHA256_PATTERN,
        _bucket_name,
        _retention_time,
        _unique_object,
        _validate_envelope,
    )
    from scripts.seal_network_incident_redrive_evidence import _canonical
    from scripts.verify_network_incident_route import AwsCli, AwsClient
except ModuleNotFoundError:  # Direct execution from the scripts directory.
    from archive_network_incident_redrive_evidence import (
        ARCHIVE_KIND,
        SHA256_PATTERN,
        _bucket_name,
        _retention_time,
        _unique_object,
        _validate_envelope,
    )
    from seal_network_incident_redrive_evidence import _canonical
    from verify_network_incident_route import AwsCli, AwsClient


AUDIT_KIND = "network-incident-redrive-evidence-retention-audit"
RECEIPT_FIELDS = frozenset(
    {
        "bucket_sha256",
        "checksum_sha256",
        "evidence_sha256",
        "kind",
        "object_key_sha256",
        "retain_until",
        "retention_mode",
        "schema_version",
        "status",
        "version_id_sha256",
    }
)
OBJECT_KEY_PATTERN = re.compile(
    r"^redrive-evidence/v1/[1-9][0-9]{0,19}/(?:[1-9][0-9]?|100)/([0-9a-f]{64})[.]json$"
)


class EvidenceReader(AwsClient, Protocol):
    def get_object(
        self,
        *,
        bucket: str,
        key: str,
        version_id: str,
        expected_bucket_owner: str,
        region: str,
    ) -> tuple[dict[str, Any], bytes]: ...


class AwsEvidenceCli(AwsCli):
    """AWS CLI adapter that keeps the downloaded body out of command output."""

    def get_object(
        self,
        *,
        bucket: str,
        key: str,
        version_id: str,
        expected_bucket_owner: str,
        region: str,
    ) -> tuple[dict[str, Any], bytes]:
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "evidence.json"
            command = [
                self.executable,
                "s3api",
                "get-object",
                "--bucket",
                bucket,
                "--key",
                key,
                "--version-id",
                version_id,
                "--expected-bucket-owner",
                expected_bucket_owner,
                "--checksum-mode",
                "ENABLED",
                "--region",
                region,
                "--output",
                "json",
                "--no-cli-pager",
                str(destination),
            ]
            try:
                completed = subprocess.run(
                    command,
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout_seconds,
                )
            except FileNotFoundError as exc:
                raise RuntimeError(
                    f"AWS CLI executable not found: {self.executable}"
                ) from exc
            except subprocess.TimeoutExpired as exc:
                raise RuntimeError(
                    f"AWS CLI timed out after {self.timeout_seconds}s: s3api get-object"
                ) from exc
            if completed.returncode != 0:
                detail = completed.stderr.strip().replace("\n", " ")[:500]
                raise RuntimeError(
                    f"AWS CLI failed: s3api get-object: {detail or 'no error text'}"
                )
            try:
                response = json.loads(completed.stdout)
                body = destination.read_bytes()
            except (OSError, json.JSONDecodeError) as exc:
                raise RuntimeError("AWS CLI returned invalid S3 object output") from exc
        if not isinstance(response, dict):
            raise RuntimeError("AWS CLI returned a non-object S3 response")
        return response, body


@dataclass(frozen=True)
class ArchiveReceipt:
    bucket_sha256: str
    evidence_sha256: str
    object_key_sha256: str
    retain_until: str
    version_id_sha256: str

    @classmethod
    def from_document(cls, document: object) -> ArchiveReceipt:
        if (
            not isinstance(document, dict)
            or set(document) != RECEIPT_FIELDS
            or document.get("kind") != ARCHIVE_KIND
            or document.get("schema_version") != 1
            or document.get("status") != "pass"
            or document.get("retention_mode") != "COMPLIANCE"
        ):
            raise ValueError("archive receipt does not match the supported schema")
        hashes = (
            "bucket_sha256",
            "checksum_sha256",
            "evidence_sha256",
            "object_key_sha256",
            "version_id_sha256",
        )
        if any(
            not isinstance(document.get(name), str)
            or SHA256_PATTERN.fullmatch(document[name]) is None
            for name in hashes
        ) or document["checksum_sha256"] != document["evidence_sha256"]:
            raise ValueError("archive receipt has invalid or inconsistent commitments")
        retain_until = document.get("retain_until")
        try:
            _retention_time(retain_until)
        except RuntimeError as exc:
            raise ValueError("archive receipt has an invalid retain-until timestamp") from exc
        return cls(
            bucket_sha256=document["bucket_sha256"],
            evidence_sha256=document["evidence_sha256"],
            object_key_sha256=document["object_key_sha256"],
            retain_until=retain_until,
            version_id_sha256=document["version_id_sha256"],
        )

    def bind_target(self, *, bucket: str, key: str, version_id: str) -> None:
        match = OBJECT_KEY_PATTERN.fullmatch(key)
        if match is None or match.group(1) != self.evidence_sha256:
            raise ValueError("object key does not bind the archived evidence commitment")
        supplied = {
            "bucket_sha256": hashlib.sha256(bucket.encode("ascii")).hexdigest(),
            "object_key_sha256": hashlib.sha256(key.encode("ascii")).hexdigest(),
            "version_id_sha256": hashlib.sha256(version_id.encode("utf-8")).hexdigest(),
        }
        if any(getattr(self, name) != value for name, value in supplied.items()):
            raise ValueError("archive receipt does not bind the supplied S3 target")


def _load_json(path: str | Path, label: str) -> object:
    source = Path(path)
    if not source.is_file():
        raise ValueError(f"{label} does not exist or is not a file")
    try:
        return json.loads(
            source.read_text(encoding="utf-8"), object_pairs_hook=_unique_object
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read {label} JSON") from exc


def _canonical_base64(value: object, label: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} is missing")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"{label} is not canonical base64") from exc
    if base64.b64encode(decoded).decode("ascii") != value:
        raise ValueError(f"{label} is not canonical base64")
    return decoded


def verify_ecdsa_signature(
    public_key_der: bytes,
    signature_der: bytes,
    message: bytes,
    *,
    openssl: str = "openssl",
    timeout_seconds: int = 10,
) -> bool:
    """Verify the embedded P-256/SHA-256 signature without calling AWS KMS."""
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        public_der = root / "public.der"
        public_pem = root / "public.pem"
        signature = root / "signature.der"
        claims = root / "claims.json"
        public_der.write_bytes(public_key_der)
        signature.write_bytes(signature_der)
        claims.write_bytes(message)
        commands = (
            [
                openssl,
                "pkey",
                "-pubin",
                "-inform",
                "DER",
                "-in",
                str(public_der),
                "-out",
                str(public_pem),
            ],
            [
                openssl,
                "dgst",
                "-sha256",
                "-verify",
                str(public_pem),
                "-signature",
                str(signature),
                str(claims),
            ],
        )
        for index, command in enumerate(commands):
            try:
                completed = subprocess.run(
                    command,
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=timeout_seconds,
                )
            except FileNotFoundError as exc:
                raise RuntimeError(f"OpenSSL executable not found: {openssl}") from exc
            except subprocess.TimeoutExpired as exc:
                raise RuntimeError(
                    f"OpenSSL timed out after {timeout_seconds}s"
                ) from exc
            if completed.returncode != 0:
                if index == 0:
                    raise RuntimeError("embedded verification key is not valid DER SPKI")
                return False
    return True


def verify_retained_evidence(
    aws: EvidenceReader,
    receipt: ArchiveReceipt,
    *,
    bucket: str,
    key: str,
    version_id: str,
    owner_account_id: str,
    region: str,
    signature_verifier: Callable[[bytes, bytes, bytes], bool] = verify_ecdsa_signature,
) -> dict[str, object]:
    bucket = _bucket_name(bucket)
    if re.fullmatch(r"[0-9]{12}", owner_account_id) is None:
        raise ValueError("archive owner account ID must contain 12 digits")
    if not version_id or version_id == "null" or len(version_id) > 1024:
        raise ValueError("S3 version ID is missing or invalid")
    receipt.bind_target(bucket=bucket, key=key, version_id=version_id)
    common = {
        "bucket": bucket,
        "key": key,
        "version_id": version_id,
        "expected_bucket_owner": owner_account_id,
        "region": region,
    }
    response, payload = aws.get_object(**common)
    digest = hashlib.sha256(payload).digest()
    checksum = base64.b64encode(digest).decode("ascii")
    if (
        digest.hex() != receipt.evidence_sha256
        or response.get("ChecksumSHA256") != checksum
        or response.get("ServerSideEncryption") != "AES256"
        or response.get("VersionId") != version_id
        or response.get("ContentType") != "application/json"
    ):
        raise RuntimeError("retained object identity, checksum or encryption is invalid")
    try:
        envelope = _validate_envelope(
            json.loads(payload.decode("ascii"), object_pairs_hook=_unique_object)
        )
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise RuntimeError("retained object is not a valid evidence envelope") from exc
    if _canonical(envelope) != payload:
        raise RuntimeError("retained evidence is not canonical JSON")

    claims = envelope["claims"]
    public_key = _canonical_base64(
        envelope["verification_key"]["value"], "verification key"
    )
    signature = _canonical_base64(envelope["signature"]["value"], "signature")
    if (
        claims.get("signing_algorithm") != "ECDSA_SHA_256"
        or hashlib.sha256(public_key).hexdigest() != claims.get("public_key_sha256")
        or not signature_verifier(public_key, signature, _canonical(claims))
    ):
        raise RuntimeError("retained evidence signature is invalid")

    retained = aws.call("s3api", "get-object-retention", **common).get("Retention", {})
    response_until = _retention_time(response.get("ObjectLockRetainUntilDate"))
    retained_until = _retention_time(retained.get("RetainUntilDate"))
    receipt_until = _retention_time(receipt.retain_until)
    if (
        response.get("ObjectLockMode") != "COMPLIANCE"
        or retained.get("Mode") != "COMPLIANCE"
        or response_until < receipt_until
        or retained_until < receipt_until
    ):
        raise RuntimeError("retained object no longer satisfies its compliance lock receipt")
    return {
        "bucket_sha256": receipt.bucket_sha256,
        "evidence_sha256": receipt.evidence_sha256,
        "kind": AUDIT_KIND,
        "object_key_sha256": receipt.object_key_sha256,
        "retain_until": retained_until.isoformat().replace("+00:00", "Z"),
        "retention_mode": "COMPLIANCE",
        "schema_version": 1,
        "signature_verified": True,
        "status": "pass",
        "storage_checksum_verified": True,
        "version_id_sha256": receipt.version_id_sha256,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Audit one exact Object Lock evidence version using read-only credentials."
    )
    parser.add_argument("retention_receipt")
    parser.add_argument("--bucket", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--version-id", required=True)
    parser.add_argument("--owner-account-id", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--aws-cli", default="aws")
    parser.add_argument("--openssl", default="openssl")
    parser.add_argument("--timeout-seconds", type=int, default=30)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        receipt = ArchiveReceipt.from_document(
            _load_json(args.retention_receipt, "archive receipt")
        )
        aws = AwsEvidenceCli(
            executable=args.aws_cli, timeout_seconds=args.timeout_seconds
        )
        audit = verify_retained_evidence(
            aws,
            receipt,
            bucket=args.bucket,
            key=args.key,
            version_id=args.version_id,
            owner_account_id=args.owner_account_id,
            region=args.region,
            signature_verifier=lambda public_key, signature, message: verify_ecdsa_signature(
                public_key,
                signature,
                message,
                openssl=args.openssl,
                timeout_seconds=min(args.timeout_seconds, 30),
            ),
        )
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"retained evidence audit failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(audit, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
