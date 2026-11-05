#!/usr/bin/env python3
"""Issue and independently verify a short-lived backend admission lease."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import re
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

try:
    from scripts.audit_live_terraform_backend import _canonical, _load_receipt
    from scripts.audit_terraform_backend import _now_utc, _observed_at, _write_atomic
    from scripts.verify_network_incident_route import AwsCli, AwsClient, _parse_arn
    from scripts.verify_retained_redrive_evidence import verify_ecdsa_signature
    from scripts.verify_terraform_backend_admission import BACKEND_ADMISSION_SCHEMA
except ModuleNotFoundError:  # Direct execution from the scripts directory.
    from audit_live_terraform_backend import _canonical, _load_receipt
    from audit_terraform_backend import _now_utc, _observed_at, _write_atomic
    from verify_network_incident_route import AwsCli, AwsClient, _parse_arn
    from verify_retained_redrive_evidence import verify_ecdsa_signature
    from verify_terraform_backend_admission import BACKEND_ADMISSION_SCHEMA


LEASE_KIND = "terraform-backend-admission-lease"
LEASE_AUDIT_KIND = "terraform-backend-admission-lease-audit"
LEASE_SCHEMA_VERSION = 1
SIGNING_ALGORITHM = "ECDSA_SHA_256"
KEY_SPEC = "ECC_NIST_P256"
MAX_TTL_SECONDS = 10 * 60

_DIGEST = re.compile(r"[0-9a-f]{64}")
_ACCOUNT_ID = re.compile(r"[0-9]{12}")
_KEY_ID = re.compile(
    r"(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    r"|mrk-[0-9a-f]{32})"
)
_AUTHORIZATION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_WORKFLOW_SHA = re.compile(r"[0-9a-f]{40}")
_WORKFLOW_SUBJECT = re.compile(r"repo:[^:/\s]+/[^:\s]+:environment:[^\s]{1,128}")

_ADMISSION_FIELDS = frozenset(
    {
        "accepted",
        "authorization_sha256",
        "backend_audit_sha256",
        "backend_configuration_verified",
        "conditional_lock_verified",
        "deployment_boundary_sha256",
        "evidence_freshness_verified",
        "evidence_sha256",
        "evidence_window_sha256",
        "exact_cleanup_verified",
        "live_backend_audit_sha256",
        "live_controls_verified",
        "lock_canary_sha256",
        "release_to_plan",
        "schema_version",
    }
)
_ADMISSION_DIGEST_FIELDS = frozenset(
    {
        "authorization_sha256",
        "backend_audit_sha256",
        "deployment_boundary_sha256",
        "evidence_sha256",
        "evidence_window_sha256",
        "live_backend_audit_sha256",
        "lock_canary_sha256",
    }
)
_ADMISSION_CHECKS = frozenset(
    {
        "accepted",
        "backend_configuration_verified",
        "conditional_lock_verified",
        "evidence_freshness_verified",
        "exact_cleanup_verified",
        "live_controls_verified",
        "release_to_plan",
    }
)
_CLAIM_FIELDS = frozenset(
    {
        "admission_evidence_sha256",
        "authorization_sha256",
        "deployment_boundary_sha256",
        "evidence_window_sha256",
        "expires_at",
        "issued_at",
        "key_arn_sha256",
        "key_revision_sha256",
        "kind",
        "max_ttl_seconds",
        "public_key_sha256",
        "schema_version",
        "signing_algorithm",
        "workflow_sha256",
        "workflow_subject_sha256",
    }
)


class BackendAdmissionLeaseError(ValueError):
    """The lease is invalid, expired, or not bound to the reviewed release."""

    code = "TERRAFORM_BACKEND_ADMISSION_LEASE_INVALID"

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(f"{self.code}: {reason}")


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _canonical_base64(value: object, label: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise BackendAdmissionLeaseError(f"{label} is missing")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise BackendAdmissionLeaseError(
            f"{label} is not canonical base64"
        ) from exc
    if base64.b64encode(decoded).decode("ascii") != value:
        raise BackendAdmissionLeaseError(f"{label} is not canonical base64")
    return decoded


def _timestamp(value: object, label: str) -> datetime:
    if not isinstance(value, str):
        raise BackendAdmissionLeaseError(f"{label} is not canonical UTC")
    try:
        canonical = _observed_at(value)
    except (TypeError, ValueError) as exc:
        raise BackendAdmissionLeaseError(f"{label} is not canonical UTC") from exc
    return datetime.strptime(canonical, "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )


def _format_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _authorization_id(value: str) -> str:
    if not isinstance(value, str) or _AUTHORIZATION_ID.fullmatch(value) is None:
        raise BackendAdmissionLeaseError("authorization ID is invalid")
    return value


def _workflow_subject(value: str) -> str:
    if not isinstance(value, str) or _WORKFLOW_SUBJECT.fullmatch(value) is None:
        raise BackendAdmissionLeaseError(
            "workflow subject must identify one GitHub Environment"
        )
    return value


def _workflow_sha(value: str) -> str:
    if not isinstance(value, str) or _WORKFLOW_SHA.fullmatch(value) is None:
        raise BackendAdmissionLeaseError("workflow SHA must be a lowercase commit SHA")
    return value


def _kms_key_arn(value: str) -> str:
    try:
        parsed = _parse_arn(value, expected_service="kms")
    except ValueError as exc:
        raise BackendAdmissionLeaseError("lease key ARN is invalid") from exc
    key_id = parsed[4].removeprefix("key/")
    if (
        parsed[0] not in {"aws", "aws-us-gov", "aws-cn"}
        or not parsed[2]
        or _ACCOUNT_ID.fullmatch(parsed[3]) is None
        or not parsed[4].startswith("key/")
        or _KEY_ID.fullmatch(key_id) is None
    ):
        raise BackendAdmissionLeaseError("lease key ARN is invalid")
    return value


@dataclass(frozen=True)
class BackendAdmission:
    evidence_sha256: str
    evidence_window_sha256: str
    deployment_boundary_sha256: str
    authorization_sha256: str

    @classmethod
    def from_document(cls, document: object) -> BackendAdmission:
        if not isinstance(document, dict) or set(document) != _ADMISSION_FIELDS:
            raise BackendAdmissionLeaseError(
                "backend admission receipt fields do not match the schema"
            )
        if document.get("schema_version") != BACKEND_ADMISSION_SCHEMA or any(
            document.get(name) is not True for name in _ADMISSION_CHECKS
        ):
            raise BackendAdmissionLeaseError(
                "backend admission receipt is not a passing supported decision"
            )
        if any(
            not isinstance(document.get(name), str)
            or _DIGEST.fullmatch(document[name]) is None
            for name in _ADMISSION_DIGEST_FIELDS
        ):
            raise BackendAdmissionLeaseError(
                "backend admission receipt contains an invalid commitment"
            )
        unsigned = {
            key: value for key, value in document.items() if key != "evidence_sha256"
        }
        if hashlib.sha256(_canonical(unsigned)).hexdigest() != document[
            "evidence_sha256"
        ]:
            raise BackendAdmissionLeaseError(
                "backend admission receipt self-digest is invalid"
            )
        return cls(
            evidence_sha256=document["evidence_sha256"],
            evidence_window_sha256=document["evidence_window_sha256"],
            deployment_boundary_sha256=document["deployment_boundary_sha256"],
            authorization_sha256=document["authorization_sha256"],
        )

    def bind_authorization(self, authorization_id: str) -> None:
        if self.authorization_sha256 != _sha256_text(
            _authorization_id(authorization_id)
        ):
            raise BackendAdmissionLeaseError(
                "backend admission receipt does not bind this authorization"
            )


def _key_revision_sha256(key_arn: str, public_key_sha256: str) -> str:
    revision = {
        "key_arn": key_arn,
        "key_spec": KEY_SPEC,
        "key_usage": "SIGN_VERIFY",
        "provider": "aws-kms",
        "public_key_sha256": public_key_sha256,
        "signing_algorithm": SIGNING_ALGORITHM,
    }
    return hashlib.sha256(_canonical(revision)).hexdigest()


@dataclass(frozen=True)
class KmsLeaseKey:
    arn: str
    key_id: str
    public_key: bytes
    public_key_sha256: str
    revision_sha256: str
    region: str

    @classmethod
    def inspect(
        cls,
        aws: AwsClient,
        key_arn: str,
        *,
        partition: str,
        account_id: str,
        region: str,
    ) -> KmsLeaseKey:
        if _ACCOUNT_ID.fullmatch(account_id) is None:
            raise BackendAdmissionLeaseError("AWS account ID must contain 12 digits")
        key_arn = _kms_key_arn(key_arn)
        parsed = _parse_arn(key_arn, expected_service="kms")
        if (
            parsed[0] != partition
            or parsed[2] != region
            or parsed[3] != account_id
            or not parsed[4].startswith("key/")
        ):
            raise BackendAdmissionLeaseError(
                "lease key must be in the release partition, Region and account"
            )
        key_id = parsed[4].removeprefix("key/")
        if _KEY_ID.fullmatch(key_id) is None:
            raise BackendAdmissionLeaseError("lease key ARN has an invalid key ID")

        metadata = aws.call(
            "kms", "describe-key", key_id=key_arn, region=region
        ).get("KeyMetadata")
        if not isinstance(metadata, dict):
            raise RuntimeError("AWS KMS returned invalid lease-key metadata")
        if (
            metadata.get("Arn") != key_arn
            or metadata.get("KeyId") != key_id
            or metadata.get("Enabled") is not True
            or metadata.get("KeyState") != "Enabled"
            or metadata.get("KeyManager") != "CUSTOMER"
            or metadata.get("KeyUsage") != "SIGN_VERIFY"
            or metadata.get("KeySpec") != KEY_SPEC
            or SIGNING_ALGORITHM not in metadata.get("SigningAlgorithms", [])
        ):
            raise RuntimeError("AWS KMS lease key differs from the reviewed contract")

        response = aws.call(
            "kms", "get-public-key", key_id=key_arn, region=region
        )
        public_key = _canonical_base64(response.get("PublicKey"), "AWS KMS public key")
        if (
            response.get("KeyId") not in {key_arn, key_id}
            or response.get("KeyUsage") != "SIGN_VERIFY"
            or response.get("KeySpec") != KEY_SPEC
            or SIGNING_ALGORITHM not in response.get("SigningAlgorithms", [])
            or not 64 <= len(public_key) <= 1024
        ):
            raise RuntimeError(
                "AWS KMS public key response differs from the reviewed contract"
            )
        public_key_sha256 = hashlib.sha256(public_key).hexdigest()
        return cls(
            arn=key_arn,
            key_id=key_id,
            public_key=public_key,
            public_key_sha256=public_key_sha256,
            revision_sha256=_key_revision_sha256(key_arn, public_key_sha256),
            region=region,
        )

    def issue(
        self,
        aws: AwsClient,
        admission: BackendAdmission,
        *,
        authorization_id: str,
        workflow_subject: str,
        workflow_sha: str,
        issued_at: str,
        ttl_seconds: int,
    ) -> dict[str, object]:
        admission.bind_authorization(authorization_id)
        workflow_subject = _workflow_subject(workflow_subject)
        workflow_sha = _workflow_sha(workflow_sha)
        if isinstance(ttl_seconds, bool) or not 1 <= ttl_seconds <= MAX_TTL_SECONDS:
            raise BackendAdmissionLeaseError(
                f"lease TTL must be between 1 and {MAX_TTL_SECONDS} seconds"
            )
        issued = _timestamp(issued_at, "lease issue time")
        expires_at = _format_timestamp(issued + timedelta(seconds=ttl_seconds))
        claims: dict[str, object] = {
            "admission_evidence_sha256": admission.evidence_sha256,
            "authorization_sha256": admission.authorization_sha256,
            "deployment_boundary_sha256": admission.deployment_boundary_sha256,
            "evidence_window_sha256": admission.evidence_window_sha256,
            "expires_at": expires_at,
            "issued_at": _format_timestamp(issued),
            "key_arn_sha256": _sha256_text(self.arn),
            "key_revision_sha256": self.revision_sha256,
            "kind": LEASE_KIND,
            "max_ttl_seconds": MAX_TTL_SECONDS,
            "public_key_sha256": self.public_key_sha256,
            "schema_version": LEASE_SCHEMA_VERSION,
            "signing_algorithm": SIGNING_ALGORITHM,
            "workflow_sha256": _sha256_text(workflow_sha),
            "workflow_subject_sha256": _sha256_text(workflow_subject),
        }
        message = _canonical(claims)
        if len(message) > 4096:
            raise BackendAdmissionLeaseError(
                "lease claims exceed the AWS KMS raw-message limit"
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
            signature = _canonical_base64(
                response.get("Signature"), "AWS KMS signature"
            )
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
            raise RuntimeError("AWS KMS did not verify the admission lease signature")
        return {
            "claims": claims,
            "signature": {
                "encoding": "base64",
                "value": base64.b64encode(signature).decode("ascii"),
            },
            "verification_key": {
                "encoding": "base64-der-subject-public-key-info",
                "value": base64.b64encode(self.public_key).decode("ascii"),
            },
        }


def verify_lease(
    envelope: object,
    admission_document: object,
    *,
    key_arn: str,
    expected_public_key_sha256: str,
    authorization_id: str,
    workflow_subject: str,
    workflow_sha: str,
    verification_time: str,
    signature_verifier: Callable[[bytes, bytes, bytes], bool] = verify_ecdsa_signature,
) -> dict[str, object]:
    """Verify the exact receipt, provenance, pinned key, lifetime, and signature."""

    admission = BackendAdmission.from_document(admission_document)
    admission.bind_authorization(authorization_id)
    key_arn = _kms_key_arn(key_arn)
    workflow_subject = _workflow_subject(workflow_subject)
    workflow_sha = _workflow_sha(workflow_sha)
    if _DIGEST.fullmatch(expected_public_key_sha256) is None:
        raise BackendAdmissionLeaseError("expected public-key digest is invalid")
    if not isinstance(envelope, dict) or set(envelope) != {
        "claims",
        "signature",
        "verification_key",
    }:
        raise BackendAdmissionLeaseError(
            "lease envelope fields do not match the schema"
        )
    claims = envelope.get("claims")
    signature_document = envelope.get("signature")
    key_document = envelope.get("verification_key")
    if not isinstance(claims, dict) or set(claims) != _CLAIM_FIELDS:
        raise BackendAdmissionLeaseError("lease claim fields do not match the schema")
    if not isinstance(signature_document, dict) or set(signature_document) != {
        "encoding",
        "value",
    }:
        raise BackendAdmissionLeaseError(
            "lease signature fields do not match the schema"
        )
    if not isinstance(key_document, dict) or set(key_document) != {
        "encoding",
        "value",
    }:
        raise BackendAdmissionLeaseError(
            "lease verification-key fields do not match the schema"
        )
    if (
        signature_document.get("encoding") != "base64"
        or key_document.get("encoding")
        != "base64-der-subject-public-key-info"
    ):
        raise BackendAdmissionLeaseError("lease binary encodings are unsupported")

    public_key = _canonical_base64(key_document.get("value"), "verification key")
    signature = _canonical_base64(signature_document.get("value"), "signature")
    public_key_sha256 = hashlib.sha256(public_key).hexdigest()
    expected = {
        "admission_evidence_sha256": admission.evidence_sha256,
        "authorization_sha256": admission.authorization_sha256,
        "deployment_boundary_sha256": admission.deployment_boundary_sha256,
        "evidence_window_sha256": admission.evidence_window_sha256,
        "key_arn_sha256": _sha256_text(key_arn),
        "key_revision_sha256": _key_revision_sha256(
            key_arn, expected_public_key_sha256
        ),
        "kind": LEASE_KIND,
        "max_ttl_seconds": MAX_TTL_SECONDS,
        "public_key_sha256": expected_public_key_sha256,
        "schema_version": LEASE_SCHEMA_VERSION,
        "signing_algorithm": SIGNING_ALGORITHM,
        "workflow_sha256": _sha256_text(workflow_sha),
        "workflow_subject_sha256": _sha256_text(workflow_subject),
    }
    if any(claims.get(name) != value for name, value in expected.items()):
        raise BackendAdmissionLeaseError(
            "lease does not bind the reviewed admission, provenance, or signing key"
        )
    if (
        public_key_sha256 != expected_public_key_sha256
        or not 64 <= len(public_key) <= 1024
        or not 64 <= len(signature) <= 144
    ):
        raise BackendAdmissionLeaseError(
            "embedded verification key or signature is invalid"
        )

    issued_at = _timestamp(claims.get("issued_at"), "lease issue time")
    expires_at = _timestamp(claims.get("expires_at"), "lease expiry time")
    verified_at = _timestamp(verification_time, "lease verification time")
    lifetime = int((expires_at - issued_at).total_seconds())
    if not 1 <= lifetime <= MAX_TTL_SECONDS:
        raise BackendAdmissionLeaseError("lease lifetime exceeds the allowed window")
    if verified_at < issued_at:
        raise BackendAdmissionLeaseError("lease is not valid yet")
    if verified_at >= expires_at:
        raise BackendAdmissionLeaseError("lease has expired")
    if not signature_verifier(public_key, signature, _canonical(claims)):
        raise BackendAdmissionLeaseError("lease signature is invalid")

    return {
        "admission_evidence_sha256": admission.evidence_sha256,
        "expires_at": claims["expires_at"],
        "kind": LEASE_AUDIT_KIND,
        "lease_sha256": hashlib.sha256(_canonical(envelope)).hexdigest(),
        "provenance_verified": True,
        "release_to_plan": True,
        "schema_version": LEASE_SCHEMA_VERSION,
        "signature_verified": True,
        "status": "pass",
        "verified_at": _format_timestamp(verified_at),
    }


def _add_common_binding_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--kms-key-arn", required=True)
    parser.add_argument("--authorization-id", required=True)
    parser.add_argument("--workflow-subject", required=True)
    parser.add_argument("--workflow-sha", required=True)
    parser.add_argument("--output", type=Path)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Issue or verify a short-lived KMS-signed backend admission lease."
    )
    commands = parser.add_subparsers(dest="command", required=True)

    issue = commands.add_parser("issue", help="issue a lease with AWS KMS")
    issue.add_argument("admission_receipt", type=Path)
    issue.add_argument(
        "--partition", choices=("aws", "aws-us-gov", "aws-cn"), required=True
    )
    issue.add_argument("--account-id", required=True)
    issue.add_argument("--region", required=True)
    issue.add_argument("--ttl-seconds", type=int, default=300)
    issue.add_argument("--aws-cli", default="aws")
    issue.add_argument("--timeout-seconds", type=int, default=30)
    _add_common_binding_arguments(issue)

    verify = commands.add_parser("verify", help="verify a lease without AWS access")
    verify.add_argument("lease", type=Path)
    verify.add_argument("admission_receipt", type=Path)
    verify.add_argument("--public-key-sha256", required=True)
    verify.add_argument("--verification-time")
    verify.add_argument("--openssl", default="openssl")
    verify.add_argument("--timeout-seconds", type=int, default=10)
    _add_common_binding_arguments(verify)
    return parser


def _write_or_print(output: Path | None, document: dict[str, object]) -> None:
    if output is None:
        print(json.dumps(document, allow_nan=False, indent=2, sort_keys=True))
    else:
        _write_atomic(output, document)


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        inputs = {args.admission_receipt.resolve()}
        if args.command == "verify":
            inputs.add(args.lease.resolve())
            if len(inputs) != 2:
                raise BackendAdmissionLeaseError(
                    "lease and admission receipt must be distinct files"
                )
        if args.output is not None and args.output.resolve() in inputs:
            raise BackendAdmissionLeaseError("output must not replace an input")
        admission_document = _load_receipt(args.admission_receipt)
        if args.command == "issue":
            admission = BackendAdmission.from_document(admission_document)
            aws = AwsCli(
                executable=args.aws_cli, timeout_seconds=args.timeout_seconds
            )
            key = KmsLeaseKey.inspect(
                aws,
                args.kms_key_arn,
                partition=args.partition,
                account_id=args.account_id,
                region=args.region,
            )
            document = key.issue(
                aws,
                admission,
                authorization_id=args.authorization_id,
                workflow_subject=args.workflow_subject,
                workflow_sha=args.workflow_sha,
                issued_at=_now_utc(),
                ttl_seconds=args.ttl_seconds,
            )
        else:
            document = verify_lease(
                _load_receipt(args.lease),
                admission_document,
                key_arn=args.kms_key_arn,
                expected_public_key_sha256=args.public_key_sha256,
                authorization_id=args.authorization_id,
                workflow_subject=args.workflow_subject,
                workflow_sha=args.workflow_sha,
                verification_time=args.verification_time or _now_utc(),
                signature_verifier=lambda public_key, signature, message: (
                    verify_ecdsa_signature(
                        public_key,
                        signature,
                        message,
                        openssl=args.openssl,
                        timeout_seconds=args.timeout_seconds,
                    )
                ),
            )
        _write_or_print(args.output, document)
        return 0
    except (OSError, TypeError, ValueError, RuntimeError) as exc:
        print(f"backend admission lease rejected: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
