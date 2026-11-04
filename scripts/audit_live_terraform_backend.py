#!/usr/bin/env python3
"""Audit live S3/KMS backend controls under one attested AWS role session."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    from scripts.audit_terraform_backend import (
        BACKEND_AUDIT_SCHEMA,
        _now_utc,
        _observed_at,
        _write_atomic,
    )
    from scripts.verify_network_incident_route import AwsCli, AwsClient
except ModuleNotFoundError:  # Direct execution from the scripts directory.
    from audit_terraform_backend import (
        BACKEND_AUDIT_SCHEMA,
        _now_utc,
        _observed_at,
        _write_atomic,
    )
    from verify_network_incident_route import AwsCli, AwsClient


LIVE_BACKEND_AUDIT_SCHEMA = "terraform-live-backend-audit/v2"
MAX_RECEIPT_BYTES = 64 * 1024

_DIGEST = re.compile(r"[0-9a-f]{64}")
_ACCOUNT = re.compile(r"[0-9]{12}")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z0-9]+){1,3}-[0-9]")
_BUCKET = re.compile(r"[a-z0-9](?:[a-z0-9.-]{1,61}[a-z0-9])?")
_ROLE_ARN = re.compile(
    r"arn:(aws|aws-us-gov|aws-cn):iam::([0-9]{12}):role/"
    r"([A-Za-z0-9+=,.@_-]+(?:/[A-Za-z0-9+=,.@_-]+)*)"
)
_SESSION_NAME = re.compile(r"[A-Za-z0-9+=,.@_-]{2,64}")
_KMS_KEY_ARN = re.compile(
    r"arn:(aws|aws-us-gov|aws-cn):kms:([a-z0-9-]+):([0-9]{12}):"
    r"key/(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    r"|mrk-[0-9a-f]{32})"
)
_BACKEND_RECEIPT_FIELDS = {
    "schema_version",
    "observed_at",
    "accepted",
    "backend_type",
    "partition",
    "account_id",
    "region",
    "bucket_sha256",
    "key_sha256",
    "kms_key_arn_sha256",
    "metadata_sha256",
    "backend_config_sha256",
    "encryption_enabled",
    "native_lockfile_enabled",
    "ambient_credentials_only",
    "evidence_sha256",
}


class LiveBackendAuditError(ValueError):
    """The live backend controls or active AWS identity violate the reviewed boundary."""

    code = "TERRAFORM_LIVE_BACKEND_AUDIT_INVALID"

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(f"{self.code}: {reason}")


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
        raise LiveBackendAuditError(
            "AWS control response is not canonicalizable"
        ) from exc


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise LiveBackendAuditError("backend receipt contains duplicate JSON keys")
        result[key] = value
    return result


def _load_receipt(path: Path) -> dict[str, Any]:
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or not 1 <= metadata.st_size <= MAX_RECEIPT_BYTES
        ):
            raise LiveBackendAuditError(
                "backend receipt must be a bounded regular file"
            )
        chunks: list[bytes] = []
        size = 0
        while chunk := os.read(descriptor, 16 * 1024):
            size += len(chunk)
            if size > MAX_RECEIPT_BYTES:
                raise LiveBackendAuditError(
                    "backend receipt grew outside the byte limit"
                )
            chunks.append(chunk)
        raw = b"".join(chunks)
        if len(raw) != metadata.st_size:
            raise LiveBackendAuditError("backend receipt changed while being read")
    except OSError as exc:
        raise LiveBackendAuditError(
            "backend receipt cannot be read without following links"
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    try:
        document = json.loads(raw, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LiveBackendAuditError("backend receipt is not valid JSON") from exc
    if not isinstance(document, dict):
        raise LiveBackendAuditError("backend receipt must be a JSON object")
    return document


@dataclass(frozen=True)
class BackendAuditReceipt:
    evidence_sha256: str
    key_sha256: str
    observed_at: str

    @classmethod
    def validate_and_bind(
        cls,
        document: dict[str, Any],
        *,
        partition: str,
        account_id: str,
        region: str,
        bucket: str,
        kms_key_arn: str,
    ) -> BackendAuditReceipt:
        if set(document) != _BACKEND_RECEIPT_FIELDS:
            raise LiveBackendAuditError(
                "backend receipt fields do not match the schema"
            )
        evidence_sha256 = document.get("evidence_sha256")
        unsigned = {
            key: value for key, value in document.items() if key != "evidence_sha256"
        }
        expected_evidence_sha256 = hashlib.sha256(_canonical(unsigned)).hexdigest()
        if (
            document.get("schema_version") != BACKEND_AUDIT_SCHEMA
            or document.get("accepted") is not True
            or document.get("backend_type") != "s3"
            or document.get("encryption_enabled") is not True
            or document.get("native_lockfile_enabled") is not True
            or document.get("ambient_credentials_only") is not True
            or document.get("partition") != partition
            or document.get("account_id") != account_id
            or document.get("region") != region
            or document.get("bucket_sha256") != _sha256(bucket)
            or document.get("kms_key_arn_sha256") != _sha256(kms_key_arn)
            or not isinstance(evidence_sha256, str)
            or _DIGEST.fullmatch(evidence_sha256) is None
            or evidence_sha256 != expected_evidence_sha256
        ):
            raise LiveBackendAuditError(
                "backend receipt is invalid or does not bind this target"
            )
        digest_fields = (
            "key_sha256",
            "metadata_sha256",
            "backend_config_sha256",
        )
        if any(
            not isinstance(document.get(field), str)
            or _DIGEST.fullmatch(document[field]) is None
            for field in digest_fields
        ):
            raise LiveBackendAuditError(
                "backend receipt contains an invalid commitment"
            )
        try:
            observed_at = _observed_at(document.get("observed_at"))
        except (ValueError, TypeError) as exc:
            raise LiveBackendAuditError("backend receipt observation time is invalid") from exc
        return cls(
            evidence_sha256=evidence_sha256,
            key_sha256=document["key_sha256"],
            observed_at=observed_at,
        )


def _validated_boundary(
    *,
    partition: str,
    account_id: str,
    region: str,
    bucket: str,
    kms_key_arn: str,
    role_arn: str,
    session_name: str,
) -> tuple[str, str]:
    if partition not in {"aws", "aws-us-gov", "aws-cn"}:
        raise LiveBackendAuditError("partition is invalid")
    if _ACCOUNT.fullmatch(account_id) is None or _REGION.fullmatch(region) is None:
        raise LiveBackendAuditError("account or Region is invalid")
    if (
        _BUCKET.fullmatch(bucket) is None
        or _SESSION_NAME.fullmatch(session_name) is None
    ):
        raise LiveBackendAuditError("bucket or role session name is invalid")
    kms_match = _KMS_KEY_ARN.fullmatch(kms_key_arn)
    role_match = _ROLE_ARN.fullmatch(role_arn)
    if (
        kms_match is None
        or kms_match.groups()[:3] != (partition, region, account_id)
        or role_match is None
        or role_match.groups()[:2] != (partition, account_id)
    ):
        raise LiveBackendAuditError(
            "KMS key or role is outside the deployment boundary"
        )
    role_name = role_match.group(3).rsplit("/", 1)[-1]
    assumed_role_arn = (
        f"arn:{partition}:sts::{account_id}:assumed-role/{role_name}/{session_name}"
    )
    return assumed_role_arn, role_name


def _bucket_region(response: dict[str, Any]) -> str:
    location = response.get("LocationConstraint")
    if location is None:
        return "us-east-1"
    if location == "EU":
        return "eu-west-1"
    if not isinstance(location, str) or _REGION.fullmatch(location) is None:
        raise LiveBackendAuditError("bucket location response is invalid")
    return location


def _call(
    aws: AwsClient,
    service: str,
    operation: str,
    **parameters: str | list[str],
) -> dict[str, Any]:
    try:
        response = aws.call(service, operation, **parameters)
    except RuntimeError as exc:
        raise LiveBackendAuditError(
            f"AWS {service} {operation} request failed"
        ) from exc
    if not isinstance(response, dict):
        raise LiveBackendAuditError(f"AWS {service} {operation} response is invalid")
    return response


def audit_live_backend(
    aws: AwsClient,
    backend_receipt_document: dict[str, Any],
    *,
    partition: str,
    account_id: str,
    region: str,
    bucket: str,
    kms_key_arn: str,
    role_arn: str,
    session_name: str,
    observed_at: str | None = None,
) -> dict[str, object]:
    """Verify caller, live bucket controls, and live KMS controls without writes."""

    assumed_role_arn, role_name = _validated_boundary(
        partition=partition,
        account_id=account_id,
        region=region,
        bucket=bucket,
        kms_key_arn=kms_key_arn,
        role_arn=role_arn,
        session_name=session_name,
    )
    receipt = BackendAuditReceipt.validate_and_bind(
        backend_receipt_document,
        partition=partition,
        account_id=account_id,
        region=region,
        bucket=bucket,
        kms_key_arn=kms_key_arn,
    )
    try:
        current_observed_at = _observed_at(observed_at or _now_utc())
    except (ValueError, TypeError) as exc:
        raise LiveBackendAuditError("live audit observation time is invalid") from exc
    if current_observed_at < receipt.observed_at:
        raise LiveBackendAuditError(
            "live audit observation precedes the backend metadata audit"
        )
    responses: dict[str, dict[str, Any]] = {}
    responses["caller"] = _call(aws, "sts", "get-caller-identity")
    if (
        responses["caller"].get("Account") != account_id
        or responses["caller"].get("Arn") != assumed_role_arn
        or not isinstance(responses["caller"].get("UserId"), str)
        or not responses["caller"]["UserId"].endswith(f":{session_name}")
    ):
        raise LiveBackendAuditError(
            "active credentials do not match the reviewed role session"
        )

    s3_parameters = {
        "bucket": bucket,
        "expected_bucket_owner": account_id,
        "region": region,
    }
    for operation in (
        "get-bucket-location",
        "get-bucket-versioning",
        "get-bucket-encryption",
        "get-public-access-block",
        "get-bucket-ownership-controls",
        "get-bucket-policy-status",
    ):
        responses[operation] = _call(aws, "s3api", operation, **s3_parameters)
    if _bucket_region(responses["get-bucket-location"]) != region:
        raise LiveBackendAuditError("bucket is not in the reviewed Region")
    versioning = responses["get-bucket-versioning"]
    if (
        versioning.get("Status") != "Enabled"
        or versioning.get("MFADelete") == "Enabled"
    ):
        raise LiveBackendAuditError("bucket versioning controls are unsafe")
    encryption = responses["get-bucket-encryption"].get(
        "ServerSideEncryptionConfiguration"
    )
    rules = encryption.get("Rules") if isinstance(encryption, dict) else None
    if not isinstance(rules, list) or len(rules) != 1 or not isinstance(rules[0], dict):
        raise LiveBackendAuditError("bucket encryption policy is invalid")
    defaults = rules[0].get("ApplyServerSideEncryptionByDefault")
    if (
        not isinstance(defaults, dict)
        or defaults.get("SSEAlgorithm") != "aws:kms"
        or defaults.get("KMSMasterKeyID") != kms_key_arn
        or rules[0].get("BucketKeyEnabled") is not True
    ):
        raise LiveBackendAuditError(
            "bucket encryption does not use the reviewed KMS key"
        )
    public_access = responses["get-public-access-block"].get(
        "PublicAccessBlockConfiguration"
    )
    if not isinstance(public_access, dict) or any(
        public_access.get(field) is not True
        for field in (
            "BlockPublicAcls",
            "IgnorePublicAcls",
            "BlockPublicPolicy",
            "RestrictPublicBuckets",
        )
    ):
        raise LiveBackendAuditError("bucket public-access blocks are incomplete")
    ownership = responses["get-bucket-ownership-controls"].get("OwnershipControls")
    ownership_rules = ownership.get("Rules") if isinstance(ownership, dict) else None
    if ownership_rules != [{"ObjectOwnership": "BucketOwnerEnforced"}]:
        raise LiveBackendAuditError("bucket ownership is not BucketOwnerEnforced")
    if responses["get-bucket-policy-status"].get("PolicyStatus") != {"IsPublic": False}:
        raise LiveBackendAuditError(
            "bucket policy is public or its status is ambiguous"
        )

    kms_parameters = {"key_id": kms_key_arn}
    responses["describe-key"] = _call(aws, "kms", "describe-key", **kms_parameters)
    responses["get-key-rotation-status"] = _call(
        aws, "kms", "get-key-rotation-status", **kms_parameters
    )
    key = responses["describe-key"].get("KeyMetadata")
    if (
        not isinstance(key, dict)
        or key.get("Arn") != kms_key_arn
        or key.get("AWSAccountId") != account_id
        or key.get("Enabled") is not True
        or key.get("KeyState") != "Enabled"
        or key.get("KeyManager") != "CUSTOMER"
        or key.get("KeyUsage") != "ENCRYPT_DECRYPT"
        or key.get("Origin") != "AWS_KMS"
        or key.get("MultiRegion") is not False
        or key.get("KeySpec") != "SYMMETRIC_DEFAULT"
        or key.get("EncryptionAlgorithms") != ["SYMMETRIC_DEFAULT"]
    ):
        raise LiveBackendAuditError(
            "KMS key controls do not match the reviewed boundary"
        )
    rotation = responses["get-key-rotation-status"]
    rotation_period = rotation.get("RotationPeriodInDays", 365)
    if (
        rotation.get("KeyRotationEnabled") is not True
        or type(rotation_period) is not int
        or not 90 <= rotation_period <= 365
    ):
        raise LiveBackendAuditError(
            "KMS automatic rotation is disabled or too infrequent"
        )

    evidence: dict[str, object] = {
        "schema_version": LIVE_BACKEND_AUDIT_SCHEMA,
        "observed_at": current_observed_at,
        "accepted": True,
        "partition": partition,
        "account_id": account_id,
        "region": region,
        "bucket_sha256": _sha256(bucket),
        "kms_key_arn_sha256": _sha256(kms_key_arn),
        "role_arn_sha256": _sha256(role_arn),
        "role_name_sha256": _sha256(role_name),
        "role_session_sha256": _sha256(session_name),
        "backend_audit_sha256": receipt.evidence_sha256,
        "state_key_sha256": receipt.key_sha256,
        "control_snapshot_sha256": hashlib.sha256(_canonical(responses)).hexdigest(),
        "caller_identity_verified": True,
        "bucket_region_verified": True,
        "bucket_versioning_verified": True,
        "bucket_kms_encryption_verified": True,
        "bucket_public_access_blocked": True,
        "bucket_owner_enforced": True,
        "bucket_policy_nonpublic": True,
        "kms_key_verified": True,
        "kms_rotation_verified": True,
    }
    evidence["evidence_sha256"] = hashlib.sha256(_canonical(evidence)).hexdigest()
    return evidence


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Audit live Terraform S3/KMS backend controls without making writes."
    )
    parser.add_argument("backend_receipt", type=Path)
    parser.add_argument(
        "--partition", choices=("aws", "aws-us-gov", "aws-cn"), required=True
    )
    parser.add_argument("--account-id", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--bucket", required=True)
    parser.add_argument("--kms-key-arn", required=True)
    parser.add_argument("--role-arn", required=True)
    parser.add_argument("--session-name", required=True)
    parser.add_argument("--aws-cli", default="aws")
    parser.add_argument("--timeout-seconds", type=int, default=30)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        if not 1 <= args.timeout_seconds <= 60:
            raise LiveBackendAuditError("timeout must be between 1 and 60 seconds")
        if (
            args.output is not None
            and args.output.resolve() == args.backend_receipt.resolve()
        ):
            raise LiveBackendAuditError("output must not replace the backend receipt")
        evidence = audit_live_backend(
            AwsCli(executable=args.aws_cli, timeout_seconds=args.timeout_seconds),
            _load_receipt(args.backend_receipt),
            partition=args.partition,
            account_id=args.account_id,
            region=args.region,
            bucket=args.bucket,
            kms_key_arn=args.kms_key_arn,
            role_arn=args.role_arn,
            session_name=args.session_name,
        )
        if args.output is None:
            print(json.dumps(evidence, allow_nan=False, indent=2, sort_keys=True))
        else:
            _write_atomic(args.output, evidence)
        return 0
    except (LiveBackendAuditError, OSError, RuntimeError) as exc:
        print(f"Live Terraform backend audit rejected: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
