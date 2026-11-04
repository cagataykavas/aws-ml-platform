#!/usr/bin/env python3
"""Audit initialized Terraform S3 backend metadata without exposing its values."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

BACKEND_AUDIT_SCHEMA = "terraform-backend-audit/v2"
MAX_METADATA_BYTES = 1024 * 1024

_ACCOUNT_ID = re.compile(r"[0-9]{12}")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z0-9]+){1,3}-[0-9]")
_BUCKET = re.compile(r"[a-z0-9](?:[a-z0-9.-]{1,61}[a-z0-9])?")
_KMS_KEY = re.compile(
    r"arn:(aws|aws-us-gov|aws-cn):kms:([a-z0-9-]+):([0-9]{12}):"
    r"key/(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    r"|mrk-[0-9a-f]{32})"
)
_STATIC_CREDENTIAL_FIELDS = (
    "access_key",
    "secret_key",
    "token",
    "profile",
    "shared_credentials_file",
    "shared_credentials_files",
    "web_identity_token",
    "web_identity_token_file",
)
_CUSTOM_ENDPOINT_FIELDS = (
    "custom_ca_bundle",
    "ec2_metadata_service_endpoint",
    "endpoint",
    "endpoints",
    "http_proxy",
    "https_proxy",
    "dynamodb_endpoint",
    "iam_endpoint",
    "metadata_service_endpoint",
    "no_proxy",
    "s3_endpoint",
    "sts_endpoint",
)
_BYPASS_FIELDS = (
    "insecure",
    "skip_credentials_validation",
    "skip_metadata_api_check",
    "skip_region_validation",
    "skip_requesting_account_id",
    "skip_s3_checksum",
)
_UTC_TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")


class BackendAuditError(ValueError):
    """Initialized backend metadata violates the deployment state boundary."""

    code = "TERRAFORM_BACKEND_AUDIT_INVALID"

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(f"{self.code}: {reason}")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise BackendAuditError("metadata contains duplicate JSON keys")
        result[key] = value
    return result


def _read_metadata(path: Path) -> tuple[dict[str, Any], bytes]:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise BackendAuditError("metadata must be a regular file")
        if not 1 <= metadata.st_size <= MAX_METADATA_BYTES:
            raise BackendAuditError("metadata size is outside the allowed range")
        chunks: list[bytes] = []
        size = 0
        while chunk := os.read(descriptor, 64 * 1024):
            size += len(chunk)
            if size > MAX_METADATA_BYTES:
                raise BackendAuditError("metadata grew outside the allowed range")
            chunks.append(chunk)
        raw = b"".join(chunks)
        if len(raw) != metadata.st_size:
            raise BackendAuditError("metadata changed while being read")
    except OSError as exc:
        raise BackendAuditError("cannot read metadata without following links") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    try:
        document = json.loads(raw, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BackendAuditError("metadata is not valid JSON") from exc
    if not isinstance(document, dict):
        raise BackendAuditError("metadata must be a JSON object")
    return document, raw


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
        raise BackendAuditError("metadata is not canonicalizable") from exc


def _digest_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _observed_at(value: str) -> str:
    if _UTC_TIMESTAMP.fullmatch(value) is None:
        raise BackendAuditError("observation time must be canonical UTC")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise BackendAuditError("observation time is invalid") from exc
    return value


def _now_utc() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _required_text(value: object, pattern: re.Pattern[str], field: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise BackendAuditError(f"{field} is invalid")
    return value


def _state_key(value: object) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 1_024
        or value.startswith("/")
        or "//" in value
        or any(part in {"", ".", ".."} for part in value.split("/"))
        or any(ord(character) < 0x21 or ord(character) > 0x7E for character in value)
    ):
        raise BackendAuditError("state key is invalid")
    return value


def _is_unset(value: object) -> bool:
    return value is None or value == "" or value == [] or value == {}


def _require_unset(config: dict[str, Any], fields: tuple[str, ...], label: str) -> None:
    if any(not _is_unset(config.get(field)) for field in fields):
        raise BackendAuditError(f"{label} must not be configured")


def audit_backend_metadata(
    document: dict[str, Any],
    raw: bytes,
    *,
    expected_partition: str,
    expected_account_id: str,
    expected_region: str,
    expected_bucket: str,
    expected_key: str,
    expected_kms_key_arn: str,
    observed_at: str | None = None,
) -> dict[str, Any]:
    """Require an encrypted, locked S3 backend using ambient workload credentials."""

    if expected_partition not in {"aws", "aws-us-gov", "aws-cn"}:
        raise BackendAuditError("expected partition is invalid")
    account_id = _required_text(expected_account_id, _ACCOUNT_ID, "expected account ID")
    region = _required_text(expected_region, _REGION, "expected Region")
    bucket = _required_text(expected_bucket, _BUCKET, "expected bucket")
    key = _state_key(expected_key)
    kms_key_arn = _required_text(expected_kms_key_arn, _KMS_KEY, "expected KMS key ARN")
    kms_match = _KMS_KEY.fullmatch(kms_key_arn)
    assert kms_match is not None
    if (
        kms_match.group(1) != expected_partition
        or kms_match.group(2) != region
        or kms_match.group(3) != account_id
    ):
        raise BackendAuditError(
            "expected KMS key must be in the deployment partition, account, and Region"
        )

    if set(document) - {"version", "serial", "lineage", "backend", "modules"}:
        raise BackendAuditError("metadata root contains unsupported fields")
    if document.get("version") != 3 or type(document.get("serial")) is not int:
        raise BackendAuditError("metadata version is unsupported")
    backend = document.get("backend")
    if not isinstance(backend, dict) or set(backend) != {"type", "config", "hash"}:
        raise BackendAuditError(
            "backend metadata fields do not match the expected schema"
        )
    if backend.get("type") != "s3":
        raise BackendAuditError("backend type must be s3")
    config = backend.get("config")
    if not isinstance(config, dict):
        raise BackendAuditError("backend config must be an object")

    actual_bucket = config.get("bucket")
    actual_key = config.get("key")
    actual_region = config.get("region")
    actual_kms = config.get("kms_key_id")
    if (
        actual_bucket != bucket
        or actual_key != key
        or actual_region != region
        or actual_kms != kms_key_arn
    ):
        raise BackendAuditError(
            "backend identity does not match the reviewed deployment boundary"
        )
    if config.get("encrypt") is not True:
        raise BackendAuditError("backend encryption must be enabled")
    if config.get("use_lockfile") is not True:
        raise BackendAuditError("native S3 state locking must be enabled")
    if not _is_unset(config.get("dynamodb_table")):
        raise BackendAuditError(
            "legacy DynamoDB locking must not replace native lockfiles"
        )
    if config.get("acl") not in (None, "", "private"):
        raise BackendAuditError("backend ACL must be private or unset")
    if not _is_unset(config.get("assume_role")) or not _is_unset(
        config.get("assume_role_with_web_identity")
    ):
        raise BackendAuditError(
            "backend must use the already assumed deployment identity"
        )
    _require_unset(config, _STATIC_CREDENTIAL_FIELDS, "static backend credentials")
    _require_unset(config, _CUSTOM_ENDPOINT_FIELDS, "custom AWS endpoints")
    if any(
        config.get(field) is not False and config.get(field) is not None
        for field in _BYPASS_FIELDS
    ):
        raise BackendAuditError("backend validation bypasses must be disabled")

    evidence = {
        "schema_version": BACKEND_AUDIT_SCHEMA,
        "observed_at": _observed_at(observed_at or _now_utc()),
        "accepted": True,
        "backend_type": "s3",
        "partition": expected_partition,
        "account_id": account_id,
        "region": region,
        "bucket_sha256": _digest_text(bucket),
        "key_sha256": _digest_text(key),
        "kms_key_arn_sha256": _digest_text(kms_key_arn),
        "metadata_sha256": hashlib.sha256(raw).hexdigest(),
        "backend_config_sha256": hashlib.sha256(_canonical(config)).hexdigest(),
        "encryption_enabled": True,
        "native_lockfile_enabled": True,
        "ambient_credentials_only": True,
    }
    evidence["evidence_sha256"] = hashlib.sha256(_canonical(evidence)).hexdigest()
    return evidence


def _write_atomic(path: Path, document: dict[str, Any]) -> None:
    payload = json.dumps(document, allow_nan=False, indent=2, sort_keys=True) + "\n"
    temporary_path: Path | None = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary.write(payload)
            temporary.flush()
            os.fsync(temporary.fileno())
            temporary_path = Path(temporary.name)
        temporary_path.replace(path)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Audit initialized Terraform S3 backend metadata without exposing values."
    )
    parser.add_argument("metadata", type=Path)
    parser.add_argument(
        "--expected-partition", choices=("aws", "aws-us-gov", "aws-cn"), required=True
    )
    parser.add_argument("--expected-account-id", required=True)
    parser.add_argument("--expected-region", required=True)
    parser.add_argument("--expected-bucket", required=True)
    parser.add_argument("--expected-key", required=True)
    parser.add_argument("--expected-kms-key-arn", required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    try:
        if args.output is not None and args.output.resolve() == args.metadata.resolve():
            raise BackendAuditError("output must not replace private backend metadata")
        document, raw = _read_metadata(args.metadata)
        evidence = audit_backend_metadata(
            document,
            raw,
            expected_partition=args.expected_partition,
            expected_account_id=args.expected_account_id,
            expected_region=args.expected_region,
            expected_bucket=args.expected_bucket,
            expected_key=args.expected_key,
            expected_kms_key_arn=args.expected_kms_key_arn,
        )
        if args.output is None:
            print(json.dumps(evidence, allow_nan=False, indent=2, sort_keys=True))
        else:
            _write_atomic(args.output, evidence)
        return 0
    except (BackendAuditError, OSError) as exc:
        print(f"Terraform backend audit rejected: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
