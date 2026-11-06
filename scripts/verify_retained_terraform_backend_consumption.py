#!/usr/bin/env python3
"""Independently audit one exact retained backend-consumption receipt version."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import stat
import sys
from dataclasses import dataclass

try:
    from scripts.archive_network_incident_redrive_evidence import (
        _bucket_name,
        _retention_time,
    )
    from scripts.archive_terraform_backend_consumption import (
        ARCHIVE_KIND,
        MAX_RECEIPT_BYTES,
        _validate_consumption,
    )
    from scripts.lease_terraform_backend_admission import _canonical
    from scripts.verify_retained_redrive_evidence import AwsEvidenceCli, EvidenceReader
except ModuleNotFoundError:  # Direct execution from the scripts directory.
    from archive_network_incident_redrive_evidence import _bucket_name, _retention_time
    from archive_terraform_backend_consumption import (
        ARCHIVE_KIND,
        MAX_RECEIPT_BYTES,
        _validate_consumption,
    )
    from lease_terraform_backend_admission import _canonical
    from verify_retained_redrive_evidence import AwsEvidenceCli, EvidenceReader


AUDIT_KIND = "terraform-backend-admission-consumption-retention-audit"
MAX_ARCHIVE_RECEIPT_BYTES = 16 * 1024
RECEIPT_FIELDS = frozenset(
    {
        "archive_receipt_sha256",
        "bucket_sha256",
        "checksum_sha256",
        "consumption_sha256",
        "kind",
        "object_key_sha256",
        "retain_until",
        "retention_mode",
        "schema_version",
        "status",
        "version_id_sha256",
    }
)
_DIGEST = re.compile(r"[0-9a-f]{64}")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z0-9]+){1,3}-[0-9]")
_OBJECT_KEY = re.compile(
    r"terraform-backend-consumptions/v1/([0-9a-f]{64})[.]json"
)


class RetainedConsumptionAuditError(ValueError):
    """The retained backend-consumption evidence is not independently auditable."""


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise RetainedConsumptionAuditError("archive receipt contains duplicate keys")
        result[key] = value
    return result


def _load_json(path: str | os.PathLike[str]) -> object:
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not 1 <= before.st_size <= MAX_ARCHIVE_RECEIPT_BYTES:
            raise RetainedConsumptionAuditError(
                "archive receipt must be a bounded regular file"
            )
        chunks: list[bytes] = []
        size = 0
        while chunk := os.read(descriptor, 4096):
            size += len(chunk)
            if size > MAX_ARCHIVE_RECEIPT_BYTES:
                raise RetainedConsumptionAuditError(
                    "archive receipt grew outside the byte limit"
                )
            chunks.append(chunk)
        after = os.fstat(descriptor)
        if (
            size != before.st_size
            or after.st_size != before.st_size
            or after.st_mtime_ns != before.st_mtime_ns
            or after.st_ctime_ns != before.st_ctime_ns
        ):
            raise RetainedConsumptionAuditError("archive receipt changed while being read")
    except OSError as exc:
        raise RetainedConsumptionAuditError(
            "archive receipt cannot be read without following links"
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    try:
        return json.loads(b"".join(chunks), object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RetainedConsumptionAuditError("archive receipt is not valid JSON") from exc


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise RetainedConsumptionAuditError(f"{label} is not a SHA-256 digest")
    return value


@dataclass(frozen=True)
class ConsumptionArchiveReceipt:
    bucket_sha256: str
    checksum_sha256: str
    consumption_sha256: str
    object_key_sha256: str
    retain_until: str
    version_id_sha256: str

    @classmethod
    def from_document(cls, document: object) -> ConsumptionArchiveReceipt:
        if (
            not isinstance(document, dict)
            or set(document) != RECEIPT_FIELDS
            or document.get("kind") != ARCHIVE_KIND
            or document.get("schema_version") != 1
            or document.get("status") != "pass"
            or document.get("retention_mode") != "COMPLIANCE"
        ):
            raise RetainedConsumptionAuditError(
                "archive receipt does not match the supported schema"
            )
        values = {
            name: _digest(document.get(name), name)
            for name in (
                "bucket_sha256",
                "checksum_sha256",
                "consumption_sha256",
                "object_key_sha256",
                "version_id_sha256",
            )
        }
        claimed = _digest(
            document.get("archive_receipt_sha256"), "archive_receipt_sha256"
        )
        unsigned = dict(document)
        unsigned.pop("archive_receipt_sha256")
        if hashlib.sha256(_canonical(unsigned)).hexdigest() != claimed:
            raise RetainedConsumptionAuditError("archive receipt digest does not match")
        retain_until = document.get("retain_until")
        try:
            _retention_time(retain_until)
        except RuntimeError as exc:
            raise RetainedConsumptionAuditError(
                "archive receipt retain-until timestamp is invalid"
            ) from exc
        return cls(
            bucket_sha256=values["bucket_sha256"],
            checksum_sha256=values["checksum_sha256"],
            consumption_sha256=values["consumption_sha256"],
            object_key_sha256=values["object_key_sha256"],
            retain_until=retain_until,
            version_id_sha256=values["version_id_sha256"],
        )

    def bind_target(
        self,
        *,
        bucket: str,
        key: str,
        version_id: str,
        expected_consumption_sha256: str,
    ) -> None:
        expected = _digest(expected_consumption_sha256, "expected consumption digest")
        match = _OBJECT_KEY.fullmatch(key)
        if match is None or match.group(1) != self.checksum_sha256:
            raise RetainedConsumptionAuditError(
                "object key does not bind the archived payload checksum"
            )
        supplied = {
            "bucket_sha256": hashlib.sha256(bucket.encode("ascii")).hexdigest(),
            "object_key_sha256": hashlib.sha256(key.encode("ascii")).hexdigest(),
            "version_id_sha256": hashlib.sha256(version_id.encode("utf-8")).hexdigest(),
        }
        if any(getattr(self, name) != value for name, value in supplied.items()):
            raise RetainedConsumptionAuditError(
                "archive receipt does not bind the supplied S3 target"
            )
        if self.consumption_sha256 != expected:
            raise RetainedConsumptionAuditError(
                "archive receipt does not bind the expected consumption"
            )


def verify_retained_consumption(
    aws: EvidenceReader,
    receipt: ConsumptionArchiveReceipt,
    *,
    bucket: str,
    key: str,
    version_id: str,
    expected_consumption_sha256: str,
    owner_account_id: str,
    region: str,
) -> dict[str, object]:
    """Verify exact S3 bytes, receipt semantics, and continuing compliance retention."""

    bucket = _bucket_name(bucket)
    if re.fullmatch(r"[0-9]{12}", owner_account_id) is None:
        raise RetainedConsumptionAuditError(
            "archive owner account ID must contain 12 digits"
        )
    if not isinstance(region, str) or _REGION.fullmatch(region) is None:
        raise RetainedConsumptionAuditError("archive region is invalid")
    if not version_id or version_id == "null" or len(version_id) > 1024:
        raise RetainedConsumptionAuditError("S3 version ID is missing or invalid")
    receipt.bind_target(
        bucket=bucket,
        key=key,
        version_id=version_id,
        expected_consumption_sha256=expected_consumption_sha256,
    )
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
        not 1 <= len(payload) <= MAX_RECEIPT_BYTES
        or digest.hex() != receipt.checksum_sha256
        or response.get("ChecksumSHA256") != checksum
        or response.get("ServerSideEncryption") != "AES256"
        or response.get("VersionId") != version_id
        or response.get("ContentType") != "application/json"
    ):
        raise RuntimeError(
            "retained consumption identity, checksum or encryption is invalid"
        )
    try:
        consumption = _validate_consumption(
            json.loads(payload.decode("ascii"), object_pairs_hook=_unique_object)
        )
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise RuntimeError("retained consumption receipt is invalid") from exc
    if _canonical(consumption) != payload:
        raise RuntimeError("retained consumption receipt is not canonical JSON")
    if consumption["consumption_sha256"] != receipt.consumption_sha256:
        raise RuntimeError("retained consumption does not match the archive receipt")

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
        raise RuntimeError(
            "retained consumption no longer satisfies its compliance lock receipt"
        )
    audit: dict[str, object] = {
        "bucket_sha256": receipt.bucket_sha256,
        "checksum_sha256": receipt.checksum_sha256,
        "consumption_sha256": receipt.consumption_sha256,
        "kind": AUDIT_KIND,
        "object_key_sha256": receipt.object_key_sha256,
        "retain_until": retained_until.isoformat().replace("+00:00", "Z"),
        "retention_mode": "COMPLIANCE",
        "schema_version": 1,
        "status": "pass",
        "storage_checksum_verified": True,
        "version_id_sha256": receipt.version_id_sha256,
    }
    audit["audit_receipt_sha256"] = hashlib.sha256(_canonical(audit)).hexdigest()
    return audit


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Audit one exact Object Lock backend-consumption version using read-only credentials."
        )
    )
    parser.add_argument("archive_receipt")
    parser.add_argument("--bucket", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--version-id", required=True)
    parser.add_argument("--expected-consumption-sha256", required=True)
    parser.add_argument("--owner-account-id", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--aws-cli", default="aws")
    parser.add_argument("--timeout-seconds", type=int, default=30)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if not 1 <= args.timeout_seconds <= 60:
            raise RetainedConsumptionAuditError(
                "timeout must be between 1 and 60 seconds"
            )
        audit = verify_retained_consumption(
            AwsEvidenceCli(
                executable=args.aws_cli, timeout_seconds=args.timeout_seconds
            ),
            ConsumptionArchiveReceipt.from_document(_load_json(args.archive_receipt)),
            bucket=args.bucket,
            key=args.key,
            version_id=args.version_id,
            expected_consumption_sha256=args.expected_consumption_sha256,
            owner_account_id=args.owner_account_id,
            region=args.region,
        )
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"retained backend consumption audit failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(audit, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
