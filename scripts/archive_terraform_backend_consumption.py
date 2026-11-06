#!/usr/bin/env python3
"""Retain one backend-admission consumption receipt under S3 Object Lock."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from datetime import UTC, datetime
from pathlib import Path

try:
    from scripts.archive_network_incident_redrive_evidence import ObjectLockArchive
    from scripts.lease_terraform_backend_admission import (
        LEASE_CONSUMPTION_KIND,
        LEASE_SCHEMA_VERSION,
        _canonical,
    )
    from scripts.verify_network_incident_route import AwsCli, AwsClient
except ModuleNotFoundError:  # Direct execution from the scripts directory.
    from archive_network_incident_redrive_evidence import ObjectLockArchive
    from lease_terraform_backend_admission import (
        LEASE_CONSUMPTION_KIND,
        LEASE_SCHEMA_VERSION,
        _canonical,
    )
    from verify_network_incident_route import AwsCli, AwsClient


ARCHIVE_KIND = "terraform-backend-admission-consumption-archive"
MAX_RECEIPT_BYTES = 16 * 1024
CONSUMPTION_FIELDS = frozenset(
    {
        "admission_evidence_sha256",
        "consumed_at",
        "consumption_sha256",
        "expires_at",
        "kind",
        "lease_sha256",
        "release_to_plan",
        "schema_version",
        "status",
        "verification_sha256",
    }
)
DIGEST_FIELDS = frozenset(
    {
        "admission_evidence_sha256",
        "consumption_sha256",
        "lease_sha256",
        "verification_sha256",
    }
)
_DIGEST = re.compile(r"[0-9a-f]{64}")
_UTC_TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")


class ConsumptionArchiveError(ValueError):
    """The receipt cannot cross the immutable archive boundary."""


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ConsumptionArchiveError("consumption receipt contains duplicate keys")
        result[key] = value
    return result


def _load_consumption(path: str | os.PathLike[str]) -> dict[str, object]:
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not 1 <= before.st_size <= MAX_RECEIPT_BYTES:
            raise ConsumptionArchiveError(
                "consumption receipt must be a bounded regular file"
            )
        chunks: list[bytes] = []
        size = 0
        while chunk := os.read(descriptor, 4096):
            size += len(chunk)
            if size > MAX_RECEIPT_BYTES:
                raise ConsumptionArchiveError(
                    "consumption receipt grew outside the byte limit"
                )
            chunks.append(chunk)
        after = os.fstat(descriptor)
        if (
            size != before.st_size
            or after.st_size != before.st_size
            or after.st_mtime_ns != before.st_mtime_ns
            or after.st_ctime_ns != before.st_ctime_ns
        ):
            raise ConsumptionArchiveError("consumption receipt changed while being read")
    except OSError as exc:
        raise ConsumptionArchiveError(
            "consumption receipt cannot be read without following links"
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    try:
        document = json.loads(b"".join(chunks), object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ConsumptionArchiveError("consumption receipt is not valid JSON") from exc
    return _validate_consumption(document)


def _timestamp(value: object, label: str) -> datetime:
    if not isinstance(value, str) or _UTC_TIMESTAMP.fullmatch(value) is None:
        raise ConsumptionArchiveError(f"{label} must be canonical UTC")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise ConsumptionArchiveError(f"{label} must be canonical UTC") from exc


def _validate_consumption(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != CONSUMPTION_FIELDS:
        raise ConsumptionArchiveError(
            "consumption receipt fields do not match the reviewed schema"
        )
    if (
        value.get("kind") != LEASE_CONSUMPTION_KIND
        or value.get("schema_version") != LEASE_SCHEMA_VERSION
        or value.get("status") != "consumed"
        or value.get("release_to_plan") is not True
        or any(
            not isinstance(value.get(name), str)
            or _DIGEST.fullmatch(value[name]) is None
            for name in DIGEST_FIELDS
        )
    ):
        raise ConsumptionArchiveError(
            "consumption receipt values do not match the reviewed schema"
        )
    if _timestamp(value["consumed_at"], "consumed_at") >= _timestamp(
        value["expires_at"], "expires_at"
    ):
        raise ConsumptionArchiveError("consumption receipt is outside its lease window")
    unsigned = dict(value)
    claimed_digest = unsigned.pop("consumption_sha256")
    if hashlib.sha256(_canonical(unsigned)).hexdigest() != claimed_digest:
        raise ConsumptionArchiveError("consumption receipt digest does not match")
    return value


def archive_consumption(
    aws: AwsClient,
    archive: ObjectLockArchive,
    consumption: dict[str, object],
) -> dict[str, object]:
    payload = _canonical(consumption)
    checksum = hashlib.sha256(payload).hexdigest()
    retained = archive.retain(
        aws,
        payload,
        key=f"terraform-backend-consumptions/v1/{checksum}.json",
    )
    receipt: dict[str, object] = {
        "bucket_sha256": retained.bucket_sha256,
        "checksum_sha256": retained.checksum_sha256,
        "consumption_sha256": consumption["consumption_sha256"],
        "kind": ARCHIVE_KIND,
        "object_key_sha256": retained.object_key_sha256,
        "retain_until": retained.retain_until,
        "retention_mode": retained.retention_mode,
        "schema_version": 1,
        "status": "pass",
        "version_id_sha256": retained.version_id_sha256,
    }
    receipt["archive_receipt_sha256"] = hashlib.sha256(_canonical(receipt)).hexdigest()
    return receipt


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Archive a backend-admission consumption receipt under verified S3 "
            "Object Lock retention."
        )
    )
    parser.add_argument("consumption_receipt")
    parser.add_argument("--bucket", required=True)
    parser.add_argument("--owner-account-id", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--retention-days", type=int, required=True)
    parser.add_argument("--aws-cli", default="aws")
    parser.add_argument("--timeout-seconds", type=int, default=30)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        consumption = _load_consumption(args.consumption_receipt)
        aws = AwsCli(executable=args.aws_cli, timeout_seconds=args.timeout_seconds)
        archive = ObjectLockArchive.inspect(
            aws,
            bucket=args.bucket,
            owner_account_id=args.owner_account_id,
            region=args.region,
            retention_days=args.retention_days,
        )
        receipt = archive_consumption(aws, archive, consumption)
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"refusing to archive backend consumption: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
