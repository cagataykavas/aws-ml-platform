#!/usr/bin/env python3
"""Write signed redrive evidence to a verified S3 Object Lock boundary."""

from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json
import re
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

try:
    from scripts.seal_network_incident_redrive_evidence import EVIDENCE_KIND, _canonical
    from scripts.verify_network_incident_route import AwsCli, AwsClient
except ModuleNotFoundError:  # Direct execution from the scripts directory.
    from seal_network_incident_redrive_evidence import EVIDENCE_KIND, _canonical
    from verify_network_incident_route import AwsCli, AwsClient


ARCHIVE_KIND = "network-incident-redrive-evidence-archive"
BUCKET_PATTERN = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
RUN_PATTERN = re.compile(r"^[1-9][0-9]{0,19}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
ENVELOPE_FIELDS = frozenset({"claims", "signature", "verification_key"})
CLAIM_FIELDS = frozenset(
    {
        "authorization_id",
        "canary_sha256",
        "key_arn",
        "key_revision_sha256",
        "kind",
        "preflight_sha256",
        "public_key_sha256",
        "route_sha256",
        "run_id",
        "schema_version",
        "signing_algorithm",
    }
)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("redrive evidence envelope contains duplicate keys")
        result[key] = value
    return result


def _load_envelope(path: str | Path) -> dict[str, object]:
    source = Path(path)
    if not source.is_file():
        raise ValueError("redrive evidence envelope does not exist or is not a file")
    try:
        value = json.loads(
            source.read_text(encoding="utf-8"), object_pairs_hook=_unique_object
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("cannot read redrive evidence envelope") from exc
    if not isinstance(value, dict) or set(value) != ENVELOPE_FIELDS:
        raise ValueError(
            "redrive evidence envelope fields do not match the archive schema"
        )
    claims = value["claims"]
    if (
        not isinstance(claims, dict)
        or set(claims) != CLAIM_FIELDS
        or claims.get("kind") != EVIDENCE_KIND
        or claims.get("schema_version") != 1
        or any(
            not isinstance(claims.get(name), str)
            or SHA256_PATTERN.fullmatch(claims[name]) is None
            for name in (
                "canary_sha256",
                "key_revision_sha256",
                "preflight_sha256",
                "public_key_sha256",
                "route_sha256",
            )
        )
    ):
        raise ValueError("redrive evidence claims do not match the archive schema")
    for name, encoding in (
        ("signature", "base64"),
        ("verification_key", "base64-der-subject-public-key-info"),
    ):
        item = value[name]
        if not isinstance(item, dict) or set(item) != {"encoding", "value"}:
            raise ValueError(
                f"redrive evidence {name} does not match the archive schema"
            )
        if item.get("encoding") != encoding or not isinstance(item.get("value"), str):
            raise ValueError(
                f"redrive evidence {name} does not match the archive schema"
            )
        try:
            decoded = base64.b64decode(item["value"], validate=True)
        except ValueError as exc:
            raise ValueError(
                f"redrive evidence {name} is not canonical base64"
            ) from exc
        if not decoded or base64.b64encode(decoded).decode("ascii") != item["value"]:
            raise ValueError(f"redrive evidence {name} is not canonical base64")
    return value


def _bucket_name(value: str) -> str:
    if (
        BUCKET_PATTERN.fullmatch(value) is None
        or ".." in value
        or ".-" in value
        or "-." in value
    ):
        raise ValueError("archive bucket name is not canonical")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise ValueError("archive bucket name must not be an IP address")


def _positive_integer(value: str, label: str, maximum: int) -> int:
    if not isinstance(value, str) or RUN_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{label} must be a positive integer")
    parsed = int(value)
    if parsed > maximum:
        raise ValueError(f"{label} exceeds its safety bound")
    return parsed


def _retention_time(value: object) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise RuntimeError("S3 returned an invalid retain-until timestamp")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise RuntimeError("S3 returned an invalid retain-until timestamp") from exc
    return parsed.astimezone(UTC)


@dataclass(frozen=True)
class ObjectLockArchive:
    bucket: str
    owner_account_id: str
    region: str
    retention_days: int

    @classmethod
    def inspect(
        cls,
        aws: AwsClient,
        *,
        bucket: str,
        owner_account_id: str,
        region: str,
        retention_days: int,
    ) -> ObjectLockArchive:
        bucket = _bucket_name(bucket)
        if re.fullmatch(r"[0-9]{12}", owner_account_id) is None:
            raise ValueError("archive owner account ID must contain 12 digits")
        if not 7 <= retention_days <= 365:
            raise ValueError("archive retention must be from 7 through 365 days")
        common = {
            "bucket": bucket,
            "expected_bucket_owner": owner_account_id,
            "region": region,
        }
        versioning = aws.call("s3api", "get-bucket-versioning", **common)
        lock = aws.call("s3api", "get-object-lock-configuration", **common)
        access = aws.call("s3api", "get-public-access-block", **common)
        default = lock.get("Rule", {}).get("DefaultRetention", {})
        public = access.get("PublicAccessBlockConfiguration", {})
        if versioning.get("Status") != "Enabled":
            raise RuntimeError("archive bucket versioning is not enabled")
        if (
            lock.get("ObjectLockEnabled") != "Enabled"
            or default.get("Mode") != "COMPLIANCE"
            or default.get("Days") != retention_days
            or set(default) != {"Mode", "Days"}
        ):
            raise RuntimeError(
                "archive bucket Object Lock differs from the reviewed contract"
            )
        if set(public) != {
            "BlockPublicAcls",
            "BlockPublicPolicy",
            "IgnorePublicAcls",
            "RestrictPublicBuckets",
        } or any(value is not True for value in public.values()):
            raise RuntimeError("archive bucket public-access block is incomplete")
        return cls(bucket, owner_account_id, region, retention_days)

    def put(
        self,
        aws: AwsClient,
        envelope: dict[str, object],
        *,
        workflow_run_id: str,
        workflow_run_attempt: str,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> dict[str, object]:
        run_id = _positive_integer(workflow_run_id, "workflow run ID", 10**20 - 1)
        attempt = _positive_integer(workflow_run_attempt, "workflow run attempt", 100)
        payload = _canonical(envelope)
        digest = hashlib.sha256(payload).digest()
        digest_hex = digest.hex()
        checksum = base64.b64encode(digest).decode("ascii")
        key = f"redrive-evidence/v1/{run_id}/{attempt}/{digest_hex}.json"

        with tempfile.NamedTemporaryFile() as source:
            source.write(payload)
            source.flush()
            response = aws.call(
                "s3api",
                "put-object",
                bucket=self.bucket,
                key=key,
                body=f"fileb://{source.name}",
                content_type="application/json",
                checksum_algorithm="SHA256",
                checksum_sha256=checksum,
                expected_bucket_owner=self.owner_account_id,
                if_none_match="*",
                server_side_encryption="AES256",
                region=self.region,
            )
        version_id = response.get("VersionId")
        if (
            response.get("ChecksumSHA256") != checksum
            or response.get("ServerSideEncryption") != "AES256"
            or not isinstance(version_id, str)
            or not version_id
            or version_id == "null"
        ):
            raise RuntimeError(
                "S3 put-object response differs from the reviewed contract"
            )
        retained = aws.call(
            "s3api",
            "get-object-retention",
            bucket=self.bucket,
            key=key,
            version_id=version_id,
            expected_bucket_owner=self.owner_account_id,
            region=self.region,
        ).get("Retention", {})
        retain_until = _retention_time(retained.get("RetainUntilDate"))
        if retained.get("Mode") != "COMPLIANCE" or retain_until < now() + timedelta(
            days=self.retention_days, minutes=-5
        ):
            raise RuntimeError(
                "stored evidence does not have the reviewed compliance retention"
            )
        return {
            "bucket_sha256": hashlib.sha256(self.bucket.encode("ascii")).hexdigest(),
            "checksum_sha256": digest_hex,
            "evidence_sha256": digest_hex,
            "kind": ARCHIVE_KIND,
            "object_key_sha256": hashlib.sha256(key.encode("ascii")).hexdigest(),
            "retain_until": retain_until.isoformat().replace("+00:00", "Z"),
            "retention_mode": "COMPLIANCE",
            "schema_version": 1,
            "status": "pass",
            "version_id_sha256": hashlib.sha256(version_id.encode("utf-8")).hexdigest(),
        }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Archive signed redrive evidence under verified S3 Object Lock retention."
    )
    parser.add_argument("evidence_envelope")
    parser.add_argument("--bucket", required=True)
    parser.add_argument("--owner-account-id", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--retention-days", type=int, required=True)
    parser.add_argument("--workflow-run-id", required=True)
    parser.add_argument("--workflow-run-attempt", required=True)
    parser.add_argument("--aws-cli", default="aws")
    parser.add_argument("--timeout-seconds", type=int, default=30)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        envelope = _load_envelope(args.evidence_envelope)
        aws = AwsCli(executable=args.aws_cli, timeout_seconds=args.timeout_seconds)
        archive = ObjectLockArchive.inspect(
            aws,
            bucket=args.bucket,
            owner_account_id=args.owner_account_id,
            region=args.region,
            retention_days=args.retention_days,
        )
        receipt = archive.put(
            aws,
            envelope,
            workflow_run_id=args.workflow_run_id,
            workflow_run_attempt=args.workflow_run_attempt,
        )
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"refusing to archive redrive evidence: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
