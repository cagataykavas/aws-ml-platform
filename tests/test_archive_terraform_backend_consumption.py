from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from scripts.archive_network_incident_redrive_evidence import ObjectLockArchive
from scripts.archive_terraform_backend_consumption import (
    ARCHIVE_KIND,
    _load_consumption,
    archive_consumption,
)
from scripts.lease_terraform_backend_admission import _canonical


ACCOUNT = "123456789012"
REGION = "eu-central-1"
BUCKET = "ml-platform-backend-consumptions-123456789012"
NOW = datetime(2026, 11, 6, 12, 0, tzinfo=UTC)


def consumption() -> dict[str, object]:
    document: dict[str, object] = {
        "admission_evidence_sha256": "a" * 64,
        "consumed_at": "2026-11-06T11:59:00Z",
        "expires_at": "2026-11-06T12:00:00Z",
        "kind": "terraform-backend-admission-lease-consumption",
        "lease_sha256": "b" * 64,
        "release_to_plan": True,
        "schema_version": 1,
        "status": "consumed",
        "verification_sha256": "c" * 64,
    }
    document["consumption_sha256"] = hashlib.sha256(_canonical(document)).hexdigest()
    return document


class FakeAws:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict[str, str | list[str]]]] = []
        self.versioning: dict[str, object] = {"Status": "Enabled"}
        self.lock: dict[str, object] = {
            "ObjectLockEnabled": "Enabled",
            "Rule": {"DefaultRetention": {"Mode": "COMPLIANCE", "Days": 30}},
        }
        self.public: dict[str, object] = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "BlockPublicPolicy": True,
                "IgnorePublicAcls": True,
                "RestrictPublicBuckets": True,
            }
        }
        self.put: dict[str, object] = {
            "ChecksumSHA256": "",
            "ServerSideEncryption": "AES256",
            "VersionId": "version-1",
        }
        self.retention: dict[str, object] = {
            "Retention": {
                "Mode": "COMPLIANCE",
                "RetainUntilDate": "2099-01-01T00:00:00Z",
            }
        }

    def call(
        self, service: str, operation: str, **parameters: str | list[str]
    ) -> dict[str, Any]:
        self.calls.append((service, operation, parameters))
        if operation == "get-bucket-versioning":
            return copy.deepcopy(self.versioning)
        if operation == "get-object-lock-configuration":
            return copy.deepcopy(self.lock)
        if operation == "get-public-access-block":
            return copy.deepcopy(self.public)
        if operation == "put-object":
            response = copy.deepcopy(self.put)
            response["ChecksumSHA256"] = parameters["checksum_sha256"]
            return response
        if operation == "get-object-retention":
            return copy.deepcopy(self.retention)
        raise AssertionError(f"unexpected AWS operation: {operation}")


def inspected_archive(aws: FakeAws) -> ObjectLockArchive:
    return ObjectLockArchive.inspect(
        aws,
        bucket=BUCKET,
        owner_account_id=ACCOUNT,
        region=REGION,
        retention_days=30,
    )


class ConsumptionValidationTests(unittest.TestCase):
    def test_loads_exact_self_digest_and_rejects_tampering(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "consumption.json"
            path.write_text(json.dumps(consumption()), encoding="utf-8")
            self.assertEqual(_load_consumption(path), consumption())

            tampered = consumption()
            tampered["release_to_plan"] = False
            path.write_text(json.dumps(tampered), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "reviewed schema"):
                _load_consumption(path)

    def test_rejects_duplicate_keys_symlinks_and_expired_window(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "consumption.json"
            path.write_text('{"kind":"a","kind":"b"}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate"):
                _load_consumption(path)

            target = root / "target.json"
            target.write_text(json.dumps(consumption()), encoding="utf-8")
            link = root / "link.json"
            os.symlink(target, link)
            with self.assertRaisesRegex(ValueError, "without following links"):
                _load_consumption(link)

            invalid = consumption()
            invalid["expires_at"] = invalid["consumed_at"]
            unsigned = dict(invalid)
            unsigned.pop("consumption_sha256")
            invalid["consumption_sha256"] = hashlib.sha256(
                _canonical(unsigned)
            ).hexdigest()
            target.write_text(json.dumps(invalid), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "lease window"):
                _load_consumption(target)


class ConsumptionArchiveTests(unittest.TestCase):
    def test_retains_canonical_payload_and_emits_private_receipt(self) -> None:
        aws = FakeAws()
        archive = inspected_archive(aws)
        document = consumption()

        receipt = archive_consumption(aws, archive, document)

        self.assertEqual(receipt["kind"], ARCHIVE_KIND)
        self.assertEqual(receipt["status"], "pass")
        self.assertEqual(receipt["retention_mode"], "COMPLIANCE")
        self.assertEqual(receipt["consumption_sha256"], document["consumption_sha256"])
        receipt_without_digest = dict(receipt)
        claimed = receipt_without_digest.pop("archive_receipt_sha256")
        self.assertEqual(hashlib.sha256(_canonical(receipt_without_digest)).hexdigest(), claimed)
        serialized = json.dumps(receipt)
        for private in (BUCKET, ACCOUNT, REGION, "version-1"):
            self.assertNotIn(private, serialized)

        put = aws.calls[3][2]
        payload_digest = hashlib.sha256(_canonical(document)).hexdigest()
        self.assertEqual(
            put["key"],
            f"terraform-backend-consumptions/v1/{payload_digest}.json",
        )
        self.assertEqual(put["if_none_match"], "*")
        self.assertEqual(put["checksum_algorithm"], "SHA256")
        self.assertEqual(put["server_side_encryption"], "AES256")
        self.assertEqual(
            put["checksum_sha256"],
            base64.b64encode(bytes.fromhex(payload_digest)).decode("ascii"),
        )
        retained = aws.calls[4][2]
        self.assertEqual(retained["version_id"], "version-1")
        self.assertEqual(retained["key"], put["key"])

    def test_rejects_mismatched_upload_or_retention_contract(self) -> None:
        aws = FakeAws()
        archive = inspected_archive(aws)
        aws.put["ServerSideEncryption"] = "aws:kms"
        with self.assertRaisesRegex(RuntimeError, "put-object response"):
            archive_consumption(aws, archive, consumption())

        aws = FakeAws()
        archive = inspected_archive(aws)
        aws.retention["Retention"] = {
            "Mode": "GOVERNANCE",
            "RetainUntilDate": (NOW + timedelta(days=30))
            .isoformat()
            .replace("+00:00", "Z"),
        }
        with self.assertRaisesRegex(RuntimeError, "compliance retention"):
            archive_consumption(aws, archive, consumption())


if __name__ == "__main__":
    unittest.main()
