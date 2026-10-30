from __future__ import annotations

import base64
import copy
import json
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from scripts.archive_network_incident_redrive_evidence import (
    ObjectLockArchive,
    _load_envelope,
)

ACCOUNT = "123456789012"
REGION = "eu-central-1"
BUCKET = "ml-platform-redrive-evidence-123456789012"
NOW = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)


def envelope() -> dict[str, object]:
    return {
        "claims": {
            "authorization_id": "41010040602:1",
            "canary_sha256": "a" * 64,
            "key_arn": f"arn:aws:kms:{REGION}:{ACCOUNT}:key/12345678-1234-1234-1234-123456789abc",
            "key_revision_sha256": "b" * 64,
            "kind": "network-incident-redrive-evidence",
            "preflight_sha256": "c" * 64,
            "public_key_sha256": "d" * 64,
            "route_sha256": "e" * 64,
            "run_id": "12345678-1234-1234-1234-123456789abc",
            "schema_version": 1,
            "signing_algorithm": "ECDSA_SHA_256",
        },
        "signature": {
            "encoding": "base64",
            "value": base64.b64encode(b"s" * 70).decode("ascii"),
        },
        "verification_key": {
            "encoding": "base64-der-subject-public-key-info",
            "value": base64.b64encode(b"p" * 91).decode("ascii"),
        },
    }


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
                "RetainUntilDate": (NOW + timedelta(days=30))
                .isoformat()
                .replace("+00:00", "Z"),
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


class ObjectLockArchiveTests(unittest.TestCase):
    def test_inspects_uploads_and_verifies_exact_immutable_version(self) -> None:
        aws = FakeAws()
        archive = ObjectLockArchive.inspect(
            aws,
            bucket=BUCKET,
            owner_account_id=ACCOUNT,
            region=REGION,
            retention_days=30,
        )
        receipt = archive.put(
            aws,
            envelope(),
            workflow_run_id="41010040602",
            workflow_run_attempt="1",
            now=lambda: NOW,
        )

        self.assertEqual(receipt["status"], "pass")
        self.assertEqual(receipt["retention_mode"], "COMPLIANCE")
        self.assertNotIn(BUCKET, json.dumps(receipt))
        self.assertNotIn("version-1", json.dumps(receipt))
        self.assertEqual(
            [operation for _, operation, _ in aws.calls],
            [
                "get-bucket-versioning",
                "get-object-lock-configuration",
                "get-public-access-block",
                "put-object",
                "get-object-retention",
            ],
        )
        put = aws.calls[3][2]
        self.assertEqual(put["if_none_match"], "*")
        self.assertEqual(put["checksum_algorithm"], "SHA256")
        self.assertEqual(put["server_side_encryption"], "AES256")
        self.assertRegex(
            str(put["key"]),
            r"^redrive-evidence/v1/41010040602/1/[0-9a-f]{64}[.]json$",
        )
        retained = aws.calls[4][2]
        self.assertEqual(retained["version_id"], "version-1")
        self.assertEqual(retained["key"], put["key"])

    def test_rejects_versioning_lock_or_public_access_drift(self) -> None:
        for mutation, message in [
            (lambda aws: aws.versioning.update(Status="Suspended"), "versioning"),
            (
                lambda aws: aws.lock["Rule"]["DefaultRetention"].update(
                    Mode="GOVERNANCE"
                ),
                "Object Lock",
            ),
            (
                lambda aws: aws.public["PublicAccessBlockConfiguration"].update(
                    RestrictPublicBuckets=False
                ),
                "public-access",
            ),
        ]:
            with self.subTest(message=message):
                aws = FakeAws()
                mutation(aws)
                with self.assertRaisesRegex(RuntimeError, message):
                    ObjectLockArchive.inspect(
                        aws,
                        bucket=BUCKET,
                        owner_account_id=ACCOUNT,
                        region=REGION,
                        retention_days=30,
                    )

    def test_rejects_weak_or_mismatched_retention_after_upload(self) -> None:
        aws = FakeAws()
        archive = ObjectLockArchive.inspect(
            aws,
            bucket=BUCKET,
            owner_account_id=ACCOUNT,
            region=REGION,
            retention_days=30,
        )
        aws.retention["Retention"] = {
            "Mode": "GOVERNANCE",
            "RetainUntilDate": (NOW + timedelta(days=30))
            .isoformat()
            .replace("+00:00", "Z"),
        }

        with self.assertRaisesRegex(RuntimeError, "compliance retention"):
            archive.put(
                aws,
                envelope(),
                workflow_run_id="41010040602",
                workflow_run_attempt="1",
                now=lambda: NOW,
            )

    def test_rejects_noncanonical_target_and_run_identity(self) -> None:
        aws = FakeAws()
        with self.assertRaisesRegex(ValueError, "canonical"):
            ObjectLockArchive.inspect(
                aws,
                bucket="Bad_Bucket",
                owner_account_id=ACCOUNT,
                region=REGION,
                retention_days=30,
            )
        archive = ObjectLockArchive.inspect(
            aws,
            bucket=BUCKET,
            owner_account_id=ACCOUNT,
            region=REGION,
            retention_days=30,
        )
        with self.assertRaisesRegex(ValueError, "run attempt"):
            archive.put(
                aws,
                envelope(),
                workflow_run_id="41010040602",
                workflow_run_attempt="0",
                now=lambda: NOW,
            )


class EnvelopeValidationTests(unittest.TestCase):
    def test_rejects_duplicate_or_tampered_envelope_schema(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "envelope.json"
            path.write_text(
                '{"claims":{},"claims":{},"signature":{},"verification_key":{}}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "duplicate"):
                _load_envelope(path)

            value = envelope()
            value["claims"]["kind"] = "unreviewed"
            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "claims"):
                _load_envelope(path)


if __name__ == "__main__":
    unittest.main()
