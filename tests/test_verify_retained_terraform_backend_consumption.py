from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from scripts.archive_terraform_backend_consumption import ARCHIVE_KIND
from scripts.lease_terraform_backend_admission import _canonical
from scripts.verify_retained_terraform_backend_consumption import (
    AUDIT_KIND,
    ConsumptionArchiveReceipt,
    _load_json,
    verify_retained_consumption,
)
from tests.test_archive_terraform_backend_consumption import consumption


ACCOUNT = "123456789012"
REGION = "eu-central-1"
BUCKET = "ml-platform-backend-consumptions-123456789012"
VERSION_ID = "version-1"
RETAIN_UNTIL = "2026-12-06T12:00:00Z"


def target() -> tuple[bytes, str, dict[str, object]]:
    document = consumption()
    payload = _canonical(document)
    checksum = hashlib.sha256(payload).hexdigest()
    key = f"terraform-backend-consumptions/v1/{checksum}.json"
    receipt: dict[str, object] = {
        "bucket_sha256": hashlib.sha256(BUCKET.encode("ascii")).hexdigest(),
        "checksum_sha256": checksum,
        "consumption_sha256": document["consumption_sha256"],
        "kind": ARCHIVE_KIND,
        "object_key_sha256": hashlib.sha256(key.encode("ascii")).hexdigest(),
        "retain_until": RETAIN_UNTIL,
        "retention_mode": "COMPLIANCE",
        "schema_version": 1,
        "status": "pass",
        "version_id_sha256": hashlib.sha256(VERSION_ID.encode()).hexdigest(),
    }
    receipt["archive_receipt_sha256"] = hashlib.sha256(_canonical(receipt)).hexdigest()
    return payload, key, receipt


class FakeAws:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload
        self.calls: list[tuple[str, str, dict[str, str | list[str]]]] = []
        checksum = base64.b64encode(hashlib.sha256(payload).digest()).decode("ascii")
        self.response: dict[str, object] = {
            "ChecksumSHA256": checksum,
            "ContentType": "application/json",
            "ObjectLockMode": "COMPLIANCE",
            "ObjectLockRetainUntilDate": RETAIN_UNTIL,
            "ServerSideEncryption": "AES256",
            "VersionId": VERSION_ID,
        }
        self.retention: dict[str, object] = {
            "Retention": {
                "Mode": "COMPLIANCE",
                "RetainUntilDate": RETAIN_UNTIL,
            }
        }

    def get_object(self, **parameters: str) -> tuple[dict[str, Any], bytes]:
        self.calls.append(("s3api", "get-object", parameters))
        return copy.deepcopy(self.response), self.payload

    def call(
        self, service: str, operation: str, **parameters: str | list[str]
    ) -> dict[str, Any]:
        self.calls.append((service, operation, parameters))
        if operation == "get-object-retention":
            return copy.deepcopy(self.retention)
        raise AssertionError(f"unexpected AWS operation: {operation}")


class RetainedConsumptionAuditTests(unittest.TestCase):
    def test_verifies_exact_version_content_and_retention(self) -> None:
        payload, key, receipt_document = target()
        aws = FakeAws(payload)

        audit = verify_retained_consumption(
            aws,
            ConsumptionArchiveReceipt.from_document(receipt_document),
            bucket=BUCKET,
            key=key,
            version_id=VERSION_ID,
            expected_consumption_sha256=receipt_document["consumption_sha256"],
            owner_account_id=ACCOUNT,
            region=REGION,
        )

        self.assertEqual(audit["kind"], AUDIT_KIND)
        self.assertEqual(audit["status"], "pass")
        self.assertTrue(audit["storage_checksum_verified"])
        self.assertEqual(len(audit["audit_receipt_sha256"]), 64)
        self.assertNotIn(BUCKET, json.dumps(audit))
        self.assertNotIn(VERSION_ID, json.dumps(audit))
        self.assertEqual(
            [operation for _, operation, _ in aws.calls],
            ["get-object", "get-object-retention"],
        )
        for _, _, parameters in aws.calls:
            self.assertEqual(parameters["version_id"], VERSION_ID)
            self.assertEqual(parameters["expected_bucket_owner"], ACCOUNT)

    def test_allows_only_retention_extension(self) -> None:
        payload, key, receipt_document = target()
        aws = FakeAws(payload)
        extended = "2027-01-06T12:00:00Z"
        aws.response["ObjectLockRetainUntilDate"] = extended
        aws.retention["Retention"]["RetainUntilDate"] = extended

        audit = verify_retained_consumption(
            aws,
            ConsumptionArchiveReceipt.from_document(receipt_document),
            bucket=BUCKET,
            key=key,
            version_id=VERSION_ID,
            expected_consumption_sha256=receipt_document["consumption_sha256"],
            owner_account_id=ACCOUNT,
            region=REGION,
        )

        self.assertEqual(audit["retain_until"], extended)

    def test_rejects_unbound_target_or_expected_consumption_before_s3(self) -> None:
        payload, key, receipt_document = target()
        for overrides, message in [
            ({"version_id": "different-version"}, "does not bind"),
            ({"key": key.replace(".json", "0.json")}, "object key"),
            ({"expected_consumption_sha256": "0" * 64}, "expected consumption"),
        ]:
            with self.subTest(message=message):
                aws = FakeAws(payload)
                arguments = {
                    "bucket": BUCKET,
                    "key": key,
                    "version_id": VERSION_ID,
                    "expected_consumption_sha256": receipt_document[
                        "consumption_sha256"
                    ],
                    "owner_account_id": ACCOUNT,
                    "region": REGION,
                    **overrides,
                }
                with self.assertRaisesRegex(ValueError, message):
                    verify_retained_consumption(
                        aws,
                        ConsumptionArchiveReceipt.from_document(receipt_document),
                        **arguments,
                    )
                self.assertEqual(aws.calls, [])

    def test_rejects_object_metadata_or_payload_tampering(self) -> None:
        payload, key, receipt_document = target()
        for mutation, message in [
            (lambda aws: setattr(aws, "payload", payload + b" "), "checksum"),
            (lambda aws: aws.response.update(ChecksumSHA256="invalid"), "checksum"),
            (lambda aws: aws.response.update(ServerSideEncryption="aws:kms"), "encryption"),
            (lambda aws: aws.response.update(ContentType="text/plain"), "identity"),
        ]:
            with self.subTest(message=message):
                aws = FakeAws(payload)
                mutation(aws)
                with self.assertRaisesRegex(RuntimeError, message):
                    verify_retained_consumption(
                        aws,
                        ConsumptionArchiveReceipt.from_document(receipt_document),
                        bucket=BUCKET,
                        key=key,
                        version_id=VERSION_ID,
                        expected_consumption_sha256=receipt_document[
                            "consumption_sha256"
                        ],
                        owner_account_id=ACCOUNT,
                        region=REGION,
                    )

    def test_rejects_retention_drift(self) -> None:
        payload, key, receipt_document = target()
        for mutation in [
            lambda aws: aws.response.update(ObjectLockMode="GOVERNANCE"),
            lambda aws: aws.retention["Retention"].update(
                RetainUntilDate="2026-11-20T12:00:00Z"
            ),
        ]:
            with self.subTest(mutation=mutation):
                aws = FakeAws(payload)
                mutation(aws)
                with self.assertRaisesRegex(RuntimeError, "compliance lock"):
                    verify_retained_consumption(
                        aws,
                        ConsumptionArchiveReceipt.from_document(receipt_document),
                        bucket=BUCKET,
                        key=key,
                        version_id=VERSION_ID,
                        expected_consumption_sha256=receipt_document[
                            "consumption_sha256"
                        ],
                        owner_account_id=ACCOUNT,
                        region=REGION,
                    )

    def test_rejects_malformed_or_tampered_archive_receipt(self) -> None:
        _, _, receipt_document = target()
        for mutation, message in [
            (lambda value: value.update(status="fail"), "schema"),
            (lambda value: value.update(consumption_sha256="0" * 64), "digest"),
            (lambda value: value.update(extra=True), "schema"),
        ]:
            with self.subTest(message=message):
                candidate = copy.deepcopy(receipt_document)
                mutation(candidate)
                with self.assertRaisesRegex(ValueError, message):
                    ConsumptionArchiveReceipt.from_document(candidate)

    def test_loader_rejects_duplicate_keys_and_symlinks(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            duplicate = root / "duplicate.json"
            duplicate.write_text('{"kind":"a","kind":"b"}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate"):
                _load_json(duplicate)

            target_file = root / "receipt.json"
            target_file.write_text("{}", encoding="utf-8")
            link = root / "receipt-link.json"
            os.symlink(target_file, link)
            with self.assertRaisesRegex(ValueError, "without following links"):
                _load_json(link)


if __name__ == "__main__":
    unittest.main()
