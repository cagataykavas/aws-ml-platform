from __future__ import annotations

import base64
import copy
import hashlib
import json
import shutil
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any
from unittest.mock import patch

from scripts.archive_network_incident_redrive_evidence import ARCHIVE_KIND
from scripts.seal_network_incident_redrive_evidence import _canonical
from scripts.verify_retained_redrive_evidence import (
    AUDIT_KIND,
    ArchiveReceipt,
    AwsEvidenceCli,
    verify_ecdsa_signature,
    verify_retained_evidence,
)

ACCOUNT = "123456789012"
REGION = "eu-central-1"
BUCKET = "ml-platform-redrive-evidence-123456789012"
VERSION_ID = "version-1"
RETAIN_UNTIL = "2026-11-29T12:00:00Z"
PUBLIC_KEY = b"p" * 91


def envelope() -> dict[str, object]:
    return {
        "claims": {
            "authorization_id": "41010040602:1",
            "canary_sha256": "a" * 64,
            "key_arn": f"arn:aws:kms:{REGION}:{ACCOUNT}:key/12345678-1234-1234-1234-123456789abc",
            "key_revision_sha256": "b" * 64,
            "kind": "network-incident-redrive-evidence",
            "preflight_sha256": "c" * 64,
            "public_key_sha256": hashlib.sha256(PUBLIC_KEY).hexdigest(),
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
            "value": base64.b64encode(PUBLIC_KEY).decode("ascii"),
        },
    }


def target() -> tuple[bytes, str, dict[str, object]]:
    payload = _canonical(envelope())
    digest = hashlib.sha256(payload).hexdigest()
    key = f"redrive-evidence/v1/41010040602/1/{digest}.json"
    receipt = {
        "bucket_sha256": hashlib.sha256(BUCKET.encode("ascii")).hexdigest(),
        "checksum_sha256": digest,
        "evidence_sha256": digest,
        "kind": ARCHIVE_KIND,
        "object_key_sha256": hashlib.sha256(key.encode("ascii")).hexdigest(),
        "retain_until": RETAIN_UNTIL,
        "retention_mode": "COMPLIANCE",
        "schema_version": 1,
        "status": "pass",
        "version_id_sha256": hashlib.sha256(VERSION_ID.encode()).hexdigest(),
    }
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


class RetainedEvidenceTests(unittest.TestCase):
    def test_verifies_exact_version_storage_retention_and_signature(self) -> None:
        payload, key, receipt_document = target()
        aws = FakeAws(payload)
        signature_inputs: list[tuple[bytes, bytes, bytes]] = []

        def verify_signature(key_bytes: bytes, signature: bytes, claims: bytes) -> bool:
            signature_inputs.append((key_bytes, signature, claims))
            return True

        audit = verify_retained_evidence(
            aws,
            ArchiveReceipt.from_document(receipt_document),
            bucket=BUCKET,
            key=key,
            version_id=VERSION_ID,
            owner_account_id=ACCOUNT,
            region=REGION,
            signature_verifier=verify_signature,
        )

        self.assertEqual(audit["kind"], AUDIT_KIND)
        self.assertTrue(audit["signature_verified"])
        self.assertTrue(audit["storage_checksum_verified"])
        self.assertNotIn(BUCKET, json.dumps(audit))
        self.assertNotIn(VERSION_ID, json.dumps(audit))
        self.assertEqual(len(signature_inputs), 1)
        self.assertEqual(signature_inputs[0][0], PUBLIC_KEY)
        self.assertEqual(signature_inputs[0][2], _canonical(envelope()["claims"]))
        self.assertEqual(
            [operation for _, operation, _ in aws.calls],
            ["get-object", "get-object-retention"],
        )
        for _, _, parameters in aws.calls:
            self.assertEqual(parameters["version_id"], VERSION_ID)
            self.assertEqual(parameters["expected_bucket_owner"], ACCOUNT)

    def test_allows_compliance_retention_extension(self) -> None:
        payload, key, receipt_document = target()
        aws = FakeAws(payload)
        extended = "2026-12-29T12:00:00Z"
        aws.response["ObjectLockRetainUntilDate"] = extended
        aws.retention["Retention"]["RetainUntilDate"] = extended

        audit = verify_retained_evidence(
            aws,
            ArchiveReceipt.from_document(receipt_document),
            bucket=BUCKET,
            key=key,
            version_id=VERSION_ID,
            owner_account_id=ACCOUNT,
            region=REGION,
            signature_verifier=lambda *_: True,
        )

        self.assertEqual(audit["retain_until"], extended)

    def test_rejects_unbound_target_before_reading_s3(self) -> None:
        payload, key, receipt_document = target()
        aws = FakeAws(payload)
        receipt = ArchiveReceipt.from_document(receipt_document)

        with self.assertRaisesRegex(ValueError, "does not bind"):
            verify_retained_evidence(
                aws,
                receipt,
                bucket=BUCKET,
                key=key,
                version_id="different-version",
                owner_account_id=ACCOUNT,
                region=REGION,
                signature_verifier=lambda *_: True,
            )

        self.assertEqual(aws.calls, [])

    def test_rejects_body_checksum_or_signature_tampering(self) -> None:
        payload, key, receipt_document = target()
        for mutation, signature_result, message in [
            (lambda aws: setattr(aws, "payload", payload + b" "), True, "checksum"),
            (
                lambda aws: aws.response.update(ChecksumSHA256="invalid"),
                True,
                "checksum",
            ),
            (lambda aws: None, False, "signature"),
        ]:
            with self.subTest(message=message):
                aws = FakeAws(payload)
                mutation(aws)
                with self.assertRaisesRegex(RuntimeError, message):
                    verify_retained_evidence(
                        aws,
                        ArchiveReceipt.from_document(receipt_document),
                        bucket=BUCKET,
                        key=key,
                        version_id=VERSION_ID,
                        owner_account_id=ACCOUNT,
                        region=REGION,
                        signature_verifier=lambda *_: signature_result,
                    )

    def test_rejects_retention_or_object_identity_drift(self) -> None:
        payload, key, receipt_document = target()
        for mutation, message in [
            (
                lambda aws: aws.response.update(ServerSideEncryption="aws:kms"),
                "identity",
            ),
            (
                lambda aws: aws.response.update(ObjectLockMode="GOVERNANCE"),
                "compliance lock",
            ),
            (
                lambda aws: aws.retention["Retention"].update(
                    RetainUntilDate="2026-11-20T12:00:00Z"
                ),
                "compliance lock",
            ),
        ]:
            with self.subTest(message=message):
                aws = FakeAws(payload)
                mutation(aws)
                with self.assertRaisesRegex(RuntimeError, message):
                    verify_retained_evidence(
                        aws,
                        ArchiveReceipt.from_document(receipt_document),
                        bucket=BUCKET,
                        key=key,
                        version_id=VERSION_ID,
                        owner_account_id=ACCOUNT,
                        region=REGION,
                        signature_verifier=lambda *_: True,
                    )

    def test_rejects_malformed_receipt(self) -> None:
        _, _, receipt_document = target()
        receipt_document["checksum_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "commitments"):
            ArchiveReceipt.from_document(receipt_document)


class AwsEvidenceCliTests(unittest.TestCase):
    @patch("scripts.verify_retained_redrive_evidence.subprocess.run")
    def test_downloads_exact_version_with_checksum_mode(self, run: Any) -> None:
        body = b'{}'

        def execute(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
            Path(command[-1]).write_bytes(body)
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=json.dumps({"VersionId": VERSION_ID}),
                stderr="",
            )

        run.side_effect = execute
        response, downloaded = AwsEvidenceCli(timeout_seconds=17).get_object(
            bucket=BUCKET,
            key="redrive-evidence/v1/1/1/evidence.json",
            version_id=VERSION_ID,
            expected_bucket_owner=ACCOUNT,
            region=REGION,
        )

        self.assertEqual(response["VersionId"], VERSION_ID)
        self.assertEqual(downloaded, body)
        command = run.call_args.args[0]
        self.assertIn("--checksum-mode", command)
        self.assertEqual(command[command.index("--checksum-mode") + 1], "ENABLED")
        self.assertEqual(command[command.index("--version-id") + 1], VERSION_ID)
        self.assertEqual(command[command.index("--expected-bucket-owner") + 1], ACCOUNT)
        self.assertEqual(run.call_args.kwargs["timeout"], 17)


@unittest.skipUnless(shutil.which("openssl"), "OpenSSL is not installed")
class OpenSslSignatureTests(unittest.TestCase):
    def test_verifies_real_p256_signature_and_rejects_tampering(self) -> None:
        message = b'{"kind":"retained-evidence-test"}'
        with TemporaryDirectory() as directory:
            root = Path(directory)
            private_key = root / "private.pem"
            public_key = root / "public.der"
            signature = root / "signature.der"
            message_path = root / "message.json"
            message_path.write_bytes(message)
            subprocess.run(
                [
                    "openssl",
                    "genpkey",
                    "-algorithm",
                    "EC",
                    "-pkeyopt",
                    "ec_paramgen_curve:P-256",
                    "-out",
                    str(private_key),
                ],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                [
                    "openssl",
                    "pkey",
                    "-in",
                    str(private_key),
                    "-pubout",
                    "-outform",
                    "DER",
                    "-out",
                    str(public_key),
                ],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                [
                    "openssl",
                    "dgst",
                    "-sha256",
                    "-sign",
                    str(private_key),
                    "-out",
                    str(signature),
                    str(message_path),
                ],
                check=True,
                capture_output=True,
            )

            self.assertTrue(
                verify_ecdsa_signature(
                    public_key.read_bytes(), signature.read_bytes(), message
                )
            )
            self.assertFalse(
                verify_ecdsa_signature(
                    public_key.read_bytes(), signature.read_bytes(), message + b" "
                )
            )


if __name__ == "__main__":
    unittest.main()
