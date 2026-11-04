from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from scripts.audit_live_terraform_backend import (
    LIVE_BACKEND_AUDIT_SCHEMA,
    LiveBackendAuditError,
    _canonical,
    _load_receipt,
    audit_live_backend,
)

PARTITION = "aws"
ACCOUNT = "123456789012"
REGION = "eu-central-1"
BUCKET = "ml-platform-terraform-state-123456789012"
KMS_KEY = f"arn:aws:kms:{REGION}:{ACCOUNT}:key/12345678-1234-4234-8234-123456789012"
ROLE_ARN = f"arn:aws:iam::{ACCOUNT}:role/deploy/terraform-staging"
SESSION = "terraform-audit-41573170992-1"
ASSUMED_ROLE = f"arn:aws:sts::{ACCOUNT}:assumed-role/terraform-staging/{SESSION}"
BACKEND_OBSERVED_AT = "2026-11-04T04:00:00Z"
LIVE_OBSERVED_AT = "2026-11-04T04:03:00Z"


def backend_receipt(**overrides: object) -> dict[str, object]:
    document: dict[str, object] = {
        "schema_version": "terraform-backend-audit/v2",
        "observed_at": BACKEND_OBSERVED_AT,
        "accepted": True,
        "backend_type": "s3",
        "partition": PARTITION,
        "account_id": ACCOUNT,
        "region": REGION,
        "bucket_sha256": hashlib.sha256(BUCKET.encode()).hexdigest(),
        "key_sha256": "a" * 64,
        "kms_key_arn_sha256": hashlib.sha256(KMS_KEY.encode()).hexdigest(),
        "metadata_sha256": "b" * 64,
        "backend_config_sha256": "c" * 64,
        "encryption_enabled": True,
        "native_lockfile_enabled": True,
        "ambient_credentials_only": True,
    }
    document.update(overrides)
    document["evidence_sha256"] = hashlib.sha256(_canonical(document)).hexdigest()
    return document


def responses() -> dict[tuple[str, str], dict[str, object]]:
    return {
        ("sts", "get-caller-identity"): {
            "Account": ACCOUNT,
            "Arn": ASSUMED_ROLE,
            "UserId": f"AROAEXAMPLE:{SESSION}",
        },
        ("s3api", "get-bucket-location"): {"LocationConstraint": REGION},
        ("s3api", "get-bucket-versioning"): {"Status": "Enabled"},
        ("s3api", "get-bucket-encryption"): {
            "ServerSideEncryptionConfiguration": {
                "Rules": [
                    {
                        "ApplyServerSideEncryptionByDefault": {
                            "SSEAlgorithm": "aws:kms",
                            "KMSMasterKeyID": KMS_KEY,
                        },
                        "BucketKeyEnabled": True,
                    }
                ]
            }
        },
        ("s3api", "get-public-access-block"): {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        },
        ("s3api", "get-bucket-ownership-controls"): {
            "OwnershipControls": {"Rules": [{"ObjectOwnership": "BucketOwnerEnforced"}]}
        },
        ("s3api", "get-bucket-policy-status"): {"PolicyStatus": {"IsPublic": False}},
        ("kms", "describe-key"): {
            "KeyMetadata": {
                "Arn": KMS_KEY,
                "AWSAccountId": ACCOUNT,
                "Enabled": True,
                "KeyState": "Enabled",
                "KeyManager": "CUSTOMER",
                "KeyUsage": "ENCRYPT_DECRYPT",
                "Origin": "AWS_KMS",
                "MultiRegion": False,
                "KeySpec": "SYMMETRIC_DEFAULT",
                "EncryptionAlgorithms": ["SYMMETRIC_DEFAULT"],
            }
        },
        ("kms", "get-key-rotation-status"): {
            "KeyRotationEnabled": True,
            "RotationPeriodInDays": 365,
        },
    }


class FakeAws:
    def __init__(
        self, values: dict[tuple[str, str], dict[str, object]] | None = None
    ) -> None:
        self.responses = values or responses()
        self.calls: list[tuple[str, str, dict[str, str | list[str]]]] = []

    def call(
        self, service: str, operation: str, **parameters: str | list[str]
    ) -> dict[str, Any]:
        self.calls.append((service, operation, parameters))
        return copy.deepcopy(self.responses[(service, operation)])


def run_audit(
    aws: FakeAws, receipt: dict[str, object] | None = None
) -> dict[str, object]:
    return audit_live_backend(
        aws,
        receipt or backend_receipt(),
        partition=PARTITION,
        account_id=ACCOUNT,
        region=REGION,
        bucket=BUCKET,
        kms_key_arn=KMS_KEY,
        role_arn=ROLE_ARN,
        session_name=SESSION,
        observed_at=LIVE_OBSERVED_AT,
    )


class LiveTerraformBackendAuditTests(unittest.TestCase):
    def test_accepts_exact_live_controls_and_emits_privacy_reduced_evidence(
        self,
    ) -> None:
        aws = FakeAws()

        first = run_audit(aws)
        second = run_audit(FakeAws())

        self.assertEqual(first, second)
        self.assertEqual(first["schema_version"], LIVE_BACKEND_AUDIT_SCHEMA)
        self.assertTrue(first["accepted"])
        self.assertTrue(first["caller_identity_verified"])
        self.assertTrue(first["bucket_kms_encryption_verified"])
        self.assertTrue(first["kms_rotation_verified"])
        serialized = json.dumps(first, sort_keys=True)
        for private_value in (BUCKET, KMS_KEY, ROLE_ARN, SESSION):
            self.assertNotIn(private_value, serialized)
        self.assertEqual(
            [(service, operation) for service, operation, _ in aws.calls],
            [
                ("sts", "get-caller-identity"),
                ("s3api", "get-bucket-location"),
                ("s3api", "get-bucket-versioning"),
                ("s3api", "get-bucket-encryption"),
                ("s3api", "get-public-access-block"),
                ("s3api", "get-bucket-ownership-controls"),
                ("s3api", "get-bucket-policy-status"),
                ("kms", "describe-key"),
                ("kms", "get-key-rotation-status"),
            ],
        )
        for service, _, parameters in aws.calls:
            if service == "s3api":
                self.assertEqual(parameters["expected_bucket_owner"], ACCOUNT)

    def test_rejects_tampered_or_mismatched_backend_receipt_before_aws_calls(
        self,
    ) -> None:
        for receipt in (
            backend_receipt(bucket_sha256="f" * 64),
            {**backend_receipt(), "accepted": False},
            {**backend_receipt(), "evidence_sha256": "f" * 64},
            {**backend_receipt(), "unexpected": True},
        ):
            with self.subTest(receipt=receipt):
                aws = FakeAws()
                with self.assertRaisesRegex(LiveBackendAuditError, "receipt"):
                    run_audit(aws, receipt)
                self.assertEqual(aws.calls, [])

    def test_rejects_backend_observation_after_live_audit(self) -> None:
        aws = FakeAws()
        receipt = backend_receipt(observed_at="2026-11-04T04:03:01Z")

        with self.assertRaisesRegex(LiveBackendAuditError, "precedes"):
            run_audit(aws, receipt)

        self.assertEqual(aws.calls, [])

    def test_rejects_wrong_active_role_before_control_plane_reads(self) -> None:
        values = responses()
        values[("sts", "get-caller-identity")]["Arn"] = (
            f"arn:aws:sts::{ACCOUNT}:assumed-role/other/{SESSION}"
        )
        aws = FakeAws(values)

        with self.assertRaisesRegex(LiveBackendAuditError, "active credentials"):
            run_audit(aws)

        self.assertEqual(
            [(service, operation) for service, operation, _ in aws.calls],
            [("sts", "get-caller-identity")],
        )

    def test_sanitizes_provider_failures(self) -> None:
        class FailingAws(FakeAws):
            def call(
                self, service: str, operation: str, **parameters: str | list[str]
            ) -> dict[str, Any]:
                raise RuntimeError(f"private diagnostic for {BUCKET} and {KMS_KEY}")

        with self.assertRaises(LiveBackendAuditError) as error:
            run_audit(FailingAws())

        self.assertIn("request failed", str(error.exception))
        self.assertNotIn(BUCKET, str(error.exception))
        self.assertNotIn(KMS_KEY, str(error.exception))

    def test_rejects_unsafe_s3_controls(self) -> None:
        mutations = (
            ("get-bucket-location", "LocationConstraint", "us-east-1", "Region"),
            ("get-bucket-versioning", "Status", "Suspended", "versioning"),
            (
                "get-bucket-encryption",
                "ServerSideEncryptionConfiguration",
                {"Rules": []},
                "encryption",
            ),
            (
                "get-public-access-block",
                "PublicAccessBlockConfiguration",
                {"BlockPublicAcls": False},
                "public-access",
            ),
            (
                "get-bucket-ownership-controls",
                "OwnershipControls",
                {"Rules": [{"ObjectOwnership": "ObjectWriter"}]},
                "ownership",
            ),
            (
                "get-bucket-policy-status",
                "PolicyStatus",
                {"IsPublic": True},
                "policy",
            ),
        )
        for operation, field, value, reason in mutations:
            with self.subTest(operation=operation):
                values = responses()
                values[("s3api", operation)][field] = value
                with self.assertRaisesRegex(LiveBackendAuditError, reason):
                    run_audit(FakeAws(values))

    def test_rejects_wrong_encryption_key_and_incomplete_public_access_blocks(
        self,
    ) -> None:
        values = responses()
        encryption = values[("s3api", "get-bucket-encryption")]
        encryption["ServerSideEncryptionConfiguration"]["Rules"][0][
            "ApplyServerSideEncryptionByDefault"
        ]["KMSMasterKeyID"] = KMS_KEY.replace("12345678", "87654321", 1)
        with self.assertRaisesRegex(LiveBackendAuditError, "reviewed KMS key"):
            run_audit(FakeAws(values))

        values = responses()
        values[("s3api", "get-public-access-block")]["PublicAccessBlockConfiguration"][
            "RestrictPublicBuckets"
        ] = False
        with self.assertRaisesRegex(LiveBackendAuditError, "public-access"):
            run_audit(FakeAws(values))

    def test_rejects_disabled_or_external_kms_key_and_slow_rotation(self) -> None:
        mutations = (
            ("KeyState", "Disabled"),
            ("KeyManager", "AWS"),
            ("Origin", "EXTERNAL"),
            ("MultiRegion", True),
            ("KeyUsage", "SIGN_VERIFY"),
        )
        for field, value in mutations:
            with self.subTest(field=field):
                values = responses()
                values[("kms", "describe-key")]["KeyMetadata"][field] = value
                with self.assertRaisesRegex(LiveBackendAuditError, "KMS key controls"):
                    run_audit(FakeAws(values))

        values = responses()
        values[("kms", "get-key-rotation-status")]["RotationPeriodInDays"] = 730
        with self.assertRaisesRegex(LiveBackendAuditError, "rotation"):
            run_audit(FakeAws(values))

    def test_maps_legacy_bucket_location_values_without_weakening_boundary(
        self,
    ) -> None:
        cases = (("us-east-1", None), ("eu-west-1", "EU"))
        for expected_region, location in cases:
            with self.subTest(region=expected_region):
                bucket = f"state-{expected_region}-123456789012"
                kms_key = KMS_KEY.replace(REGION, expected_region)
                receipt = backend_receipt(
                    region=expected_region,
                    bucket_sha256=hashlib.sha256(bucket.encode()).hexdigest(),
                    kms_key_arn_sha256=hashlib.sha256(kms_key.encode()).hexdigest(),
                )
                values = responses()
                values[("s3api", "get-bucket-location")]["LocationConstraint"] = (
                    location
                )
                values[("s3api", "get-bucket-encryption")][
                    "ServerSideEncryptionConfiguration"
                ]["Rules"][0]["ApplyServerSideEncryptionByDefault"][
                    "KMSMasterKeyID"
                ] = kms_key
                values[("kms", "describe-key")]["KeyMetadata"]["Arn"] = kms_key
                result = audit_live_backend(
                    FakeAws(values),
                    receipt,
                    partition=PARTITION,
                    account_id=ACCOUNT,
                    region=expected_region,
                    bucket=bucket,
                    kms_key_arn=kms_key,
                    role_arn=ROLE_ARN,
                    session_name=SESSION,
                )
                self.assertTrue(result["bucket_region_verified"])

    def test_rejects_invalid_boundary_before_aws_calls(self) -> None:
        aws = FakeAws()
        with self.assertRaisesRegex(LiveBackendAuditError, "outside"):
            audit_live_backend(
                aws,
                backend_receipt(),
                partition=PARTITION,
                account_id=ACCOUNT,
                region=REGION,
                bucket=BUCKET,
                kms_key_arn=KMS_KEY.replace(ACCOUNT, "999999999999"),
                role_arn=ROLE_ARN,
                session_name=SESSION,
            )
        self.assertEqual(aws.calls, [])

    def test_receipt_loader_rejects_duplicate_keys_and_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            duplicate = root / "duplicate.json"
            duplicate.write_text('{"accepted":true,"accepted":true}', encoding="utf-8")
            with self.assertRaisesRegex(LiveBackendAuditError, "duplicate"):
                _load_receipt(duplicate)

            target = root / "target.json"
            target.write_text(json.dumps(backend_receipt()), encoding="utf-8")
            link = root / "receipt.json"
            link.symlink_to(target)
            with self.assertRaisesRegex(
                LiveBackendAuditError, "without following links"
            ):
                _load_receipt(link)


if __name__ == "__main__":
    unittest.main()
