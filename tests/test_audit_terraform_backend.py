from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "audit_terraform_backend.py"
SPEC = importlib.util.spec_from_file_location("audit_terraform_backend", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

ACCOUNT = "123456789012"
PARTITION = "aws"
REGION = "eu-central-1"
BUCKET = "ml-platform-terraform-state-123456789012"
KEY = "aws-ml-platform/staging/terraform.tfstate"
KMS_KEY = f"arn:aws:kms:{REGION}:{ACCOUNT}:key/12345678-1234-4234-8234-123456789012"


def _metadata(**overrides: object) -> dict[str, object]:
    config: dict[str, object] = {
        "bucket": BUCKET,
        "key": KEY,
        "region": REGION,
        "encrypt": True,
        "kms_key_id": KMS_KEY,
        "use_lockfile": True,
        "acl": None,
        "dynamodb_table": None,
        "access_key": None,
        "secret_key": None,
        "token": None,
        "profile": None,
        "shared_credentials_file": None,
        "shared_credentials_files": [],
        "web_identity_token": None,
        "web_identity_token_file": None,
        "assume_role": None,
        "assume_role_with_web_identity": None,
        "endpoint": None,
        "endpoints": None,
        "dynamodb_endpoint": None,
        "iam_endpoint": None,
        "s3_endpoint": None,
        "sts_endpoint": None,
        "insecure": False,
        "skip_credentials_validation": False,
        "skip_metadata_api_check": False,
        "skip_region_validation": False,
        "skip_requesting_account_id": False,
        "skip_s3_checksum": False,
    }
    config.update(overrides)
    return {
        "version": 3,
        "serial": 1,
        "lineage": "00000000-0000-4000-8000-000000000000",
        "backend": {"type": "s3", "config": config, "hash": 42},
        "modules": [],
    }


class TerraformBackendAuditTests(unittest.TestCase):
    def _run(
        self,
        metadata: dict[str, object] | str,
        *,
        partition: str = PARTITION,
        account: str = ACCOUNT,
        region: str = REGION,
        bucket: str = BUCKET,
        key: str = KEY,
        kms_key: str = KMS_KEY,
        output: bool = False,
    ) -> tuple[subprocess.CompletedProcess[str], str | None]:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "terraform.tfstate"
            path.write_text(
                metadata if isinstance(metadata, str) else json.dumps(metadata),
                encoding="utf-8",
            )
            output_path = root / "audit.json"
            command = [
                sys.executable,
                str(SCRIPT),
                str(path),
                "--expected-partition",
                partition,
                "--expected-account-id",
                account,
                "--expected-region",
                region,
                "--expected-bucket",
                bucket,
                "--expected-key",
                key,
                "--expected-kms-key-arn",
                kms_key,
            ]
            if output:
                command.extend(("--output", str(output_path)))
            result = subprocess.run(
                command, check=False, capture_output=True, text=True
            )
            content = (
                output_path.read_text(encoding="utf-8")
                if output_path.exists()
                else None
            )
            return result, content

    def test_accepts_exact_encrypted_locked_backend_without_exposing_names(
        self,
    ) -> None:
        result, content = self._run(_metadata())
        report = json.loads(result.stdout)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIsNone(content)
        self.assertTrue(report["accepted"])
        self.assertEqual(report["schema_version"], MODULE.BACKEND_AUDIT_SCHEMA)
        self.assertTrue(report["encryption_enabled"])
        self.assertTrue(report["native_lockfile_enabled"])
        self.assertTrue(report["ambient_credentials_only"])
        self.assertEqual(
            report["bucket_sha256"], hashlib.sha256(BUCKET.encode()).hexdigest()
        )
        self.assertNotIn(BUCKET, result.stdout)
        self.assertNotIn(KEY, result.stdout)
        self.assertNotIn(KMS_KEY, result.stdout)

    def test_file_output_is_atomic_deterministic_and_privacy_reduced(self) -> None:
        first_result, first = self._run(_metadata(), output=True)
        second_result, second = self._run(_metadata(), output=True)

        self.assertEqual(first_result.returncode, 0)
        self.assertEqual(second_result.returncode, 0)
        first_document = json.loads(first)
        second_document = json.loads(second)
        for document in (first_document, second_document):
            self.assertRegex(
                document.pop("observed_at"),
                r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$",
            )
            document.pop("evidence_sha256")
        self.assertEqual(first_document, second_document)
        self.assertNotIn(BUCKET, first)
        self.assertNotIn(KEY, first)

    def test_rejects_local_backend_and_mismatched_identity(self) -> None:
        local = _metadata()
        local["backend"]["type"] = "local"
        local_result, _ = self._run(local)
        bucket_result, _ = self._run(_metadata(), bucket="another-state-bucket")

        self.assertEqual(local_result.returncode, 2)
        self.assertIn("must be s3", local_result.stderr)
        self.assertEqual(bucket_result.returncode, 2)
        self.assertIn("identity does not match", bucket_result.stderr)

    def test_rejects_unencrypted_or_unlocked_state(self) -> None:
        unencrypted, _ = self._run(_metadata(encrypt=False))
        unlocked, _ = self._run(_metadata(use_lockfile=False))
        legacy, _ = self._run(_metadata(dynamodb_table="legacy-lock-table"))

        self.assertIn("encryption", unencrypted.stderr)
        self.assertIn("state locking", unlocked.stderr)
        self.assertIn("DynamoDB", legacy.stderr)
        self.assertEqual(
            {unencrypted.returncode, unlocked.returncode, legacy.returncode}, {2}
        )

    def test_rejects_static_credentials_and_secondary_assumption(self) -> None:
        for overrides in (
            {"access_key": "AKIAEXAMPLE"},
            {"profile": "production"},
            {"web_identity_token_file": "/tmp/token"},
            {"assume_role": {"role_arn": "arn:aws:iam::123456789012:role/other"}},
        ):
            with self.subTest(overrides=overrides):
                result, _ = self._run(_metadata(**overrides))
                self.assertEqual(result.returncode, 2)
                self.assertNotIn("AKIAEXAMPLE", result.stderr)
                self.assertNotIn("production", result.stderr)

    def test_rejects_custom_endpoints_and_validation_bypasses(self) -> None:
        endpoint, _ = self._run(_metadata(s3_endpoint="https://localhost:9000"))
        bypass, _ = self._run(_metadata(skip_credentials_validation=True))

        self.assertEqual(endpoint.returncode, 2)
        self.assertIn("custom AWS endpoints", endpoint.stderr)
        self.assertEqual(bypass.returncode, 2)
        self.assertIn("validation bypasses", bypass.stderr)

    def test_rejects_cross_partition_account_or_region_kms_boundary(self) -> None:
        cross_account = KMS_KEY.replace(ACCOUNT, "999999999999")
        cross_region = KMS_KEY.replace(REGION, "us-east-1")

        partition_result, _ = self._run(_metadata(), partition="aws-us-gov")
        account_result, _ = self._run(_metadata(), kms_key=cross_account)
        region_result, _ = self._run(_metadata(), kms_key=cross_region)

        self.assertEqual(partition_result.returncode, 2)
        self.assertEqual(account_result.returncode, 2)
        self.assertEqual(region_result.returncode, 2)
        for result in (partition_result, account_result, region_result):
            self.assertIn("deployment partition, account, and Region", result.stderr)

    def test_rejects_unsafe_state_keys_and_nonprivate_acl(self) -> None:
        traversal, _ = self._run(_metadata(), key="../terraform.tfstate")
        public_acl, _ = self._run(_metadata(acl="public-read"))

        self.assertEqual(traversal.returncode, 2)
        self.assertIn("state key", traversal.stderr)
        self.assertEqual(public_acl.returncode, 2)
        self.assertIn("ACL", public_acl.stderr)

    def test_rejects_duplicate_keys_unknown_root_fields_and_output_alias(self) -> None:
        duplicate, _ = self._run('{"version":3,"version":3}')
        unknown = _metadata()
        unknown["unexpected"] = True
        unknown_result, _ = self._run(unknown)

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "terraform.tfstate"
            path.write_text(json.dumps(_metadata()), encoding="utf-8")
            alias = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    str(path),
                    "--expected-partition",
                    PARTITION,
                    "--expected-account-id",
                    ACCOUNT,
                    "--expected-region",
                    REGION,
                    "--expected-bucket",
                    BUCKET,
                    "--expected-key",
                    KEY,
                    "--expected-kms-key-arn",
                    KMS_KEY,
                    "--output",
                    str(path),
                ],
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertEqual(duplicate.returncode, 2)
        self.assertIn("duplicate", duplicate.stderr)
        self.assertEqual(unknown_result.returncode, 2)
        self.assertIn("unsupported", unknown_result.stderr)
        self.assertEqual(alias.returncode, 2)
        self.assertIn("must not replace", alias.stderr)

    def test_rejects_symlinked_metadata_without_following_it(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.json"
            target.write_text(json.dumps(_metadata()), encoding="utf-8")
            link = root / "terraform.tfstate"
            link.symlink_to(target)
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    str(link),
                    "--expected-partition",
                    PARTITION,
                    "--expected-account-id",
                    ACCOUNT,
                    "--expected-region",
                    REGION,
                    "--expected-bucket",
                    BUCKET,
                    "--expected-key",
                    KEY,
                    "--expected-kms-key-arn",
                    KMS_KEY,
                ],
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertEqual(result.returncode, 2)
        self.assertIn("without following links", result.stderr)


if __name__ == "__main__":
    unittest.main()
