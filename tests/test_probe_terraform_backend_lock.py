from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import unittest
from unittest.mock import patch

from scripts.audit_live_terraform_backend import _canonical
from scripts.probe_terraform_backend_lock import (
    LOCK_CANARY_SCHEMA,
    AwsCliLockStore,
    BackendLockCanaryError,
    probe_backend_lock,
)

PARTITION = "aws"
ACCOUNT = "123456789012"
REGION = "eu-central-1"
BUCKET = "ml-platform-terraform-state-123456789012"
STATE_KEY = "aws-ml-platform/staging/terraform.tfstate"
KMS_KEY = f"arn:aws:kms:{REGION}:{ACCOUNT}:key/12345678-1234-4234-8234-123456789012"
ROLE_NAME = "terraform-staging"
ROLE_ARN = f"arn:aws:iam::{ACCOUNT}:role/deploy/{ROLE_NAME}"
AUTHORIZATION = "41666644513-2"
SESSION = f"terraform-lock-{AUTHORIZATION}"
VERSION_ID = "3HL4kqtJlcpXroDTDmJ+3dcLwW4xJb8v"
ETAG = '"d41d8cd98f00b204e9800998ecf8427e"'
BACKEND_OBSERVED_AT = "2026-11-04T04:00:00Z"
LIVE_OBSERVED_AT = "2026-11-04T04:03:00Z"
CANARY_OBSERVED_AT = "2026-11-04T04:06:00Z"


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def backend_receipt(**overrides: object) -> dict[str, object]:
    document: dict[str, object] = {
        "schema_version": "terraform-backend-audit/v2",
        "observed_at": BACKEND_OBSERVED_AT,
        "accepted": True,
        "backend_type": "s3",
        "partition": PARTITION,
        "account_id": ACCOUNT,
        "region": REGION,
        "bucket_sha256": digest(BUCKET),
        "key_sha256": digest(STATE_KEY),
        "kms_key_arn_sha256": digest(KMS_KEY),
        "metadata_sha256": "a" * 64,
        "backend_config_sha256": "b" * 64,
        "encryption_enabled": True,
        "native_lockfile_enabled": True,
        "ambient_credentials_only": True,
    }
    document.update(overrides)
    document["evidence_sha256"] = hashlib.sha256(_canonical(document)).hexdigest()
    return document


def live_receipt(
    backend: dict[str, object] | None = None,
    **overrides: object,
) -> dict[str, object]:
    backend = backend or backend_receipt()
    document: dict[str, object] = {
        "schema_version": "terraform-live-backend-audit/v2",
        "observed_at": LIVE_OBSERVED_AT,
        "accepted": True,
        "partition": PARTITION,
        "account_id": ACCOUNT,
        "region": REGION,
        "bucket_sha256": digest(BUCKET),
        "kms_key_arn_sha256": digest(KMS_KEY),
        "role_arn_sha256": digest(ROLE_ARN),
        "role_name_sha256": digest(ROLE_NAME),
        "role_session_sha256": digest(SESSION),
        "backend_audit_sha256": backend["evidence_sha256"],
        "state_key_sha256": digest(STATE_KEY),
        "control_snapshot_sha256": "c" * 64,
        "caller_identity_verified": True,
        "bucket_region_verified": True,
        "bucket_versioning_verified": True,
        "bucket_kms_encryption_verified": True,
        "bucket_public_access_blocked": True,
        "bucket_owner_enforced": True,
        "bucket_policy_nonpublic": True,
        "kms_key_verified": True,
        "kms_rotation_verified": True,
    }
    document.update(overrides)
    document["evidence_sha256"] = hashlib.sha256(_canonical(document)).hexdigest()
    return document


class FakeStore:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []
        self.acquire_error: Exception | None = None
        self.contention_error: Exception | None = None
        self.contention_response: dict[str, object] | None = None
        self.release_error: Exception | None = None
        self.acquire_response: dict[str, object] | None = None
        self.release_response: dict[str, object] | None = None

    def acquire(self, **parameters: object) -> dict[str, object]:
        self.calls.append(("acquire", parameters))
        if self.acquire_error:
            raise self.acquire_error
        if self.acquire_response is not None:
            return copy.deepcopy(self.acquire_response)
        return {
            "VersionId": VERSION_ID,
            "ETag": ETAG,
            "ChecksumSHA256": parameters["checksum_sha256"],
            "ServerSideEncryption": "aws:kms",
            "SSEKMSKeyId": KMS_KEY,
            "BucketKeyEnabled": True,
        }

    def assert_contended(self, **parameters: object) -> dict[str, object] | None:
        self.calls.append(("contend", parameters))
        if self.contention_error:
            raise self.contention_error
        return copy.deepcopy(self.contention_response)

    def release(self, **parameters: object) -> dict[str, object]:
        self.calls.append(("release", parameters))
        if self.release_error:
            raise self.release_error
        if self.release_response is not None:
            return copy.deepcopy(self.release_response)
        return {"VersionId": parameters["version_id"]}


def run_probe(
    store: FakeStore,
    backend: dict[str, object] | None = None,
    live: dict[str, object] | None = None,
    **overrides: str,
) -> dict[str, object]:
    backend = backend or backend_receipt()
    live = live or live_receipt(backend)
    parameters = {
        "partition": PARTITION,
        "account_id": ACCOUNT,
        "region": REGION,
        "bucket": BUCKET,
        "state_key": STATE_KEY,
        "kms_key_arn": KMS_KEY,
        "role_arn": ROLE_ARN,
        "session_name": SESSION,
        "authorization_id": AUTHORIZATION,
        "observed_at": CANARY_OBSERVED_AT,
    }
    parameters.update(overrides)
    return probe_backend_lock(store, backend, live, **parameters)


class TerraformBackendLockCanaryTests(unittest.TestCase):
    def test_proves_acquisition_contention_and_exact_cleanup_privately(self) -> None:
        first_store = FakeStore()
        first = run_probe(first_store)
        second = run_probe(FakeStore())

        self.assertEqual(first, second)
        self.assertEqual(first["schema_version"], LOCK_CANARY_SCHEMA)
        self.assertTrue(first["conditional_acquisition_verified"])
        self.assertTrue(first["contention_rejection_verified"])
        self.assertTrue(first["exact_version_cleanup_verified"])
        self.assertEqual(
            [name for name, _ in first_store.calls], ["acquire", "contend", "release"]
        )
        acquire = first_store.calls[0][1]
        release = first_store.calls[2][1]
        self.assertEqual(acquire["expected_owner"], ACCOUNT)
        self.assertEqual(acquire["kms_key_arn"], KMS_KEY)
        self.assertEqual(release["version_id"], VERSION_ID)
        self.assertIn(".lock-canary/", str(acquire["key"]))
        self.assertNotEqual(acquire["key"], f"{STATE_KEY}.tflock")
        serialized = json.dumps(first, sort_keys=True)
        for secret in (BUCKET, STATE_KEY, KMS_KEY, ROLE_ARN, SESSION, VERSION_ID, ETAG):
            self.assertNotIn(secret, serialized)

    def test_rejects_tampered_or_cross_bound_receipts_before_writes(self) -> None:
        original_backend = backend_receipt()
        cases = (
            (
                {**original_backend, "evidence_sha256": "f" * 64},
                live_receipt(original_backend),
            ),
            (original_backend, {**live_receipt(original_backend), "accepted": False}),
            (
                original_backend,
                live_receipt(original_backend, state_key_sha256="f" * 64),
            ),
            (
                original_backend,
                live_receipt(original_backend, role_name_sha256="f" * 64),
            ),
            (original_backend, {**live_receipt(original_backend), "unexpected": True}),
        )
        for backend, live in cases:
            with self.subTest(live=live):
                store = FakeStore()
                with self.assertRaises(ValueError):
                    run_probe(store, backend, live)
                self.assertEqual(store.calls, [])

    def test_requires_run_bound_session_and_isolated_state_key(self) -> None:
        for overrides in (
            {"authorization_id": "not-a-run"},
            {"session_name": "terraform-lock-41666644513-3"},
            {"state_key": "../terraform.tfstate"},
        ):
            with self.subTest(overrides=overrides):
                store = FakeStore()
                with self.assertRaises(ValueError):
                    run_probe(store, **overrides)
                self.assertEqual(store.calls, [])

    def test_rejects_out_of_order_observations_before_writes(self) -> None:
        backend = backend_receipt()
        live = live_receipt(backend, observed_at="2026-11-04T04:06:01Z")
        store = FakeStore()

        with self.assertRaisesRegex(BackendLockCanaryError, "precedes"):
            run_probe(store, backend, live)

        self.assertEqual(store.calls, [])

    def test_unsafe_acquisition_response_still_cleans_exact_version(self) -> None:
        store = FakeStore()
        store.acquire_response = {
            "VersionId": VERSION_ID,
            "ETag": ETAG,
            "ChecksumSHA256": "wrong",
            "ServerSideEncryption": "aws:kms",
            "SSEKMSKeyId": KMS_KEY,
            "BucketKeyEnabled": True,
        }

        with self.assertRaisesRegex(BackendLockCanaryError, "acquisition response"):
            run_probe(store)

        self.assertEqual([name for name, _ in store.calls], ["acquire", "release"])
        self.assertEqual(store.calls[-1][1]["version_id"], VERSION_ID)

    def test_success_without_version_requires_operator_inspection(self) -> None:
        store = FakeStore()
        store.acquire_response = {
            "ETag": ETAG,
            "ChecksumSHA256": "unknown",
            "ServerSideEncryption": "aws:kms",
            "SSEKMSKeyId": KMS_KEY,
            "BucketKeyEnabled": True,
        }

        with self.assertRaisesRegex(BackendLockCanaryError, "operator inspection"):
            run_probe(store)

        self.assertEqual([name for name, _ in store.calls], ["acquire"])

    def test_contention_failure_is_sanitized_after_cleanup(self) -> None:
        store = FakeStore()
        store.contention_error = RuntimeError(f"private failure for {BUCKET}")

        with self.assertRaises(BackendLockCanaryError) as error:
            run_probe(store)

        self.assertIn("conditional lock probe failed", str(error.exception))
        self.assertNotIn(BUCKET, str(error.exception))
        self.assertEqual(
            [name for name, _ in store.calls], ["acquire", "contend", "release"]
        )

    def test_unexpected_second_owner_cleans_both_versions_before_failure(self) -> None:
        store = FakeStore()
        second_version = "4HL4kqtJlcpXroDTDmJ+3dcLwW4xJb9w"
        store.contention_response = {
            "VersionId": second_version,
            "ETag": ETAG,
            "ServerSideEncryption": "aws:kms",
            "SSEKMSKeyId": KMS_KEY,
            "BucketKeyEnabled": True,
        }

        original_contend = store.assert_contended

        def contend(**parameters: object) -> dict[str, object] | None:
            assert store.contention_response is not None
            store.contention_response["ChecksumSHA256"] = parameters["checksum_sha256"]
            return original_contend(**parameters)

        store.assert_contended = contend  # type: ignore[method-assign]
        with self.assertRaisesRegex(BackendLockCanaryError, "unexpectedly succeeded"):
            run_probe(store)

        released = [
            parameters["version_id"]
            for name, parameters in store.calls
            if name == "release"
        ]
        self.assertEqual(released, [second_version, VERSION_ID])

    def test_cleanup_failure_requires_operator_inspection(self) -> None:
        store = FakeStore()
        store.release_error = RuntimeError(f"private cleanup failure for {STATE_KEY}")

        with self.assertRaises(BackendLockCanaryError) as error:
            run_probe(store)

        self.assertIn("operator inspection", str(error.exception))
        self.assertNotIn(STATE_KEY, str(error.exception))

    def test_acquisition_failure_never_attempts_delete(self) -> None:
        store = FakeStore()
        store.acquire_error = RuntimeError(f"private acquisition failure for {BUCKET}")

        with self.assertRaisesRegex(
            BackendLockCanaryError, "conditional lock probe failed"
        ):
            run_probe(store)

        self.assertEqual([name for name, _ in store.calls], ["acquire"])


class AwsCliLockStoreTests(unittest.TestCase):
    def test_put_uses_private_file_conditional_write_and_exact_controls(self) -> None:
        observed: dict[str, object] = {}

        def fake_run(
            command: list[str], **_kwargs: object
        ) -> subprocess.CompletedProcess[str]:
            body_path = command[command.index("--body") + 1]
            with open(body_path, "rb") as stream:
                observed["body"] = stream.read()
            observed["command"] = command
            response = {
                "VersionId": VERSION_ID,
                "ETag": ETAG,
                "ChecksumSHA256": "checksum",
                "ServerSideEncryption": "aws:kms",
                "SSEKMSKeyId": KMS_KEY,
                "BucketKeyEnabled": True,
            }
            return subprocess.CompletedProcess(command, 0, json.dumps(response), "")

        store = AwsCliLockStore(executable="aws-reviewed", timeout_seconds=12)
        with patch(
            "scripts.probe_terraform_backend_lock.subprocess.run", side_effect=fake_run
        ):
            result = store.acquire(
                bucket=BUCKET,
                key="isolated/key",
                body=b"private body",
                checksum_sha256="checksum",
                expected_owner=ACCOUNT,
                region=REGION,
                kms_key_arn=KMS_KEY,
            )

        command = observed["command"]
        self.assertEqual(observed["body"], b"private body")
        self.assertEqual(result["VersionId"], VERSION_ID)
        self.assertIn("--if-none-match", command)
        self.assertIn("--expected-bucket-owner", command)
        self.assertIn("--ssekms-key-id", command)
        self.assertNotIn("private body", command)

    def test_contention_accepts_only_precondition_failed(self) -> None:
        store = AwsCliLockStore()
        parameters = {
            "bucket": BUCKET,
            "key": "isolated/key",
            "body": b"body",
            "checksum_sha256": "checksum",
            "expected_owner": ACCOUNT,
            "region": REGION,
            "kms_key_arn": KMS_KEY,
        }
        rejected = subprocess.CompletedProcess(
            ["aws"],
            255,
            "",
            "An error occurred (PreconditionFailed) when calling the PutObject operation",
        )
        with patch(
            "scripts.probe_terraform_backend_lock.subprocess.run", return_value=rejected
        ):
            store.assert_contended(**parameters)

        denied = subprocess.CompletedProcess(
            ["aws"],
            255,
            "",
            "An error occurred (AccessDenied) when calling the PutObject operation",
        )
        with (
            patch(
                "scripts.probe_terraform_backend_lock.subprocess.run",
                return_value=denied,
            ),
            self.assertRaisesRegex(RuntimeError, "not rejected safely"),
        ):
            store.assert_contended(**parameters)

    def test_release_deletes_only_the_exact_created_version(self) -> None:
        completed = subprocess.CompletedProcess(
            ["aws"], 0, json.dumps({"VersionId": VERSION_ID}), ""
        )
        store = AwsCliLockStore()
        with patch(
            "scripts.probe_terraform_backend_lock.subprocess.run",
            return_value=completed,
        ) as run:
            result = store.release(
                bucket=BUCKET,
                key="isolated/key",
                version_id=VERSION_ID,
                expected_owner=ACCOUNT,
                region=REGION,
            )

        command = run.call_args.args[0]
        self.assertEqual(result["VersionId"], VERSION_ID)
        self.assertEqual(command[command.index("--version-id") + 1], VERSION_ID)
        self.assertNotIn("--bypass-governance-retention", command)


if __name__ == "__main__":
    unittest.main()
