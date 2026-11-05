from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from scripts.lease_terraform_backend_admission import (
    KEY_SPEC,
    LEASE_KIND,
    MAX_TTL_SECONDS,
    SIGNING_ALGORITHM,
    BackendAdmission,
    BackendAdmissionLeaseError,
    KmsLeaseKey,
    main,
    verify_and_consume_lease,
    verify_lease,
)
from tests.test_probe_terraform_backend_lock import (
    ACCOUNT,
    AUTHORIZATION,
    KMS_KEY,
    PARTITION,
    REGION,
)
from tests.test_verify_terraform_backend_admission import _verify

KEY_ID = "12345678-1234-1234-1234-123456789abc"
SIGNING_KEY_ARN = f"arn:{PARTITION}:kms:{REGION}:{ACCOUNT}:key/{KEY_ID}"
PUBLIC_KEY = b"p" * 91
PUBLIC_KEY_SHA256 = hashlib.sha256(PUBLIC_KEY).hexdigest()
SIGNATURE = b"s" * 70
ISSUED_AT = "2026-11-05T08:00:00Z"
WORKFLOW_SUBJECT = "repo:cagataykavas/aws-ml-platform:environment:terraform-staging"
WORKFLOW_SHA = "1" * 40


class FakeAws:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict[str, str | list[str]]]] = []
        self.metadata = {
            "Arn": SIGNING_KEY_ARN,
            "KeyId": KEY_ID,
            "Enabled": True,
            "KeyState": "Enabled",
            "KeyManager": "CUSTOMER",
            "KeyUsage": "SIGN_VERIFY",
            "KeySpec": KEY_SPEC,
            "SigningAlgorithms": [SIGNING_ALGORITHM],
        }
        self.public = {
            "KeyId": SIGNING_KEY_ARN,
            "PublicKey": base64.b64encode(PUBLIC_KEY).decode("ascii"),
            "KeyUsage": "SIGN_VERIFY",
            "KeySpec": KEY_SPEC,
            "SigningAlgorithms": [SIGNING_ALGORITHM],
        }
        self.signature_valid: object = True

    def call(
        self, service: str, operation: str, **parameters: str | list[str]
    ) -> dict[str, object]:
        self.calls.append((service, operation, parameters))
        if operation == "describe-key":
            return {"KeyMetadata": dict(self.metadata)}
        if operation == "get-public-key":
            return dict(self.public)
        if operation == "sign":
            return {
                "KeyId": SIGNING_KEY_ARN,
                "SigningAlgorithm": SIGNING_ALGORITHM,
                "Signature": base64.b64encode(SIGNATURE).decode("ascii"),
            }
        if operation == "verify":
            return {
                "KeyId": SIGNING_KEY_ARN,
                "SigningAlgorithm": SIGNING_ALGORITHM,
                "SignatureValid": self.signature_valid,
            }
        raise AssertionError(f"unexpected AWS operation: {operation}")


def admission_document() -> dict[str, object]:
    return _verify()


def issue_lease(
    *, ttl_seconds: int = 300
) -> tuple[FakeAws, KmsLeaseKey, dict[str, object]]:
    aws = FakeAws()
    key = KmsLeaseKey.inspect(
        aws,
        SIGNING_KEY_ARN,
        partition=PARTITION,
        account_id=ACCOUNT,
        region=REGION,
    )
    envelope = key.issue(
        aws,
        BackendAdmission.from_document(admission_document()),
        authorization_id=AUTHORIZATION,
        workflow_subject=WORKFLOW_SUBJECT,
        workflow_sha=WORKFLOW_SHA,
        issued_at=ISSUED_AT,
        ttl_seconds=ttl_seconds,
    )
    return aws, key, envelope


def verify(envelope: object, **overrides: object) -> dict[str, object]:
    parameters = {
        "key_arn": SIGNING_KEY_ARN,
        "expected_public_key_sha256": PUBLIC_KEY_SHA256,
        "authorization_id": AUTHORIZATION,
        "workflow_subject": WORKFLOW_SUBJECT,
        "workflow_sha": WORKFLOW_SHA,
        "verification_time": "2026-11-05T08:04:59Z",
        "signature_verifier": lambda public_key, signature, message: (
            public_key == PUBLIC_KEY and signature == SIGNATURE and bool(message)
        ),
    }
    parameters.update(overrides)
    return verify_lease(envelope, admission_document(), **parameters)


def consume(
    envelope: object, directory: Path, **overrides: object
) -> dict[str, object]:
    parameters = {
        "key_arn": SIGNING_KEY_ARN,
        "expected_public_key_sha256": PUBLIC_KEY_SHA256,
        "authorization_id": AUTHORIZATION,
        "workflow_subject": WORKFLOW_SUBJECT,
        "workflow_sha": WORKFLOW_SHA,
        "verification_time": "2026-11-05T08:04:59Z",
        "consumption_directory": directory,
        "signature_verifier": lambda public_key, signature, message: (
            public_key == PUBLIC_KEY and signature == SIGNATURE and bool(message)
        ),
    }
    parameters.update(overrides)
    return verify_and_consume_lease(envelope, admission_document(), **parameters)


class KmsAdmissionLeaseTests(unittest.TestCase):
    def test_issues_private_provenance_bound_lease_and_verifies_offline(self) -> None:
        aws, key, envelope = issue_lease()
        audit = verify(envelope)

        claims = envelope["claims"]
        self.assertEqual(claims["kind"], LEASE_KIND)
        self.assertEqual(claims["max_ttl_seconds"], MAX_TTL_SECONDS)
        self.assertEqual(claims["public_key_sha256"], key.public_key_sha256)
        self.assertEqual(claims["expires_at"], "2026-11-05T08:05:00Z")
        self.assertTrue(audit["release_to_plan"])
        self.assertTrue(audit["signature_verified"])
        self.assertEqual(
            [operation for _, operation, _ in aws.calls],
            ["describe-key", "get-public-key", "sign", "verify"],
        )

        serialized = json.dumps(envelope, sort_keys=True)
        for private in (
            ACCOUNT,
            REGION,
            KMS_KEY,
            SIGNING_KEY_ARN,
            AUTHORIZATION,
            WORKFLOW_SUBJECT,
            WORKFLOW_SHA,
        ):
            self.assertNotIn(private, serialized)

    def test_rejects_tampered_or_nonpassing_admission_receipt(self) -> None:
        admission = admission_document()
        for field, value, error in (
            ("release_to_plan", False, "passing"),
            ("evidence_window_sha256", "f" * 64, "self-digest"),
            ("unreviewed", True, "fields"),
        ):
            with self.subTest(field=field):
                changed = {**admission, field: value}
                with self.assertRaisesRegex(BackendAdmissionLeaseError, error):
                    BackendAdmission.from_document(changed)

    def test_rejects_wrong_authorization_provenance_and_key_pin(self) -> None:
        _, _, envelope = issue_lease()
        cases = (
            ({"authorization_id": "wrong-run"}, "authorization"),
            (
                {
                    "workflow_subject": (
                        "repo:cagataykavas/aws-ml-platform:environment:production"
                    )
                },
                "provenance",
            ),
            ({"workflow_sha": "2" * 40}, "provenance"),
            ({"expected_public_key_sha256": "f" * 64}, "signing key"),
        )
        for overrides, error in cases:
            with (
                self.subTest(overrides=overrides),
                self.assertRaisesRegex(BackendAdmissionLeaseError, error),
            ):
                verify(envelope, **overrides)

    def test_rejects_not_yet_valid_expired_and_overlong_leases(self) -> None:
        _, _, envelope = issue_lease()
        with self.assertRaisesRegex(BackendAdmissionLeaseError, "not valid yet"):
            verify(envelope, verification_time="2026-11-05T07:59:59Z")
        with self.assertRaisesRegex(BackendAdmissionLeaseError, "expired"):
            verify(envelope, verification_time="2026-11-05T08:05:00Z")
        with self.assertRaisesRegex(BackendAdmissionLeaseError, "TTL"):
            issue_lease(ttl_seconds=MAX_TTL_SECONDS + 1)

        changed = copy.deepcopy(envelope)
        changed["claims"]["expires_at"] = "2026-11-05T08:10:01Z"
        with self.assertRaisesRegex(BackendAdmissionLeaseError, "lifetime"):
            verify(changed)

    def test_rejects_claim_extension_and_invalid_signature(self) -> None:
        _, _, envelope = issue_lease()
        extended = copy.deepcopy(envelope)
        extended["claims"]["unreviewed"] = True
        with self.assertRaisesRegex(BackendAdmissionLeaseError, "claim fields"):
            verify(extended)

        with self.assertRaisesRegex(BackendAdmissionLeaseError, "signature"):
            verify(envelope, signature_verifier=lambda *_: False)

    def test_rejects_wrong_scope_disabled_key_and_failed_kms_verification(self) -> None:
        aws = FakeAws()
        with self.assertRaisesRegex(BackendAdmissionLeaseError, "partition"):
            KmsLeaseKey.inspect(
                aws,
                SIGNING_KEY_ARN.replace(ACCOUNT, "210987654321"),
                partition=PARTITION,
                account_id=ACCOUNT,
                region=REGION,
            )

        aws = FakeAws()
        aws.metadata["Enabled"] = False
        with self.assertRaisesRegex(RuntimeError, "reviewed contract"):
            KmsLeaseKey.inspect(
                aws,
                SIGNING_KEY_ARN,
                partition=PARTITION,
                account_id=ACCOUNT,
                region=REGION,
            )

        aws = FakeAws()
        key = KmsLeaseKey.inspect(
            aws,
            SIGNING_KEY_ARN,
            partition=PARTITION,
            account_id=ACCOUNT,
            region=REGION,
        )
        aws.signature_valid = 1
        with self.assertRaisesRegex(RuntimeError, "did not verify"):
            key.issue(
                aws,
                BackendAdmission.from_document(admission_document()),
                authorization_id=AUTHORIZATION,
                workflow_subject=WORKFLOW_SUBJECT,
                workflow_sha=WORKFLOW_SHA,
                issued_at=ISSUED_AT,
                ttl_seconds=300,
            )

    def test_verified_lease_is_consumed_once_with_private_minimal_evidence(
        self,
    ) -> None:
        _, _, envelope = issue_lease()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            os.chmod(root, 0o700)
            receipt = consume(envelope, root)

            self.assertEqual(receipt["status"], "consumed")
            self.assertTrue(receipt["release_to_plan"])
            markers = list(root.iterdir())
            self.assertEqual(len(markers), 1)
            self.assertEqual(os.stat(markers[0]).st_mode & 0o777, 0o600)
            retained = markers[0].read_text(encoding="utf-8")
            retained_document = json.loads(retained)
            retained_digest = retained_document.pop("consumption_sha256")
            self.assertEqual(
                retained_digest,
                hashlib.sha256(
                    json.dumps(
                        retained_document,
                        allow_nan=False,
                        separators=(",", ":"),
                        sort_keys=True,
                    ).encode()
                ).hexdigest(),
            )
            for private in (
                ACCOUNT,
                REGION,
                SIGNING_KEY_ARN,
                AUTHORIZATION,
                WORKFLOW_SUBJECT,
                WORKFLOW_SHA,
            ):
                self.assertNotIn(private, retained)

            with self.assertRaisesRegex(BackendAdmissionLeaseError, "already consumed"):
                consume(envelope, root)

    def test_invalid_lease_cannot_create_consumption_marker(self) -> None:
        _, _, envelope = issue_lease()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            os.chmod(root, 0o700)
            with self.assertRaisesRegex(BackendAdmissionLeaseError, "signature"):
                consume(envelope, root, signature_verifier=lambda *_: False)
            self.assertEqual(list(root.iterdir()), [])

    def test_concurrent_consumers_allow_exactly_one_plan_release(self) -> None:
        _, _, envelope = issue_lease()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            os.chmod(root, 0o700)

            def attempt(_position: int) -> str:
                try:
                    return str(consume(envelope, root)["status"])
                except BackendAdmissionLeaseError as exc:
                    return exc.reason

            with ThreadPoolExecutor(max_workers=6) as pool:
                outcomes = list(pool.map(attempt, range(6)))

            self.assertEqual(outcomes.count("consumed"), 1)
            self.assertEqual(outcomes.count("lease was already consumed"), 5)
            self.assertEqual(len(list(root.iterdir())), 1)

    def test_consumption_directory_must_be_private_and_not_a_symlink(self) -> None:
        _, _, envelope = issue_lease()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            broad = root / "broad"
            broad.mkdir(mode=0o755)
            os.chmod(broad, 0o755)
            with self.assertRaisesRegex(BackendAdmissionLeaseError, "permissions"):
                consume(envelope, broad)

            protected = root / "protected"
            protected.mkdir(mode=0o700)
            linked = root / "linked"
            linked.symlink_to(protected, target_is_directory=True)
            with self.assertRaisesRegex(
                BackendAdmissionLeaseError, "protected directory"
            ):
                consume(envelope, linked)


class AdmissionLeaseCliTests(unittest.TestCase):
    def test_cli_issues_and_verifies_private_files_and_refuses_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            admission = root / "admission.json"
            output = root / "lease.json"
            audit = root / "lease-audit.json"
            admission.write_text(json.dumps(admission_document()), encoding="utf-8")
            arguments = [
                "issue",
                str(admission),
                "--partition",
                PARTITION,
                "--account-id",
                ACCOUNT,
                "--region",
                REGION,
                "--kms-key-arn",
                SIGNING_KEY_ARN,
                "--authorization-id",
                AUTHORIZATION,
                "--workflow-subject",
                WORKFLOW_SUBJECT,
                "--workflow-sha",
                WORKFLOW_SHA,
                "--output",
                str(output),
            ]
            with (
                patch(
                    "scripts.lease_terraform_backend_admission.AwsCli",
                    return_value=FakeAws(),
                ),
                patch(
                    "scripts.lease_terraform_backend_admission._now_utc",
                    return_value=ISSUED_AT,
                ),
            ):
                self.assertEqual(main(arguments), 0)
            self.assertEqual(os.stat(output).st_mode & 0o777, 0o600)

            verify_arguments = [
                "verify",
                str(output),
                str(admission),
                "--kms-key-arn",
                SIGNING_KEY_ARN,
                "--public-key-sha256",
                PUBLIC_KEY_SHA256,
                "--authorization-id",
                AUTHORIZATION,
                "--workflow-subject",
                WORKFLOW_SUBJECT,
                "--workflow-sha",
                WORKFLOW_SHA,
                "--verification-time",
                "2026-11-05T08:04:59Z",
                "--output",
                str(audit),
            ]
            with patch(
                "scripts.lease_terraform_backend_admission.verify_ecdsa_signature",
                return_value=True,
            ):
                self.assertEqual(main(verify_arguments), 0)
            self.assertTrue(
                json.loads(audit.read_text(encoding="utf-8"))["release_to_plan"]
            )
            self.assertEqual(os.stat(audit).st_mode & 0o777, 0o600)

            arguments[-1] = str(admission)
            with patch(
                "scripts.lease_terraform_backend_admission.AwsCli",
                return_value=FakeAws(),
            ):
                self.assertEqual(main(arguments), 2)

    def test_cli_consumes_a_verified_lease_once(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            admission = root / "admission.json"
            lease = root / "lease.json"
            output = root / "consumption.json"
            markers = root / "consumed"
            markers.mkdir(mode=0o700)
            admission.write_text(json.dumps(admission_document()), encoding="utf-8")
            lease.write_text(json.dumps(issue_lease()[2]), encoding="utf-8")
            arguments = [
                "consume",
                str(lease),
                str(admission),
                "--kms-key-arn",
                SIGNING_KEY_ARN,
                "--public-key-sha256",
                PUBLIC_KEY_SHA256,
                "--authorization-id",
                AUTHORIZATION,
                "--workflow-subject",
                WORKFLOW_SUBJECT,
                "--workflow-sha",
                WORKFLOW_SHA,
                "--verification-time",
                "2026-11-05T08:04:59Z",
                "--consumption-directory",
                str(markers),
                "--output",
                str(output),
            ]
            with patch(
                "scripts.lease_terraform_backend_admission.verify_ecdsa_signature",
                return_value=True,
            ):
                self.assertEqual(main(arguments), 0)
                self.assertEqual(main(arguments), 2)
            self.assertEqual(json.loads(output.read_text())["status"], "consumed")
            self.assertEqual(len(list(markers.iterdir())), 1)


if __name__ == "__main__":
    unittest.main()
