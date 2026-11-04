from __future__ import annotations

import copy
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.audit_live_terraform_backend import _canonical
from scripts.verify_terraform_backend_admission import (
    BACKEND_ADMISSION_SCHEMA,
    BackendAdmissionError,
    main,
    verify_backend_admission,
)
from tests.test_probe_terraform_backend_lock import (
    ACCOUNT,
    AUTHORIZATION,
    BUCKET,
    KMS_KEY,
    PARTITION,
    REGION,
    ROLE_ARN,
    SESSION,
    STATE_KEY,
    FakeStore,
    backend_receipt,
    live_receipt,
    run_probe,
)


def _chain():
    backend = backend_receipt()
    live = live_receipt(backend)
    canary = run_probe(FakeStore(), backend, live)
    return backend, live, canary


def _verify(backend=None, live=None, canary=None, **overrides: str):
    default_backend, default_live, default_canary = _chain()
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
    }
    parameters.update(overrides)
    return verify_backend_admission(
        backend or default_backend,
        live or default_live,
        canary or default_canary,
        **parameters,
    )


def _resign(document: dict[str, object]) -> dict[str, object]:
    changed = copy.deepcopy(document)
    changed.pop("evidence_sha256", None)
    changed["evidence_sha256"] = hashlib.sha256(_canonical(changed)).hexdigest()
    return changed


class TerraformBackendAdmissionTests(unittest.TestCase):
    def test_cross_binds_three_receipts_into_private_deterministic_admission(
        self,
    ) -> None:
        backend, live, canary = _chain()
        first = _verify(backend, live, canary)
        second = _verify(backend, live, canary)

        self.assertEqual(first, second)
        self.assertEqual(first["schema_version"], BACKEND_ADMISSION_SCHEMA)
        self.assertTrue(first["accepted"])
        self.assertTrue(first["release_to_plan"])
        self.assertEqual(first["backend_audit_sha256"], backend["evidence_sha256"])
        self.assertEqual(first["live_backend_audit_sha256"], live["evidence_sha256"])
        self.assertEqual(first["lock_canary_sha256"], canary["evidence_sha256"])
        serialized = json.dumps(first, sort_keys=True)
        for private in (
            ACCOUNT,
            REGION,
            BUCKET,
            STATE_KEY,
            KMS_KEY,
            ROLE_ARN,
            SESSION,
            AUTHORIZATION,
        ):
            self.assertNotIn(private, serialized)

    def test_rejects_tampered_receipts_even_when_digest_is_not_updated(self) -> None:
        backend, live, canary = _chain()
        cases = (
            ({**backend, "accepted": False}, live, canary),
            (backend, {**live, "kms_rotation_verified": False}, canary),
            (backend, live, {**canary, "exact_version_cleanup_verified": False}),
        )
        for candidate in cases:
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                _verify(*candidate)

    def test_rejects_self_consistent_canary_policy_downgrade_and_extension(
        self,
    ) -> None:
        backend, live, canary = _chain()
        downgraded = _resign({**canary, "contention_rejection_verified": False})
        extended = _resign({**canary, "unreviewed": True})

        with self.assertRaisesRegex(BackendAdmissionError, "another run"):
            _verify(backend, live, downgraded)
        with self.assertRaisesRegex(BackendAdmissionError, "fields"):
            _verify(backend, live, extended)

    def test_recomputes_canary_key_and_payload_commitments(self) -> None:
        backend, live, canary = _chain()
        for field in ("canary_key_sha256", "payload_sha256"):
            with self.subTest(field=field):
                changed = _resign({**canary, field: "f" * 64})
                with self.assertRaisesRegex(BackendAdmissionError, "another run"):
                    _verify(backend, live, changed)

    def test_rejects_cross_run_canary_even_when_each_chain_is_valid(self) -> None:
        backend, live, _canary = _chain()
        other_authorization = "41686237354-1"
        other_session = f"terraform-lock-{other_authorization}"
        other_live = live_receipt(
            backend,
            role_session_sha256=hashlib.sha256(other_session.encode()).hexdigest(),
        )
        other_canary = run_probe(
            FakeStore(),
            backend,
            other_live,
            session_name=other_session,
            authorization_id=other_authorization,
        )

        with self.assertRaises(ValueError):
            _verify(backend, live, other_canary)

    def test_rejects_boundary_substitution_before_admission(self) -> None:
        for overrides in (
            {"bucket": "other-terraform-state-bucket"},
            {"state_key": "other/terraform.tfstate"},
            {"authorization_id": "41686237353-3"},
            {"session_name": "terraform-lock-41686237353-3"},
        ):
            with self.subTest(overrides=overrides), self.assertRaises(ValueError):
                _verify(**overrides)

    def test_provider_identifiers_only_enter_one_boundary_commitment(self) -> None:
        evidence = _verify()

        self.assertEqual(len(str(evidence["deployment_boundary_sha256"])), 64)
        self.assertEqual(len(str(evidence["authorization_sha256"])), 64)
        self.assertEqual(len(str(evidence["evidence_sha256"])), 64)
        self.assertEqual(
            set(evidence),
            {
                "schema_version",
                "accepted",
                "release_to_plan",
                "deployment_boundary_sha256",
                "authorization_sha256",
                "backend_audit_sha256",
                "live_backend_audit_sha256",
                "lock_canary_sha256",
                "backend_configuration_verified",
                "live_controls_verified",
                "conditional_lock_verified",
                "exact_cleanup_verified",
                "evidence_sha256",
            },
        )


class TerraformBackendAdmissionCliTests(unittest.TestCase):
    def test_cli_writes_private_receipt_and_refuses_input_overwrite(self) -> None:
        backend, live, canary = _chain()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = [
                root / name for name in ("backend.json", "live.json", "canary.json")
            ]
            for path, document in zip(paths, (backend, live, canary), strict=True):
                path.write_text(json.dumps(document), encoding="utf-8")
            output = root / "admission.json"
            arguments = [
                "verify_terraform_backend_admission.py",
                *(str(path) for path in paths),
                "--partition",
                PARTITION,
                "--account-id",
                ACCOUNT,
                "--region",
                REGION,
                "--bucket",
                BUCKET,
                "--state-key",
                STATE_KEY,
                "--kms-key-arn",
                KMS_KEY,
                "--role-arn",
                ROLE_ARN,
                "--session-name",
                SESSION,
                "--authorization-id",
                AUTHORIZATION,
                "--output",
                str(output),
            ]
            with patch("sys.argv", arguments):
                self.assertEqual(main(), 0)

            document = json.loads(output.read_text(encoding="utf-8"))
            self.assertTrue(document["release_to_plan"])
            self.assertEqual(os.stat(output).st_mode & 0o777, 0o600)

            arguments[-1] = str(paths[0])
            with patch("sys.argv", arguments):
                self.assertEqual(main(), 2)


if __name__ == "__main__":
    unittest.main()
