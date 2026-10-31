from __future__ import annotations

import hashlib
import re
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

from scripts.run_retained_evidence_live_audit import (
    attest_caller_identity,
    run_live_audit,
)
from scripts.verify_retained_redrive_evidence import ArchiveReceipt


ACCOUNT = "123456789012"
ROLE_ARN = f"arn:aws:iam::{ACCOUNT}:role/audit/retained-evidence"
SESSION = "retained-audit-123456789-2"
ASSUMED_ARN = f"arn:aws:sts::{ACCOUNT}:assumed-role/retained-evidence/{SESSION}"
WORKFLOW = Path(".github/workflows/retained-evidence-live-audit.yml")


class FakeAws:
    def __init__(self, response: dict[str, object]) -> None:
        self.response = response
        self.calls: list[tuple[str, str, dict[str, str | list[str]]]] = []

    def call(
        self, service: str, operation: str, **parameters: str | list[str]
    ) -> dict[str, Any]:
        self.calls.append((service, operation, parameters))
        return self.response


def identity(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "Account": ACCOUNT,
        "Arn": ASSUMED_ARN,
        "UserId": f"AROAEXAMPLE:{SESSION}",
    }
    value.update(overrides)
    return value


class CallerIdentityTests(unittest.TestCase):
    def test_attests_exact_account_role_and_workflow_session(self) -> None:
        aws = FakeAws(identity())

        receipt = attest_caller_identity(
            aws, role_arn=ROLE_ARN, session_name=SESSION, account_id=ACCOUNT
        )

        self.assertEqual(aws.calls, [("sts", "get-caller-identity", {})])
        self.assertTrue(receipt["caller_identity_verified"])
        self.assertEqual(
            receipt["auditor_role_sha256"],
            hashlib.sha256(ROLE_ARN.encode()).hexdigest(),
        )
        self.assertNotIn(ROLE_ARN, str(receipt))
        self.assertNotIn(SESSION, str(receipt))

    def test_rejects_wrong_account_role_or_session(self) -> None:
        mutations = (
            {"Account": "999999999999"},
            {"Arn": f"arn:aws:iam::{ACCOUNT}:role/retained-evidence"},
            {"Arn": ASSUMED_ARN.replace(SESSION, "retained-audit-1-1")},
            {"UserId": "AROAEXAMPLE:other-session"},
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                with self.assertRaisesRegex(RuntimeError, "expected auditor session"):
                    attest_caller_identity(
                        FakeAws(identity(**mutation)),
                        role_arn=ROLE_ARN,
                        session_name=SESSION,
                        account_id=ACCOUNT,
                    )

    def test_rejects_malformed_expected_boundary_before_aws_call(self) -> None:
        aws = FakeAws(identity())
        for role, session, account in (
            ("not-an-arn", SESSION, ACCOUNT),
            (ROLE_ARN, "interactive-session", ACCOUNT),
            (ROLE_ARN, SESSION, "999999999999"),
        ):
            with self.subTest(role=role, session=session, account=account):
                with self.assertRaises(ValueError):
                    attest_caller_identity(
                        aws, role_arn=role, session_name=session, account_id=account
                    )
        self.assertEqual(aws.calls, [])

    @patch("scripts.run_retained_evidence_live_audit.verify_retained_evidence")
    def test_live_audit_attests_identity_before_delegating_exact_version(
        self, verify: Any
    ) -> None:
        aws = FakeAws(identity())
        verify.return_value = {"kind": "retention-audit", "status": "pass"}
        receipt = object.__new__(ArchiveReceipt)

        result = run_live_audit(
            aws,
            receipt,
            role_arn=ROLE_ARN,
            session_name=SESSION,
            bucket="audit-bucket",
            key="redrive-evidence/v1/1/1/a.json",
            version_id="version-1",
            owner_account_id=ACCOUNT,
            region="eu-central-1",
        )

        self.assertEqual(aws.calls, [("sts", "get-caller-identity", {})])
        verify.assert_called_once_with(
            aws,
            receipt,
            bucket="audit-bucket",
            key="redrive-evidence/v1/1/1/a.json",
            version_id="version-1",
            owner_account_id=ACCOUNT,
            region="eu-central-1",
        )
        self.assertEqual(result["status"], "pass")
        self.assertTrue(result["caller_identity_verified"])


class LiveAuditWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")

    def test_is_manual_protected_and_minimally_permissioned(self) -> None:
        before_jobs = self.workflow.split("jobs:", 1)[0]
        self.assertIn("workflow_dispatch:", before_jobs)
        self.assertNotIn("pull_request", before_jobs)
        self.assertNotIn("push:", before_jobs)
        self.assertIn("permissions: {}", before_jobs)
        self.assertIn("environment: ${{ inputs.environment }}", self.workflow)
        self.assertIn("github.event.repository.default_branch", self.workflow)
        self.assertRegex(self.workflow, r"permissions:\n\s+contents: read\n\s+id-token: write")
        job_header = self.workflow.split("steps:", 1)[0]
        self.assertNotIn("secrets.", job_header)

    def test_uses_pinned_actions_short_oidc_session_and_exact_object_policy(self) -> None:
        uses = re.findall(r"uses: ([^\s]+)", self.workflow)
        self.assertGreaterEqual(len(uses), 4)
        self.assertTrue(all(re.fullmatch(r"[^@]+@[0-9a-f]{40}", item) for item in uses))
        self.assertIn("role-duration-seconds: 900", self.workflow)
        self.assertIn("allowed-account-ids: ${{ vars.AWS_ACCOUNT_ID }}", self.workflow)
        self.assertIn('"s3:GetObjectVersion","s3:GetObjectRetention"', self.workflow)
        self.assertIn("secrets.RETAINED_EVIDENCE_BUCKET", self.workflow)
        self.assertIn("secrets.RETAINED_EVIDENCE_OBJECT_KEY", self.workflow)
        self.assertNotIn("aws-access-key-id:", self.workflow)
        self.assertNotIn("aws-secret-access-key:", self.workflow)

    def test_fails_closed_and_only_archives_privacy_reduced_output(self) -> None:
        self.assertIn(
            '[[ "$RETAINED_EVIDENCE_AUDIT_ENABLED" != "true" ]]', self.workflow
        )
        self.assertIn("run_retained_evidence_live_audit.py", self.workflow)
        self.assertIn("--session-name \"$AUDITOR_SESSION_NAME\"", self.workflow)
        artifact = self.workflow.split("Archive privacy-reduced audit receipt", 1)[1]
        self.assertIn("retained-evidence-audit-receipt.json", artifact)
        before_cleanup = artifact.split("Remove private audit inputs", 1)[0]
        self.assertNotIn("retention-receipt.json\n", before_cleanup)
        self.assertIn("if: ${{ always() }}", self.workflow)


if __name__ == "__main__":
    unittest.main()

