from __future__ import annotations

import re
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

from scripts.run_retained_backend_consumption_audit import (
    run_live_backend_consumption_audit,
)
from scripts.verify_retained_terraform_backend_consumption import (
    ConsumptionArchiveReceipt,
)

ACCOUNT = "123456789012"
ROLE_ARN = f"arn:aws:iam::{ACCOUNT}:role/backend-consumption-auditor"
SESSION = "retained-audit-123456789-2"
ASSUMED_ARN = (
    f"arn:aws:sts::{ACCOUNT}:assumed-role/backend-consumption-auditor/{SESSION}"
)
WORKFLOW = Path(".github/workflows/backend-consumption-live-audit.yml")


class FakeAws:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict[str, str | list[str]]]] = []

    def call(
        self, service: str, operation: str, **parameters: str | list[str]
    ) -> dict[str, Any]:
        self.calls.append((service, operation, parameters))
        return {
            "Account": ACCOUNT,
            "Arn": ASSUMED_ARN,
            "UserId": f"AROAEXAMPLE:{SESSION}",
        }


class LiveBackendConsumptionAuditTests(unittest.TestCase):
    @patch("scripts.run_retained_backend_consumption_audit.verify_retained_consumption")
    def test_attests_exact_oidc_session_before_reading_retained_version(
        self, verify: Any
    ) -> None:
        aws = FakeAws()
        verify.return_value = {"kind": "backend-consumption-audit", "status": "pass"}
        receipt = object.__new__(ConsumptionArchiveReceipt)

        result = run_live_backend_consumption_audit(
            aws,
            receipt,
            role_arn=ROLE_ARN,
            session_name=SESSION,
            bucket="backend-consumption-archive",
            key="terraform-backend-consumptions/v1/a.json",
            version_id="version-1",
            expected_consumption_sha256="a" * 64,
            owner_account_id=ACCOUNT,
            region="eu-central-1",
        )

        self.assertEqual(aws.calls, [("sts", "get-caller-identity", {})])
        verify.assert_called_once_with(
            aws,
            receipt,
            bucket="backend-consumption-archive",
            key="terraform-backend-consumptions/v1/a.json",
            version_id="version-1",
            expected_consumption_sha256="a" * 64,
            owner_account_id=ACCOUNT,
            region="eu-central-1",
        )
        self.assertEqual(result["status"], "pass")
        self.assertTrue(result["caller_identity_verified"])
        self.assertNotIn(ROLE_ARN, str(result))
        self.assertNotIn(SESSION, str(result))

    @patch("scripts.run_retained_backend_consumption_audit.verify_retained_consumption")
    def test_wrong_active_role_fails_before_retained_object_read(
        self, verify: Any
    ) -> None:
        aws = FakeAws()
        aws.call = lambda *args, **kwargs: {  # type: ignore[method-assign]
            "Account": ACCOUNT,
            "Arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/other/{SESSION}",
            "UserId": f"AROAEXAMPLE:{SESSION}",
        }

        with self.assertRaisesRegex(RuntimeError, "expected auditor session"):
            run_live_backend_consumption_audit(
                aws,
                object.__new__(ConsumptionArchiveReceipt),
                role_arn=ROLE_ARN,
                session_name=SESSION,
                bucket="backend-consumption-archive",
                key="terraform-backend-consumptions/v1/a.json",
                version_id="version-1",
                expected_consumption_sha256="a" * 64,
                owner_account_id=ACCOUNT,
                region="eu-central-1",
            )
        verify.assert_not_called()


class BackendConsumptionAuditWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")

    def test_is_manual_default_branch_protected_and_minimally_permissioned(
        self,
    ) -> None:
        before_jobs = self.workflow.split("jobs:", 1)[0]
        self.assertIn("workflow_dispatch:", before_jobs)
        self.assertNotIn("pull_request", before_jobs)
        self.assertNotIn("push:", before_jobs)
        self.assertIn("permissions: {}", before_jobs)
        self.assertIn("environment: ${{ inputs.environment }}", self.workflow)
        self.assertIn("github.event.repository.default_branch", self.workflow)
        self.assertRegex(
            self.workflow, r"permissions:\n\s+contents: read\n\s+id-token: write"
        )
        self.assertNotIn("secrets.", self.workflow.split("steps:", 1)[0])

    def test_uses_pinned_actions_short_session_and_exact_object_policy(self) -> None:
        uses = re.findall(r"uses: ([^\s]+)", self.workflow)
        self.assertGreaterEqual(len(uses), 4)
        self.assertTrue(all(re.fullmatch(r"[^@]+@[0-9a-f]{40}", item) for item in uses))
        self.assertIn("role-duration-seconds: 900", self.workflow)
        self.assertIn("allowed-account-ids: ${{ vars.AWS_ACCOUNT_ID }}", self.workflow)
        self.assertIn('"s3:GetObjectVersion","s3:GetObjectRetention"', self.workflow)
        self.assertIn("secrets.BACKEND_CONSUMPTION_OBJECT_KEY", self.workflow)
        self.assertNotIn("s3:ListBucket", self.workflow)
        self.assertNotIn("s3:PutObject", self.workflow)
        self.assertNotIn("s3:Delete", self.workflow)
        self.assertNotIn("aws-access-key-id:", self.workflow)
        self.assertNotIn("aws-secret-access-key:", self.workflow)

    def test_fails_closed_and_archives_only_privacy_reduced_output(self) -> None:
        self.assertIn(
            '[[ "$BACKEND_CONSUMPTION_AUDIT_ENABLED" != "true" ]]', self.workflow
        )
        self.assertIn("run_retained_backend_consumption_audit.py", self.workflow)
        self.assertIn("--expected-consumption-sha256", self.workflow)
        artifact = self.workflow.split("Archive privacy-reduced audit receipt", 1)[1]
        self.assertIn("backend-consumption-audit-receipt.json", artifact)
        before_cleanup = artifact.split("Remove private audit inputs", 1)[0]
        self.assertNotIn("backend-consumption-archive-receipt.json\n", before_cleanup)
        self.assertIn("if: ${{ always() }}", self.workflow)


if __name__ == "__main__":
    unittest.main()
