from __future__ import annotations

import re
import unittest
from pathlib import Path

WORKFLOW = Path(".github/workflows/incident-redrive-canary.yml")


class RedriveCanaryWorkflowContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")

    def test_requires_protected_environment_and_serializes_it(self) -> None:
        self.assertIn("type: environment", self.workflow)
        self.assertIn("environment: ${{ inputs.environment }}", self.workflow)
        self.assertIn(
            "group: incident-redrive-canary-${{ inputs.environment }}", self.workflow
        )
        self.assertIn("cancel-in-progress: false", self.workflow)

    def test_validates_nonproduction_route_before_oidc_exchange(self) -> None:
        validation = self.workflow.index("Validate isolated redrive route")
        credential_exchange = self.workflow.index("Exchange GitHub OIDC token")

        self.assertLess(validation, credential_exchange)
        self.assertIn("--production-queue-arn", self.workflow)
        self.assertIn("--fault-queue-arn", self.workflow)
        self.assertIn("--fault-dead-letter-queue-arn", self.workflow)
        self.assertIn("--redrive-canary-role-arn", self.workflow)

    def test_verifies_live_boundary_before_data_plane_drill(self) -> None:
        credentials = self.workflow.index("Exchange GitHub OIDC token")
        preflight = self.workflow.index("Verify live IAM and SQS drill boundary")
        drill = self.workflow.index("Run bounded poison-message redrive drill")

        self.assertLess(credentials, preflight)
        self.assertLess(preflight, drill)
        self.assertIn("verify_network_incident_redrive_prerequisites.py", self.workflow)
        self.assertIn("NETWORK_INCIDENT_REDRIVE_OIDC_SUBJECT", self.workflow)
        self.assertIn("redrive-preflight-receipt.json", self.workflow)
        self.assertIn(
            '--authorization-id "$GITHUB_RUN_ID:$GITHUB_RUN_ATTEMPT"', self.workflow
        )
        self.assertIn(
            '--preflight-receipt "$RUNNER_TEMP/redrive-preflight-receipt.json"',
            self.workflow,
        )

    def test_uses_only_short_lived_oidc_credentials(self) -> None:
        self.assertIn("permissions: {}", self.workflow)
        self.assertIn("contents: read", self.workflow)
        self.assertIn("id-token: write", self.workflow)
        self.assertIn("role-duration-seconds: 900", self.workflow)
        self.assertIn("allowed-account-ids: ${{ vars.AWS_ACCOUNT_ID }}", self.workflow)
        self.assertNotIn("aws-access-key-id", self.workflow)
        self.assertNotIn("aws-secret-access-key", self.workflow)
        self.assertNotIn("secrets.", self.workflow)

    def test_pins_every_third_party_action_to_a_commit(self) -> None:
        uses = re.findall(r"^\s*uses:\s*([^\s#]+)", self.workflow, flags=re.MULTILINE)

        self.assertEqual(len(uses), 4)
        for action in uses:
            self.assertRegex(action, r"^[^@]+@[0-9a-f]{40}$")

    def test_bounds_execution_and_archives_failed_receipts(self) -> None:
        self.assertIn("timeout-minutes: 10", self.workflow)
        self.assertIn("--call-timeout-seconds 30", self.workflow)
        self.assertIn("--dlq-receive-attempts 5", self.workflow)
        self.assertIn("--wait-seconds 5", self.workflow)
        self.assertIn("steps.redrive-canary.outcome == 'failure'", self.workflow)
        self.assertIn("steps.redrive-preflight.outcome == 'failure'", self.workflow)
        self.assertIn("retention-days: 30", self.workflow)


if __name__ == "__main__":
    unittest.main()
