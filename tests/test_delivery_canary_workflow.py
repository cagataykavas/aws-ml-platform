from __future__ import annotations

import re
import unittest
from pathlib import Path

WORKFLOW = Path(".github/workflows/incident-delivery-canary.yml")


class DeliveryCanaryWorkflowContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")

    def test_requires_a_github_environment_and_serializes_each_environment(
        self,
    ) -> None:
        self.assertIn("type: environment", self.workflow)
        self.assertIn("environment: ${{ inputs.environment }}", self.workflow)
        self.assertIn(
            "group: incident-delivery-canary-${{ inputs.environment }}", self.workflow
        )
        self.assertIn("cancel-in-progress: false", self.workflow)

    def test_uses_only_oidc_short_lived_credentials(self) -> None:
        self.assertIn("id-token: write", self.workflow)
        self.assertIn("contents: read", self.workflow)
        self.assertIn("permissions: {}", self.workflow)
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

    def test_bounds_execution_and_archives_receipt_even_on_canary_failure(self) -> None:
        self.assertIn("timeout-minutes: 8", self.workflow)
        self.assertIn("--receive-attempts 3", self.workflow)
        self.assertIn("--wait-seconds 10", self.workflow)
        self.assertIn("steps.delivery-canary.outcome == 'failure'", self.workflow)
        self.assertIn("retention-days: 30", self.workflow)
        self.assertIn("if-no-files-found: error", self.workflow)


if __name__ == "__main__":
    unittest.main()
