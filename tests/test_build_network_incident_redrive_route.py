from __future__ import annotations

import json
import stat
import tempfile
import unittest
from pathlib import Path

from scripts.build_network_incident_redrive_route import (
    build_route_document,
    write_route_document,
)

ACCOUNT = "123456789012"
REGION = "eu-central-1"
PRODUCTION_ARN = f"arn:aws:sqs:{REGION}:{ACCOUNT}:ml-platform-network-incidents-consumer"
FAULT_ARN = f"arn:aws:sqs:{REGION}:{ACCOUNT}:ml-platform-network-incidents-fault-injection"
DLQ_ARN = f"{FAULT_ARN}-dlq"
ROLE_ARN = f"arn:aws:iam::{ACCOUNT}:role/network-incident-redrive-canary"


def valid_arguments() -> dict[str, str]:
    return {
        "production_queue_arn": PRODUCTION_ARN,
        "fault_queue_arn": FAULT_ARN,
        "fault_dead_letter_queue_arn": DLQ_ARN,
        "redrive_canary_role_arn": ROLE_ARN,
        "expected_account_id": ACCOUNT,
        "expected_region": REGION,
    }


class BuildRedriveRouteTests(unittest.TestCase):
    def test_accepts_dedicated_route_in_expected_boundary(self) -> None:
        document = build_route_document(**valid_arguments())

        self.assertEqual(document["production_queue_arn"], PRODUCTION_ARN)
        self.assertEqual(document["fault_queue_arn"], FAULT_ARN)
        self.assertEqual(document["fault_dead_letter_queue_arn"], DLQ_ARN)

    def test_rejects_account_substitution_before_credentials(self) -> None:
        arguments = valid_arguments()
        arguments["expected_account_id"] = "999999999999"

        with self.assertRaisesRegex(ValueError, "expected AWS account"):
            build_route_document(**arguments)

    def test_rejects_region_substitution_before_credentials(self) -> None:
        arguments = valid_arguments()
        arguments["expected_region"] = "us-east-1"

        with self.assertRaisesRegex(ValueError, "expected AWS Region"):
            build_route_document(**arguments)

    def test_rejects_production_queue_reuse(self) -> None:
        arguments = valid_arguments()
        arguments["fault_queue_arn"] = PRODUCTION_ARN

        with self.assertRaisesRegex(ValueError, "must be distinct"):
            build_route_document(**arguments)

    def test_rejects_unrelated_dead_letter_queue(self) -> None:
        arguments = valid_arguments()
        arguments["fault_dead_letter_queue_arn"] = DLQ_ARN.replace("-dlq", "-other-dlq")

        with self.assertRaisesRegex(ValueError, "dedicated fault queue -dlq"):
            build_route_document(**arguments)

    def test_rejects_role_from_another_account(self) -> None:
        arguments = valid_arguments()
        arguments["redrive_canary_role_arn"] = ROLE_ARN.replace(ACCOUNT, "999999999999")

        with self.assertRaisesRegex(ValueError, "share the route partition and account"):
            build_route_document(**arguments)


class WriteRedriveRouteTests(unittest.TestCase):
    def test_writes_deterministic_private_json(self) -> None:
        document = build_route_document(**valid_arguments())
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "nested" / "route.json"

            write_route_document(document, output)

            self.assertEqual(json.loads(output.read_text(encoding="utf-8")), document)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            self.assertTrue(output.read_text(encoding="utf-8").endswith("\n"))


if __name__ == "__main__":
    unittest.main()
