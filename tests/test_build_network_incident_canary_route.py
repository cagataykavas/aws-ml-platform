from __future__ import annotations

import json
import stat
import tempfile
import unittest
from pathlib import Path

from scripts.build_network_incident_canary_route import (
    build_route_document,
    write_route_document,
)

ACCOUNT = "123456789012"
REGION = "eu-central-1"
TOPIC_ARN = f"arn:aws:sns:{REGION}:{ACCOUNT}:ml-platform-network-incidents"
QUEUE_ARN = f"arn:aws:sqs:{REGION}:{ACCOUNT}:ml-platform-network-incidents-consumer"
DLQ_ARN = f"arn:aws:sqs:{REGION}:{ACCOUNT}:ml-platform-network-incidents-consumer-dlq"
CANARY_ARN = f"arn:aws:sqs:{REGION}:{ACCOUNT}:ml-platform-network-incidents-canary"


def valid_arguments() -> dict[str, str]:
    return {
        "topic_arn": TOPIC_ARN,
        "queue_arn": QUEUE_ARN,
        "dead_letter_queue_arn": DLQ_ARN,
        "delivery_canary_queue_arn": CANARY_ARN,
        "expected_account_id": ACCOUNT,
        "expected_region": REGION,
    }


class BuildRouteDocumentTests(unittest.TestCase):
    def test_accepts_one_coherent_environment_route(self) -> None:
        document = build_route_document(**valid_arguments())

        self.assertEqual(document["topic_arn"], TOPIC_ARN)
        self.assertEqual(document["delivery_canary_queue_arn"], CANARY_ARN)

    def test_rejects_account_substitution(self) -> None:
        arguments = valid_arguments()
        arguments["expected_account_id"] = "999999999999"

        with self.assertRaisesRegex(ValueError, "expected AWS account"):
            build_route_document(**arguments)

    def test_rejects_region_substitution(self) -> None:
        arguments = valid_arguments()
        arguments["expected_region"] = "us-east-1"

        with self.assertRaisesRegex(ValueError, "expected AWS Region"):
            build_route_document(**arguments)

    def test_rejects_reused_incident_and_dead_letter_queue(self) -> None:
        arguments = valid_arguments()
        arguments["dead_letter_queue_arn"] = QUEUE_ARN

        with self.assertRaisesRegex(ValueError, "must be distinct"):
            build_route_document(**arguments)

    def test_rejects_cross_account_protected_queue(self) -> None:
        arguments = valid_arguments()
        arguments["queue_arn"] = QUEUE_ARN.replace(ACCOUNT, "999999999999")

        with self.assertRaisesRegex(ValueError, "share partition, Region and account"):
            build_route_document(**arguments)


class WriteRouteDocumentTests(unittest.TestCase):
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
