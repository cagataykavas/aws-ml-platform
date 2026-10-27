from __future__ import annotations

import json
import unittest
from typing import Any

from scripts.run_network_incident_delivery_canary import (
    CANARY_KIND,
    CanaryRoute,
    run_canary,
)


ACCOUNT = "123456789012"
REGION = "eu-central-1"
TOPIC_ARN = f"arn:aws:sns:{REGION}:{ACCOUNT}:ml-platform-network-incidents"
QUEUE_ARN = f"arn:aws:sqs:{REGION}:{ACCOUNT}:ml-platform-network-incidents-consumer"
DLQ_ARN = f"arn:aws:sqs:{REGION}:{ACCOUNT}:ml-platform-network-incidents-consumer-dlq"
CANARY_ARN = f"arn:aws:sqs:{REGION}:{ACCOUNT}:ml-platform-network-incidents-canary"
CANARY_URL = f"https://sqs.{REGION}.amazonaws.com/{ACCOUNT}/ml-platform-network-incidents-canary"
RUN_ID = "canary-run-1"
SENT_AT = "2026-10-27T05:00:00+00:00"


def route_document() -> dict[str, Any]:
    return {
        "topic_arn": TOPIC_ARN,
        "queue_arn": QUEUE_ARN,
        "dead_letter_queue_arn": DLQ_ARN,
        "delivery_canary_queue_arn": CANARY_ARN,
    }


def delivery(run_id: str = RUN_ID, *, topic_arn: str = TOPIC_ARN) -> dict[str, str]:
    payload = {
        "kind": CANARY_KIND,
        "run_id": run_id,
        "schema_version": 1,
        "sent_at": SENT_AT,
    }
    body = {
        "Type": "Notification",
        "TopicArn": topic_arn,
        "Message": json.dumps(payload, separators=(",", ":"), sort_keys=True),
        "MessageAttributes": {"route_canary": {"Type": "String", "Value": "true"}},
    }
    return {
        "Body": json.dumps(body),
        "ReceiptHandle": f"receipt-{run_id}",
        "MessageId": f"sqs-{run_id}",
    }


class FakeAws:
    def __init__(self, receives: list[dict[str, Any]]) -> None:
        self.receives = list(receives)
        self.calls: list[tuple[str, str, dict[str, str | list[str]]]] = []

    def call(self, service: str, operation: str, **parameters: str | list[str]) -> dict[str, Any]:
        self.calls.append((service, operation, parameters))
        if (service, operation) == ("sqs", "get-queue-url"):
            return {"QueueUrl": CANARY_URL}
        if (service, operation) == ("sns", "publish"):
            return {"MessageId": "sns-canary-1"}
        if (service, operation) == ("sqs", "receive-message"):
            return self.receives.pop(0) if self.receives else {}
        if (service, operation) == ("sqs", "delete-message"):
            return {}
        raise AssertionError(f"unexpected call: {service} {operation}")


class CanaryRouteTests(unittest.TestCase):
    def test_accepts_wrapped_terraform_output(self) -> None:
        route = CanaryRoute.from_document({"value": route_document(), "type": ["object"]})

        self.assertEqual(route.queue_arn, CANARY_ARN)
        self.assertEqual(route.region, REGION)

    def test_rejects_production_queue_reuse(self) -> None:
        document = route_document()
        document["delivery_canary_queue_arn"] = QUEUE_ARN.replace("-consumer", "-canary")
        document["queue_arn"] = document["delivery_canary_queue_arn"]

        with self.assertRaisesRegex(ValueError, "must differ"):
            CanaryRoute.from_document(document)

    def test_rejects_non_canary_queue_name(self) -> None:
        document = route_document()
        document["delivery_canary_queue_arn"] = QUEUE_ARN

        with self.assertRaisesRegex(ValueError, "dedicated -canary"):
            CanaryRoute.from_document(document)

    def test_rejects_cross_region_queue(self) -> None:
        document = route_document()
        document["delivery_canary_queue_arn"] = CANARY_ARN.replace(REGION, "us-east-1")

        with self.assertRaisesRegex(ValueError, "share partition, Region and account"):
            CanaryRoute.from_document(document)


class RunCanaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.route = CanaryRoute.from_document(route_document())

    def test_publishes_verifies_and_deletes_only_matching_delivery(self) -> None:
        aws = FakeAws([{"Messages": [delivery("old-run"), delivery()]}])

        result = run_canary(
            self.route,
            aws,
            run_id=RUN_ID,
            sent_at=SENT_AT,
            max_attempts=2,
            wait_seconds=4,
        )

        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["observed"]["ignored_messages"], 1)
        self.assertEqual(result["observed"]["receive_attempt"], 1)
        publish = next(call for call in aws.calls if call[:2] == ("sns", "publish"))
        self.assertEqual(publish[2]["topic_arn"], TOPIC_ARN)
        self.assertIn('"route_canary"', publish[2]["message_attributes"])
        deletes = [call for call in aws.calls if call[:2] == ("sqs", "delete-message")]
        self.assertEqual(len(deletes), 1)
        self.assertEqual(deletes[0][2]["receipt_handle"], f"receipt-{RUN_ID}")

    def test_never_deletes_unrelated_delivery_on_timeout(self) -> None:
        aws = FakeAws([{"Messages": [delivery("another-run")]}, {}])

        with self.assertRaisesRegex(RuntimeError, "not observed"):
            run_canary(
                self.route,
                aws,
                run_id=RUN_ID,
                sent_at=SENT_AT,
                max_attempts=2,
                wait_seconds=1,
            )

        self.assertFalse(any(call[:2] == ("sqs", "delete-message") for call in aws.calls))

    def test_rejects_matching_payload_from_wrong_topic_without_deleting(self) -> None:
        aws = FakeAws([{"Messages": [delivery(topic_arn="arn:aws:sns:eu-central-1:123456789012:other")] }])

        with self.assertRaisesRegex(RuntimeError, "invalid SNS envelope"):
            run_canary(self.route, aws, run_id=RUN_ID, sent_at=SENT_AT)

        self.assertFalse(any(call[:2] == ("sqs", "delete-message") for call in aws.calls))

    def test_rejects_unbounded_poll_configuration_before_aws_calls(self) -> None:
        aws = FakeAws([])

        with self.assertRaisesRegex(ValueError, "max_attempts"):
            run_canary(
                self.route,
                aws,
                run_id=RUN_ID,
                sent_at=SENT_AT,
                max_attempts=11,
            )

        self.assertEqual(aws.calls, [])


if __name__ == "__main__":
    unittest.main()
