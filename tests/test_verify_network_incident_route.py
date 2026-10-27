from __future__ import annotations

import copy
import json
import subprocess
import unittest
from typing import Any
from unittest.mock import patch

from scripts.verify_network_incident_route import AwsCli, Route, verify


ACCOUNT = "123456789012"
REGION = "eu-central-1"
TOPIC_ARN = f"arn:aws:sns:{REGION}:{ACCOUNT}:ml-platform-network-incidents"
QUEUE_ARN = f"arn:aws:sqs:{REGION}:{ACCOUNT}:ml-platform-network-incidents-consumer"
DLQ_ARN = f"arn:aws:sqs:{REGION}:{ACCOUNT}:ml-platform-network-incidents-consumer-dlq"
QUEUE_URL = f"https://sqs.{REGION}.amazonaws.com/{ACCOUNT}/ml-platform-network-incidents-consumer"
DLQ_URL = f"https://sqs.{REGION}.amazonaws.com/{ACCOUNT}/ml-platform-network-incidents-consumer-dlq"
SUBSCRIPTION_ARN = f"arn:aws:sns:{REGION}:{ACCOUNT}:ml-platform-network-incidents:subscription-id"


def route_document() -> dict[str, Any]:
    return {
        "topic_arn": TOPIC_ARN,
        "queue_arn": QUEUE_ARN,
        "dead_letter_queue_arn": DLQ_ARN,
        "queue_health_alarms": [
            "ml-platform-network-incidents-consumer-age",
            "ml-platform-network-incidents-consumer-dlq",
        ],
    }


def topic_policy(route: Route) -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "cloudwatch.amazonaws.com"},
                    "Action": "SNS:Publish",
                    "Resource": route.topic_arn,
                    "Condition": {
                        "StringEquals": {"aws:SourceAccount": route.account_id},
                        "ArnEquals": {"aws:SourceArn": sorted(route.expected_alarm_arns)},
                    },
                }
            ],
        }
    )


def queue_policy(route: Route, resource_arn: str = QUEUE_ARN) -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "sns.amazonaws.com"},
                    "Action": "sqs:SendMessage",
                    "Resource": resource_arn,
                    "Condition": {
                        "StringEquals": {"aws:SourceAccount": route.account_id},
                        "ArnEquals": {"aws:SourceArn": route.topic_arn},
                    },
                }
            ],
        }
    )


class FakeAws:
    def __init__(self, route: Route) -> None:
        self.calls: list[tuple[str, str, dict[str, str | list[str]]]] = []
        self.responses: dict[str, dict[str, Any]] = {
            "topic": {
                "Attributes": {
                    "KmsMasterKeyId": f"arn:aws:kms:{REGION}:{ACCOUNT}:key/topic-key",
                    "Policy": topic_policy(route),
                }
            },
            "queue-url": {"QueueUrl": QUEUE_URL},
            "dlq-url": {"QueueUrl": DLQ_URL},
            "queue": {
                "Attributes": {
                    "QueueArn": QUEUE_ARN,
                    "KmsMasterKeyId": f"arn:aws:kms:{REGION}:{ACCOUNT}:key/topic-key",
                    "Policy": queue_policy(route),
                    "RedrivePolicy": json.dumps(
                        {"deadLetterTargetArn": DLQ_ARN, "maxReceiveCount": "5"}
                    ),
                }
            },
            "dlq": {
                "Attributes": {
                    "QueueArn": DLQ_ARN,
                    "KmsMasterKeyId": f"arn:aws:kms:{REGION}:{ACCOUNT}:key/topic-key",
                    "Policy": queue_policy(route, DLQ_ARN),
                    "RedriveAllowPolicy": json.dumps(
                        {"redrivePermission": "byQueue", "sourceQueueArns": [QUEUE_ARN]}
                    ),
                }
            },
            "subscriptions": {
                "Subscriptions": [
                    {
                        "Protocol": "sqs",
                        "Endpoint": QUEUE_ARN,
                        "SubscriptionArn": SUBSCRIPTION_ARN,
                    }
                ]
            },
            "subscription": {
                "Attributes": {
                    "RawMessageDelivery": "false",
                    "RedrivePolicy": json.dumps({"deadLetterTargetArn": DLQ_ARN}),
                    "FilterPolicyScope": "MessageAttributes",
                    "FilterPolicy": json.dumps(
                        {
                            "route_canary": [
                                {"anything-but": "true"},
                                {"exists": False},
                            ]
                        }
                    ),
                }
            },
        }

    def call(self, service: str, operation: str, **parameters: str | list[str]) -> dict[str, Any]:
        self.calls.append((service, operation, parameters))
        if (service, operation) == ("sns", "get-topic-attributes"):
            return copy.deepcopy(self.responses["topic"])
        if (service, operation) == ("sqs", "get-queue-url"):
            key = "dlq-url" if parameters["queue_name"].endswith("-dlq") else "queue-url"
            return copy.deepcopy(self.responses[key])
        if (service, operation) == ("sqs", "get-queue-attributes"):
            key = "dlq" if parameters["queue_url"] == DLQ_URL else "queue"
            return copy.deepcopy(self.responses[key])
        if (service, operation) == ("sns", "list-subscriptions-by-topic"):
            return copy.deepcopy(self.responses["subscriptions"])
        if (service, operation) == ("sns", "get-subscription-attributes"):
            return copy.deepcopy(self.responses["subscription"])
        raise AssertionError(f"unexpected AWS call: {service} {operation} {parameters}")


class RouteTests(unittest.TestCase):
    def test_accepts_direct_terraform_output(self) -> None:
        route = Route.from_document(route_document())

        self.assertEqual(route.account_id, ACCOUNT)
        self.assertEqual(route.region, REGION)
        self.assertEqual(len(route.expected_alarm_arns), 4)

    def test_accepts_wrapped_terraform_output(self) -> None:
        route = Route.from_document({"value": route_document(), "type": ["object"]})

        self.assertEqual(route.queue_arn, QUEUE_ARN)

    def test_rejects_cross_account_queue(self) -> None:
        document = route_document()
        document["queue_arn"] = document["queue_arn"].replace(ACCOUNT, "210987654321")

        with self.assertRaisesRegex(ValueError, "share partition, Region and account"):
            Route.from_document(document)

    def test_rejects_disabled_queue_output(self) -> None:
        document = route_document()
        document["queue_arn"] = None

        with self.assertRaisesRegex(ValueError, "enable the managed queue"):
            Route.from_document(document)


class AwsCliTests(unittest.TestCase):
    @patch("scripts.verify_network_incident_route.subprocess.run")
    def test_builds_bounded_json_command(self, run: Any) -> None:
        run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout='{"Attributes": {}}', stderr=""
        )

        response = AwsCli(executable="aws-test", timeout_seconds=7).call(
            "sqs",
            "get-queue-attributes",
            queue_url=QUEUE_URL,
            attribute_names=["QueueArn", "Policy"],
            region=REGION,
        )

        self.assertEqual(response, {"Attributes": {}})
        command = run.call_args.args[0]
        self.assertEqual(command[:3], ["aws-test", "sqs", "get-queue-attributes"])
        self.assertIn("--no-cli-pager", command)
        self.assertEqual(run.call_args.kwargs["timeout"], 7)


class VerifyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.route = Route.from_document(route_document())
        self.aws = FakeAws(self.route)

    def test_passes_complete_live_route_contract(self) -> None:
        result = verify(self.route, self.aws)

        self.assertEqual(result["status"], "pass")
        self.assertTrue(all(check["passed"] for check in result["checks"]))
        self.assertEqual(len(result["checks"]), 14)

    def test_rejects_wildcard_cloudwatch_source(self) -> None:
        policy = json.loads(self.aws.responses["topic"]["Attributes"]["Policy"])
        policy["Statement"][0]["Condition"]["ArnEquals"]["aws:SourceArn"] = "*"
        self.aws.responses["topic"]["Attributes"]["Policy"] = json.dumps(policy)

        result = verify(self.route, self.aws)

        failed = {check["name"] for check in result["checks"] if not check["passed"]}
        self.assertEqual(result["status"], "fail")
        self.assertEqual(failed, {"cloudwatch-publish-policy"})

    def test_rejects_shadow_wildcard_cloudwatch_grant(self) -> None:
        policy = json.loads(self.aws.responses["topic"]["Attributes"]["Policy"])
        policy["Statement"].append(
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "SNS:*",
                "Resource": TOPIC_ARN,
            }
        )
        self.aws.responses["topic"]["Attributes"]["Policy"] = json.dumps(policy)

        result = verify(self.route, self.aws)

        failed = {check["name"] for check in result["checks"] if not check["passed"]}
        self.assertEqual(failed, {"cloudwatch-publish-policy"})

    def test_rejects_topic_policy_for_another_account(self) -> None:
        policy = json.loads(self.aws.responses["queue"]["Attributes"]["Policy"])
        policy["Statement"][0]["Condition"]["StringEquals"]["aws:SourceAccount"] = "210987654321"
        self.aws.responses["queue"]["Attributes"]["Policy"] = json.dumps(policy)

        result = verify(self.route, self.aws)

        failed = {check["name"] for check in result["checks"] if not check["passed"]}
        self.assertEqual(failed, {"topic-to-queue-policy"})

    def test_rejects_unconfirmed_subscription_without_reading_its_attributes(self) -> None:
        self.aws.responses["subscriptions"]["Subscriptions"][0][
            "SubscriptionArn"
        ] = "PendingConfirmation"

        result = verify(self.route, self.aws)

        failed = {check["name"] for check in result["checks"] if not check["passed"]}
        self.assertEqual(failed, {"confirmed-subscription"})
        operations = [(service, operation) for service, operation, _ in self.aws.calls]
        self.assertNotIn(("sns", "get-subscription-attributes"), operations)

    def test_rejects_unbounded_consumer_redrive(self) -> None:
        self.aws.responses["queue"]["Attributes"]["RedrivePolicy"] = json.dumps(
            {"deadLetterTargetArn": DLQ_ARN, "maxReceiveCount": "0"}
        )

        result = verify(self.route, self.aws)

        failed = {check["name"] for check in result["checks"] if not check["passed"]}
        self.assertEqual(failed, {"consumer-redrive-policy"})

    def test_rejects_different_route_encryption_keys(self) -> None:
        self.aws.responses["dlq"]["Attributes"]["KmsMasterKeyId"] = (
            f"arn:aws:kms:{REGION}:{ACCOUNT}:key/other-key"
        )

        result = verify(self.route, self.aws)

        failed = {check["name"] for check in result["checks"] if not check["passed"]}
        self.assertEqual(failed, {"shared-encryption-boundary"})

    def test_rejects_missing_dead_letter_delivery_grant(self) -> None:
        self.aws.responses["dlq"]["Attributes"]["Policy"] = "{}"

        result = verify(self.route, self.aws)

        failed = {check["name"] for check in result["checks"] if not check["passed"]}
        self.assertEqual(failed, {"topic-to-dead-letter-policy"})

    def test_rejects_raw_message_delivery(self) -> None:
        self.aws.responses["subscription"]["Attributes"]["RawMessageDelivery"] = "true"

        result = verify(self.route, self.aws)

        failed = {check["name"] for check in result["checks"] if not check["passed"]}
        self.assertEqual(failed, {"sns-envelope-retention"})

    def test_rejects_production_subscription_that_accepts_canaries(self) -> None:
        self.aws.responses["subscription"]["Attributes"]["FilterPolicy"] = json.dumps(
            {"route_canary": ["true"]}
        )

        result = verify(self.route, self.aws)

        failed = {check["name"] for check in result["checks"] if not check["passed"]}
        self.assertEqual(failed, {"delivery-canary-isolation"})


if __name__ == "__main__":
    unittest.main()
