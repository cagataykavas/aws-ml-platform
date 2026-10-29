from __future__ import annotations

import copy
import unittest
from typing import Any

from scripts.run_network_incident_redrive_canary import RedriveRoute
from scripts.verify_network_incident_redrive_prerequisites import RoleBoundary, verify

ACCOUNT = "123456789012"
REGION = "eu-central-1"
PRODUCTION_ARN = (
    f"arn:aws:sqs:{REGION}:{ACCOUNT}:ml-platform-network-incidents-consumer"
)
FAULT_ARN = (
    f"arn:aws:sqs:{REGION}:{ACCOUNT}:ml-platform-network-incidents-fault-injection"
)
DLQ_ARN = f"{FAULT_ARN}-dlq"
ROLE_ARN = f"arn:aws:iam::{ACCOUNT}:role/network-incident-redrive-canary"
SUBJECT = "repo:cagataykavas/aws-ml-platform:environment:redrive-staging"


def route() -> RedriveRoute:
    return RedriveRoute.from_document(
        {
            "production_queue_arn": PRODUCTION_ARN,
            "fault_queue_arn": FAULT_ARN,
            "fault_dead_letter_queue_arn": DLQ_ARN,
        }
    )


def queue_policy(arn: str, actions: list[str]) -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "ExactCanaryRole",
                "Effect": "Allow",
                "Principal": {"AWS": ROLE_ARN},
                "Action": actions,
                "Resource": arn,
            },
            {
                "Sid": "DenyInsecureTransport",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "sqs:*",
                "Resource": arn,
                "Condition": {"Bool": {"aws:SecureTransport": "false"}},
            },
        ],
    }


def responses() -> dict[str, Any]:
    source_actions = [
        "sqs:ChangeMessageVisibility",
        "sqs:DeleteMessage",
        "sqs:GetQueueAttributes",
        "sqs:GetQueueUrl",
        "sqs:ReceiveMessage",
        "sqs:SendMessage",
    ]
    dlq_actions = [
        "sqs:DeleteMessage",
        "sqs:GetQueueAttributes",
        "sqs:GetQueueUrl",
        "sqs:ReceiveMessage",
    ]
    return {
        "caller": {
            "Account": ACCOUNT,
            "Arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/network-incident-redrive-canary/run-1",
        },
        "role": {
            "Role": {
                "AssumeRolePolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "GitHubEnvironmentOidc",
                            "Effect": "Allow",
                            "Principal": {
                                "Federated": f"arn:aws:iam::{ACCOUNT}:oidc-provider/token.actions.githubusercontent.com"
                            },
                            "Action": "sts:AssumeRoleWithWebIdentity",
                            "Condition": {
                                "StringEquals": {
                                    "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
                                    "token.actions.githubusercontent.com:sub": SUBJECT,
                                }
                            },
                        }
                    ],
                }
            }
        },
        "role_policy": {
            "PolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "ExerciseFaultSource",
                        "Effect": "Allow",
                        "Action": source_actions,
                        "Resource": FAULT_ARN,
                    },
                    {
                        "Sid": "VerifyFaultDeadLetters",
                        "Effect": "Allow",
                        "Action": dlq_actions,
                        "Resource": DLQ_ARN,
                    },
                    {
                        "Sid": "InspectCanaryBoundary",
                        "Effect": "Allow",
                        "Action": ["iam:GetRole", "iam:GetRolePolicy"],
                        "Resource": ROLE_ARN,
                    },
                ],
            }
        },
        "source": {
            "QueueArn": FAULT_ARN,
            "SqsManagedSseEnabled": "true",
            "MessageRetentionPeriod": "3600",
            "RedrivePolicy": {
                "deadLetterTargetArn": DLQ_ARN,
                "maxReceiveCount": "3",
            },
            "Policy": queue_policy(FAULT_ARN, source_actions),
        },
        "dlq": {
            "QueueArn": DLQ_ARN,
            "SqsManagedSseEnabled": "true",
            "MessageRetentionPeriod": "3600",
            "RedriveAllowPolicy": {
                "redrivePermission": "byQueue",
                "sourceQueueArns": [FAULT_ARN],
            },
            "Policy": queue_policy(DLQ_ARN, dlq_actions),
        },
    }


class FakeAws:
    def __init__(self, payloads: dict[str, Any]) -> None:
        self.payloads = payloads

    def call(self, service: str, operation: str, **parameters: Any) -> dict[str, Any]:
        if (service, operation) == ("sts", "get-caller-identity"):
            return self.payloads["caller"]
        if (service, operation) == ("iam", "get-role"):
            return self.payloads["role"]
        if (service, operation) == ("iam", "get-role-policy"):
            return self.payloads["role_policy"]
        if (service, operation) == ("sqs", "get-queue-url"):
            return {"QueueUrl": f"https://sqs.example/{parameters['queue_name']}"}
        if (service, operation) == ("sqs", "get-queue-attributes"):
            key = "dlq" if str(parameters["queue_url"]).endswith("-dlq") else "source"
            return {"Attributes": self.payloads[key]}
        raise AssertionError(f"unexpected AWS call: {service} {operation}")


class RedrivePrerequisiteVerifierTests(unittest.TestCase):
    def run_verify(self, payloads: dict[str, Any]) -> dict[str, Any]:
        active_route = route()
        role = RoleBoundary.parse(ROLE_ARN, active_route)
        return verify(active_route, role, SUBJECT, FakeAws(payloads))

    def test_accepts_exact_live_terraform_contract(self) -> None:
        result = self.run_verify(responses())

        self.assertEqual(result["status"], "pass")
        self.assertEqual(len(result["route_sha256"]), 64)
        self.assertTrue(all(item["passed"] for item in result["checks"]))

    def test_rejects_broadened_oidc_trust(self) -> None:
        payloads = responses()
        trust = payloads["role"]["Role"]["AssumeRolePolicyDocument"]
        trust["Statement"][0]["Condition"]["StringEquals"][
            "token.actions.githubusercontent.com:sub"
        ] = "repo:cagataykavas/aws-ml-platform:*"

        result = self.run_verify(payloads)

        self.assertEqual(result["status"], "fail")
        self.assertFalse(
            next(item for item in result["checks"] if item["name"] == "oidc-trust")[
                "passed"
            ]
        )

    def test_rejects_broadened_inline_policy(self) -> None:
        payloads = responses()
        payloads["role_policy"]["PolicyDocument"]["Statement"][0]["Action"].append(
            "sqs:*"
        )

        result = self.run_verify(payloads)

        self.assertEqual(result["status"], "fail")
        self.assertFalse(
            next(
                item
                for item in result["checks"]
                if item["name"] == "least-privilege-role-policy"
            )["passed"]
        )

    def test_rejects_queue_policy_and_redrive_drift(self) -> None:
        payloads = responses()
        payloads["source"]["RedrivePolicy"]["maxReceiveCount"] = "9"
        payloads["dlq"]["Policy"]["Statement"][0]["Principal"] = "*"

        result = self.run_verify(payloads)

        failed = {item["name"] for item in result["checks"] if not item["passed"]}
        self.assertEqual(result["status"], "fail")
        self.assertEqual(failed, {"source-redrive-policy", "queue-resource-policies"})

    def test_rejects_wrong_active_caller(self) -> None:
        payloads = responses()
        payloads["caller"]["Arn"] = (
            f"arn:aws:sts::{ACCOUNT}:assumed-role/another-role/run-1"
        )

        result = self.run_verify(payloads)

        self.assertEqual(result["status"], "fail")
        self.assertFalse(
            next(
                item for item in result["checks"] if item["name"] == "caller-identity"
            )["passed"]
        )

    def test_rejects_unbound_subject_before_live_calls(self) -> None:
        active_route = route()
        role = RoleBoundary.parse(ROLE_ARN, active_route)
        with self.assertRaisesRegex(ValueError, "bind one repository Environment"):
            verify(
                active_route,
                role,
                "repo:owner/repo:ref:main",
                FakeAws(copy.deepcopy(responses())),
            )


if __name__ == "__main__":
    unittest.main()
