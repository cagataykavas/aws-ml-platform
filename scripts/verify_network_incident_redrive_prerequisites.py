#!/usr/bin/env python3
"""Read-only live preflight for the isolated SQS redrive drill."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    from scripts.run_network_incident_redrive_canary import RedriveRoute
    from scripts.verify_network_incident_route import (
        AwsCli,
        AwsClient,
        _json_object,
        _statements,
    )
except ModuleNotFoundError:  # Direct execution from the scripts directory.
    from run_network_incident_redrive_canary import RedriveRoute
    from verify_network_incident_route import (
        AwsCli,
        AwsClient,
        _json_object,
        _statements,
    )


SOURCE_ACTIONS = frozenset(
    {
        "sqs:changemessagevisibility",
        "sqs:deletemessage",
        "sqs:getqueueattributes",
        "sqs:getqueueurl",
        "sqs:receivemessage",
        "sqs:sendmessage",
    }
)
DLQ_ACTIONS = frozenset(
    {
        "sqs:deletemessage",
        "sqs:getqueueattributes",
        "sqs:getqueueurl",
        "sqs:receivemessage",
    }
)
SELF_INSPECTION_ACTIONS = frozenset({"iam:getrole", "iam:getrolepolicy"})
POLICY_NAME = "network-incident-redrive-canary"
SUBJECT_PATTERN = re.compile(r"repo:[^/\s:]+/[^\s:]+:environment:[^\s]+")
AUTHORIZATION_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")


@dataclass(frozen=True)
class RoleBoundary:
    arn: str
    name: str
    partition: str
    account_id: str

    @classmethod
    def parse(cls, arn: str, route: RedriveRoute) -> RoleBoundary:
        parts = arn.split(":", 5)
        if len(parts) != 6 or parts[:3] != ["arn", route.partition, "iam"]:
            raise ValueError(
                "redrive canary role must be an IAM ARN in the route partition"
            )
        if parts[3] or parts[4] != route.account_id or not parts[5].startswith("role/"):
            raise ValueError("redrive canary role must belong to the route account")
        name = parts[5].removeprefix("role/")
        if not name or "/" in name:
            raise ValueError(
                "redrive canary role must use the expected pathless role name"
            )
        return cls(
            arn=arn, name=name, partition=route.partition, account_id=route.account_id
        )


@dataclass
class Check:
    name: str
    passed: bool
    detail: str


def verify(
    route: RedriveRoute,
    role: RoleBoundary,
    expected_oidc_subject: str,
    aws: AwsClient,
    *,
    authorization_id: str,
) -> dict[str, Any]:
    if SUBJECT_PATTERN.fullmatch(expected_oidc_subject) is None:
        raise ValueError("expected OIDC subject must bind one repository Environment")
    if AUTHORIZATION_ID_PATTERN.fullmatch(authorization_id) is None:
        raise ValueError("authorization_id must be a stable 1-128 character identifier")
    checks: list[Check] = []

    def check(name: str, condition: bool, success: str, failure: str) -> None:
        checks.append(Check(name, condition, success if condition else failure))

    caller = aws.call("sts", "get-caller-identity")
    caller_arn = caller.get("Arn", "")
    expected_assumed_prefix = (
        f"arn:{route.partition}:sts::{route.account_id}:assumed-role/{role.name}/"
    )
    check(
        "caller-identity",
        caller.get("Account") == route.account_id
        and isinstance(caller_arn, str)
        and caller_arn.startswith(expected_assumed_prefix),
        "current credentials are the expected account-local canary role",
        "current credentials are not the expected account-local canary role",
    )

    role_payload = aws.call("iam", "get-role", role_name=role.name).get("Role", {})
    trust = _json_object(role_payload.get("AssumeRolePolicyDocument"))
    expected_provider = (
        f"arn:{route.partition}:iam::{route.account_id}:"
        "oidc-provider/token.actions.githubusercontent.com"
    )
    check(
        "oidc-trust",
        _exact_oidc_trust(trust, expected_provider, expected_oidc_subject),
        "role trust binds the exact GitHub provider, audience and Environment subject",
        "role trust differs from the exact GitHub OIDC boundary",
    )

    policy = _json_object(
        aws.call(
            "iam",
            "get-role-policy",
            role_name=role.name,
            policy_name=POLICY_NAME,
        ).get("PolicyDocument")
    )
    check(
        "least-privilege-role-policy",
        _exact_role_policy(policy, route, role),
        "inline role policy contains only the two drill routes and self-inspection",
        "inline role policy is broader than or differs from the reviewed contract",
    )

    source_attributes = _queue_attributes(aws, route.fault_queue_arn, route)
    dlq_attributes = _queue_attributes(aws, route.fault_dead_letter_queue_arn, route)
    check(
        "queue-identities",
        source_attributes.get("QueueArn") == route.fault_queue_arn
        and dlq_attributes.get("QueueArn") == route.fault_dead_letter_queue_arn,
        "queue URLs resolve to the reviewed fault source and DLQ",
        "a queue URL resolves to an unexpected ARN",
    )
    check(
        "queue-encryption",
        source_attributes.get("SqsManagedSseEnabled", "").lower() == "true"
        and dlq_attributes.get("SqsManagedSseEnabled", "").lower() == "true",
        "both drill queues use SQS-managed encryption",
        "a drill queue is not SQS-managed encrypted",
    )
    check(
        "queue-retention",
        _integer_between(source_attributes.get("MessageRetentionPeriod"), 900, 86_400)
        and _integer_between(dlq_attributes.get("MessageRetentionPeriod"), 900, 86_400),
        "both drill queues have bounded non-production retention",
        "a drill queue has an invalid retention period",
    )
    redrive = _json_object(source_attributes.get("RedrivePolicy"))
    check(
        "source-redrive-policy",
        redrive.get("deadLetterTargetArn") == route.fault_dead_letter_queue_arn
        and _integer_between(redrive.get("maxReceiveCount"), 2, 5),
        "fault source has the exact DLQ and bounded receive threshold",
        "fault source redrive policy differs from the reviewed contract",
    )
    redrive_allow = _json_object(dlq_attributes.get("RedriveAllowPolicy"))
    check(
        "dead-letter-source-policy",
        redrive_allow.get("redrivePermission") == "byQueue"
        and redrive_allow.get("sourceQueueArns") == [route.fault_queue_arn],
        "DLQ accepts redrive only from the fault source",
        "DLQ redrive admission differs from the reviewed contract",
    )
    check(
        "queue-resource-policies",
        _exact_queue_policy(
            _json_object(source_attributes.get("Policy")),
            route.fault_queue_arn,
            role.arn,
            SOURCE_ACTIONS,
        )
        and _exact_queue_policy(
            _json_object(dlq_attributes.get("Policy")),
            route.fault_dead_letter_queue_arn,
            role.arn,
            DLQ_ACTIONS,
        ),
        "queue policies grant only the canary role and deny insecure transport",
        "a queue resource policy differs from the reviewed contract",
    )

    route_digest = hashlib.sha256(
        json.dumps(
            {
                "fault_dead_letter_queue_arn": route.fault_dead_letter_queue_arn,
                "fault_queue_arn": route.fault_queue_arn,
                "production_queue_arn": route.production_queue_arn,
                "role_arn": role.arn,
                "subject": expected_oidc_subject,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()
    return {
        "status": "pass" if all(item.passed for item in checks) else "fail",
        "schema_version": 1,
        "authorization_id": authorization_id,
        "queue_route_sha256": route.digest(),
        "route_sha256": route_digest,
        "checks": [item.__dict__ for item in checks],
    }


def _exact_oidc_trust(policy: dict[str, Any], provider: str, subject: str) -> bool:
    statements = _statements(policy)
    if len(statements) != 1:
        return False
    statement = statements[0]
    condition = statement.get("Condition", {})
    equals = condition.get("StringEquals", {}) if isinstance(condition, dict) else {}
    return (
        statement.get("Effect") == "Allow"
        and statement.get("Action") == "sts:AssumeRoleWithWebIdentity"
        and statement.get("Principal") == {"Federated": provider}
        and equals
        == {
            "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
            "token.actions.githubusercontent.com:sub": subject,
        }
    )


def _exact_role_policy(
    policy: dict[str, Any], route: RedriveRoute, role: RoleBoundary
) -> bool:
    expected = {
        "ExerciseFaultSource": (SOURCE_ACTIONS, route.fault_queue_arn),
        "VerifyFaultDeadLetters": (DLQ_ACTIONS, route.fault_dead_letter_queue_arn),
        "InspectCanaryBoundary": (SELF_INSPECTION_ACTIONS, role.arn),
    }
    statements = _statements(policy)
    if len(statements) != len(expected):
        return False
    by_sid = {statement.get("Sid"): statement for statement in statements}
    if set(by_sid) != set(expected):
        return False
    return all(
        statement.get("Effect") == "Allow"
        and _actions(statement.get("Action")) == actions
        and statement.get("Resource") == resource
        for sid, (actions, resource) in expected.items()
        for statement in [by_sid[sid]]
    ) and route.production_queue_arn not in json.dumps(policy, sort_keys=True)


def _exact_queue_policy(
    policy: dict[str, Any],
    queue_arn: str,
    role_arn: str,
    expected_actions: frozenset[str],
) -> bool:
    statements = _statements(policy)
    if len(statements) != 2:
        return False
    by_sid = {statement.get("Sid"): statement for statement in statements}
    allow = by_sid.get("ExactCanaryRole", {})
    deny = by_sid.get("DenyInsecureTransport", {})
    return (
        allow.get("Effect") == "Allow"
        and allow.get("Principal") == {"AWS": role_arn}
        and _actions(allow.get("Action")) == expected_actions
        and allow.get("Resource") == queue_arn
        and deny.get("Effect") == "Deny"
        and deny.get("Principal") == "*"
        and deny.get("Action") == "sqs:*"
        and deny.get("Resource") == queue_arn
        and deny.get("Condition") == {"Bool": {"aws:SecureTransport": "false"}}
    )


def _queue_attributes(aws: AwsClient, arn: str, route: RedriveRoute) -> dict[str, Any]:
    queue_url = aws.call(
        "sqs",
        "get-queue-url",
        queue_name=arn.rsplit(":", 1)[1],
        queue_owner_aws_account_id=route.account_id,
        region=route.region,
    ).get("QueueUrl")
    if not isinstance(queue_url, str) or not queue_url:
        raise RuntimeError("AWS CLI returned no QueueUrl for a drill queue")
    attributes = aws.call(
        "sqs",
        "get-queue-attributes",
        queue_url=queue_url,
        attribute_names=[
            "QueueArn",
            "Policy",
            "RedrivePolicy",
            "RedriveAllowPolicy",
            "SqsManagedSseEnabled",
            "MessageRetentionPeriod",
        ],
        region=route.region,
    ).get("Attributes")
    if not isinstance(attributes, dict):
        raise RuntimeError("AWS CLI returned invalid drill queue attributes")  # noqa: TRY004
    return attributes


def _actions(value: Any) -> frozenset[str]:
    values = value if isinstance(value, list) else [value]
    return frozenset(item.casefold() for item in values if isinstance(item, str))


def _integer_between(value: Any, minimum: int, maximum: int) -> bool:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return False
    return minimum <= parsed <= maximum and str(parsed) == str(value)


def _load_document(path: str) -> Any:
    text = sys.stdin.read() if path == "-" else Path(path).read_text(encoding="utf-8")
    return json.loads(text)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Verify the live redrive IAM and SQS boundary without data-plane calls."
    )
    parser.add_argument(
        "route_json", help="Validated redrive route JSON, or '-' for stdin."
    )
    parser.add_argument("--role-arn", required=True)
    parser.add_argument("--expected-oidc-subject", required=True)
    parser.add_argument("--authorization-id", required=True)
    parser.add_argument("--aws-cli", default="aws")
    parser.add_argument("--timeout-seconds", type=int, default=30)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.timeout_seconds < 1 or args.timeout_seconds > 300:
        parser.error("--timeout-seconds must be between 1 and 300")
    try:
        route = RedriveRoute.from_document(_load_document(args.route_json))
        role = RoleBoundary.parse(args.role_arn, route)
        result = verify(
            route,
            role,
            args.expected_oidc_subject,
            AwsCli(executable=args.aws_cli, timeout_seconds=args.timeout_seconds),
            authorization_id=args.authorization_id,
        )
    except (OSError, ValueError, json.JSONDecodeError, RuntimeError) as exc:
        result = {"status": "error", "error": str(exc)}
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
