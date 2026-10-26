#!/usr/bin/env python3
"""Read-only runtime preflight for the managed SNS-to-SQS incident route."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol


BASE_ALARM_NAMES = (
    "ml-platform-rejected-packets",
    "ml-platform-flow-log-delivery-health",
)


class AwsClient(Protocol):
    def call(
        self, service: str, operation: str, **parameters: str | list[str]
    ) -> dict[str, Any]: ...


class AwsCli:
    """Small AWS CLI adapter so the verifier has no runtime Python dependencies."""

    def __init__(self, *, executable: str = "aws", timeout_seconds: int = 30) -> None:
        self.executable = executable
        self.timeout_seconds = timeout_seconds

    def call(self, service: str, operation: str, **parameters: str | list[str]) -> dict[str, Any]:
        command = [self.executable, service, operation]
        for name, value in parameters.items():
            command.append(f"--{name.replace('_', '-')}")
            command.extend(value if isinstance(value, list) else [value])
        command.extend(["--output", "json", "--no-cli-pager"])

        try:
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
            )
        except FileNotFoundError as exc:
            raise RuntimeError(f"AWS CLI executable not found: {self.executable}") from exc
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(
                f"AWS CLI timed out after {self.timeout_seconds}s: {service} {operation}"
            ) from exc

        if completed.returncode != 0:
            detail = completed.stderr.strip().replace("\n", " ")[:500]
            raise RuntimeError(
                f"AWS CLI failed: {service} {operation}: {detail or 'no error text'}"
            )
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"AWS CLI returned invalid JSON: {service} {operation}") from exc
        if not isinstance(payload, dict):
            raise RuntimeError(f"AWS CLI returned a non-object response: {service} {operation}")
        return payload


@dataclass(frozen=True)
class Route:
    topic_arn: str
    queue_arn: str
    dead_letter_queue_arn: str
    queue_health_alarms: tuple[str, ...]
    partition: str
    region: str
    account_id: str

    @classmethod
    def from_document(cls, document: Any) -> "Route":
        if (
            isinstance(document, dict)
            and "value" in document
            and isinstance(document["value"], dict)
        ):
            document = document["value"]
        if not isinstance(document, dict):
            raise ValueError("route document must be a JSON object")

        required = (
            "topic_arn",
            "queue_arn",
            "dead_letter_queue_arn",
            "queue_health_alarms",
        )
        missing = [name for name in required if name not in document]
        if missing:
            raise ValueError(f"route document is missing: {', '.join(missing)}")

        topic_arn = _required_string(document["topic_arn"], "topic_arn")
        queue_arn = _required_string(document["queue_arn"], "queue_arn")
        dlq_arn = _required_string(document["dead_letter_queue_arn"], "dead_letter_queue_arn")
        alarms = document["queue_health_alarms"]
        if not isinstance(alarms, list) or not alarms or not all(
            isinstance(alarm, str) and alarm for alarm in alarms
        ):
            raise ValueError("queue_health_alarms must be a non-empty list of names")

        topic = _parse_arn(topic_arn, expected_service="sns")
        queue = _parse_arn(queue_arn, expected_service="sqs")
        dlq = _parse_arn(dlq_arn, expected_service="sqs")
        boundary = (topic[0], topic[2], topic[3])
        if (queue[0], queue[2], queue[3]) != boundary or (dlq[0], dlq[2], dlq[3]) != boundary:
            raise ValueError(
                "topic, queue and dead-letter queue must share partition, Region and account"
            )
        if queue_arn == dlq_arn:
            raise ValueError("queue and dead-letter queue ARNs must differ")

        return cls(
            topic_arn=topic_arn,
            queue_arn=queue_arn,
            dead_letter_queue_arn=dlq_arn,
            queue_health_alarms=tuple(alarms),
            partition=topic[0],
            region=topic[2],
            account_id=topic[3],
        )

    @property
    def expected_alarm_arns(self) -> set[str]:
        names = (*BASE_ALARM_NAMES, *self.queue_health_alarms)
        return {
            f"arn:{self.partition}:cloudwatch:{self.region}:{self.account_id}:alarm:{name}"
            for name in names
        }


@dataclass
class Check:
    name: str
    passed: bool
    detail: str


def verify(route: Route, aws: AwsClient) -> dict[str, Any]:
    checks: list[Check] = []

    def check(name: str, condition: bool, success: str, failure: str) -> None:
        checks.append(Check(name, condition, success if condition else failure))

    topic_attributes = aws.call(
        "sns", "get-topic-attributes", topic_arn=route.topic_arn, region=route.region
    ).get("Attributes", {})
    check(
        "topic-encryption",
        bool(topic_attributes.get("KmsMasterKeyId")),
        "managed topic is KMS encrypted",
        "managed topic has no KmsMasterKeyId",
    )

    topic_policy = _json_object(topic_attributes.get("Policy"))
    check(
        "cloudwatch-publish-policy",
        _allows_cloudwatch_alarms(topic_policy, route),
        "topic policy binds CloudWatch publication to every managed alarm",
        "topic policy does not exactly bind CloudWatch publication to the managed alarms",
    )

    queue_url, queue_attributes = _queue_attributes(aws, route.queue_arn, route)
    dlq_url, dlq_attributes = _queue_attributes(aws, route.dead_letter_queue_arn, route)
    check(
        "queue-identity",
        queue_attributes.get("QueueArn") == route.queue_arn,
        "consumer queue resolved to the expected ARN",
        "consumer queue URL resolved to an unexpected ARN",
    )
    check(
        "dead-letter-identity",
        dlq_attributes.get("QueueArn") == route.dead_letter_queue_arn,
        "dead-letter queue resolved to the expected ARN",
        "dead-letter queue URL resolved to an unexpected ARN",
    )
    check(
        "queue-encryption",
        bool(queue_attributes.get("KmsMasterKeyId")) and bool(dlq_attributes.get("KmsMasterKeyId")),
        "consumer and dead-letter queues are KMS encrypted",
        "consumer or dead-letter queue has no KmsMasterKeyId",
    )
    check(
        "shared-encryption-boundary",
        bool(topic_attributes.get("KmsMasterKeyId"))
        and topic_attributes.get("KmsMasterKeyId") == queue_attributes.get("KmsMasterKeyId")
        and queue_attributes.get("KmsMasterKeyId") == dlq_attributes.get("KmsMasterKeyId"),
        "topic, consumer queue and dead-letter queue use the same KMS key",
        "managed route resources do not share the expected KMS key",
    )

    queue_policy = _json_object(queue_attributes.get("Policy"))
    check(
        "topic-to-queue-policy",
        _allows_exact_topic(queue_policy, route.queue_arn, route),
        "queue policy contains the exact topic/account delivery boundary",
        "queue policy does not bind SQS delivery to the expected topic and account",
    )
    dlq_policy = _json_object(dlq_attributes.get("Policy"))
    check(
        "topic-to-dead-letter-policy",
        _allows_exact_topic(dlq_policy, route.dead_letter_queue_arn, route),
        "dead-letter policy contains the exact SNS delivery-failure boundary",
        "dead-letter policy does not allow delivery failures from the expected topic/account",
    )

    redrive = _json_object(queue_attributes.get("RedrivePolicy"))
    check(
        "consumer-redrive-policy",
        redrive.get("deadLetterTargetArn") == route.dead_letter_queue_arn
        and _positive_integer(redrive.get("maxReceiveCount")),
        "consumer failures have a bounded path to the expected dead-letter queue",
        "consumer queue redrive policy is missing, unbounded or targets another queue",
    )

    redrive_allow = _json_object(dlq_attributes.get("RedriveAllowPolicy"))
    check(
        "dead-letter-source-policy",
        redrive_allow.get("redrivePermission") == "byQueue"
        and redrive_allow.get("sourceQueueArns") == [route.queue_arn],
        "dead-letter queue accepts redrive only from the consumer queue",
        "dead-letter queue does not restrict redrive to the consumer queue",
    )

    subscriptions = aws.call(
        "sns", "list-subscriptions-by-topic", topic_arn=route.topic_arn, region=route.region
    ).get("Subscriptions", [])
    matching = [
        item
        for item in subscriptions
        if isinstance(item, dict)
        and item.get("Protocol") == "sqs"
        and item.get("Endpoint") == route.queue_arn
        and item.get("SubscriptionArn") not in (None, "PendingConfirmation", "Deleted")
    ]
    check(
        "confirmed-subscription",
        len(matching) == 1,
        "exactly one confirmed SQS subscription connects the topic to the consumer queue",
        "expected exactly one confirmed SQS subscription for the consumer queue",
    )

    if len(matching) == 1:
        subscription_attributes = aws.call(
            "sns",
            "get-subscription-attributes",
            subscription_arn=str(matching[0]["SubscriptionArn"]),
            region=route.region,
        ).get("Attributes", {})
        subscription_redrive = _json_object(subscription_attributes.get("RedrivePolicy"))
        check(
            "subscription-redrive-policy",
            subscription_redrive.get("deadLetterTargetArn") == route.dead_letter_queue_arn,
            "SNS delivery failures target the expected dead-letter queue",
            "SNS subscription delivery failures do not target the expected dead-letter queue",
        )
        check(
            "sns-envelope-retention",
            subscription_attributes.get("RawMessageDelivery", "false").lower() == "false",
            "SNS envelopes are retained for incident provenance",
            "raw delivery removes the SNS provenance envelope",
        )

    result = {
        "status": "pass" if all(item.passed for item in checks) else "fail",
        "route": {
            "topic_arn": route.topic_arn,
            "queue_arn": route.queue_arn,
            "dead_letter_queue_arn": route.dead_letter_queue_arn,
        },
        "checks": [item.__dict__ for item in checks],
        "observed": {"queue_url": queue_url, "dead_letter_queue_url": dlq_url},
    }
    return result


def _queue_attributes(aws: AwsClient, arn: str, route: Route) -> tuple[str, dict[str, Any]]:
    queue_name = arn.rsplit(":", 1)[1]
    queue_url = aws.call(
        "sqs",
        "get-queue-url",
        queue_name=queue_name,
        queue_owner_aws_account_id=route.account_id,
        region=route.region,
    ).get("QueueUrl")
    if not isinstance(queue_url, str) or not queue_url:
        raise RuntimeError(f"AWS CLI returned no QueueUrl for {arn}")
    attributes = aws.call(
        "sqs",
        "get-queue-attributes",
        queue_url=queue_url,
        attribute_names=[
            "QueueArn",
            "Policy",
            "RedrivePolicy",
            "RedriveAllowPolicy",
            "KmsMasterKeyId",
        ],
        region=route.region,
    ).get("Attributes", {})
    if not isinstance(attributes, dict):
        raise RuntimeError(f"AWS CLI returned invalid queue attributes for {arn}")
    return queue_url, attributes


def _allows_cloudwatch_alarms(policy: dict[str, Any], route: Route) -> bool:
    relevant = [
        statement
        for statement in _statements(policy)
        if statement.get("Effect") == "Allow"
        and _principal_may_include(statement.get("Principal"), "cloudwatch.amazonaws.com")
        and _action_allows(statement.get("Action"), "sns:publish")
    ]
    if len(relevant) != 1:
        return False
    statement = relevant[0]
    condition = statement.get("Condition", {})
    return (
        _principal_is(statement.get("Principal"), "cloudwatch.amazonaws.com")
        and _contains_casefold(statement.get("Action"), "sns:publish")
        and _contains(statement.get("Resource"), route.topic_arn)
        and _condition_values(condition, "aws:SourceAccount") == [route.account_id]
        and set(_condition_values(condition, "aws:SourceArn")) == route.expected_alarm_arns
    )


def _allows_exact_topic(policy: dict[str, Any], resource_arn: str, route: Route) -> bool:
    relevant = [
        statement
        for statement in _statements(policy)
        if statement.get("Effect") == "Allow"
        and _principal_may_include(statement.get("Principal"), "sns.amazonaws.com")
        and _action_allows(statement.get("Action"), "sqs:sendmessage")
    ]
    if len(relevant) != 1:
        return False
    statement = relevant[0]
    condition = statement.get("Condition", {})
    return (
        _principal_is(statement.get("Principal"), "sns.amazonaws.com")
        and _contains_casefold(statement.get("Action"), "sqs:sendmessage")
        and _contains(statement.get("Resource"), resource_arn)
        and _condition_values(condition, "aws:SourceAccount") == [route.account_id]
        and _condition_values(condition, "aws:SourceArn") == [route.topic_arn]
    )


def _statements(policy: dict[str, Any]) -> list[dict[str, Any]]:
    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        return []
    return [item for item in statements if isinstance(item, dict)]


def _condition_values(condition: Any, key: str) -> list[str]:
    if not isinstance(condition, dict):
        return []
    values: list[str] = []
    for operator in ("StringEquals", "ArnEquals"):
        block = condition.get(operator, {})
        if isinstance(block, dict) and key in block:
            value = block[key]
            values.extend(value if isinstance(value, list) else [value])
    return [value for value in values if isinstance(value, str)]


def _principal_is(principal: Any, service: str) -> bool:
    return isinstance(principal, dict) and _contains(principal.get("Service"), service)


def _principal_may_include(principal: Any, service: str) -> bool:
    return principal == "*" or (
        isinstance(principal, dict)
        and (
            _contains(principal.get("Service"), service)
            or _contains(principal.get("Service"), "*")
        )
    )


def _action_allows(value: Any, expected: str) -> bool:
    actions = [
        item.casefold()
        for item in (value if isinstance(value, list) else [value])
        if isinstance(item, str)
    ]
    service = expected.split(":", 1)[0]
    return expected.casefold() in actions or f"{service}:*" in actions or "*" in actions


def _contains(value: Any, expected: str) -> bool:
    return expected in (value if isinstance(value, list) else [value])


def _contains_casefold(value: Any, expected: str) -> bool:
    values = value if isinstance(value, list) else [value]
    return expected.casefold() in [
        item.casefold() for item in values if isinstance(item, str)
    ]


def _json_object(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if not isinstance(value, str) or not value:
        return {}
    try:
        decoded = json.loads(value)
    except json.JSONDecodeError:
        return {}
    return decoded if isinstance(decoded, dict) else {}


def _positive_integer(value: Any) -> bool:
    try:
        return int(value) >= 1 and str(int(value)) == str(value)
    except (TypeError, ValueError):
        return False


def _required_string(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(
            f"{name} must be a non-empty string; enable the managed queue before preflight"
        )
    return value


def _parse_arn(arn: str, *, expected_service: str) -> tuple[str, str, str, str, str]:
    parts = arn.split(":", 5)
    if len(parts) != 6 or parts[0] != "arn" or parts[2] != expected_service:
        raise ValueError(f"expected an {expected_service} ARN, got: {arn}")
    partition, service, region, account_id, resource = parts[1:]
    if (
        not all((partition, service, region, account_id, resource))
        or not account_id.isdigit()
        or len(account_id) != 12
    ):
        raise ValueError(f"malformed ARN: {arn}")
    return partition, service, region, account_id, resource


def _load_document(path: str) -> Any:
    text = sys.stdin.read() if path == "-" else Path(path).read_text(encoding="utf-8")
    return json.loads(text)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Verify the deployed managed network incident route without publishing or "
            "consuming messages."
        )
    )
    parser.add_argument(
        "route_json",
        help=(
            "Terraform output JSON file, or '-' for stdin "
            "(terraform output -json managed_network_incident_route)."
        ),
    )
    parser.add_argument("--aws-cli", default="aws", help="AWS CLI executable (default: aws).")
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=30,
        help="Timeout for each AWS CLI call.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.timeout_seconds < 1 or args.timeout_seconds > 300:
        _parser().error("--timeout-seconds must be between 1 and 300")
    try:
        route = Route.from_document(_load_document(args.route_json))
        result = verify(
            route,
            AwsCli(executable=args.aws_cli, timeout_seconds=args.timeout_seconds),
        )
    except (OSError, ValueError, json.JSONDecodeError, RuntimeError) as exc:
        result = {"status": "error", "error": str(exc)}
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
