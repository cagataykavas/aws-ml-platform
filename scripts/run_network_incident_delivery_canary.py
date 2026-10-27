#!/usr/bin/env python3
"""Exercise the isolated SNS-to-SQS delivery-canary path."""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from scripts.verify_network_incident_route import (
        AwsCli,
        AwsClient,
        _parse_arn,
        _required_string,
    )
except ModuleNotFoundError:  # Direct execution: python scripts/run_network_...py
    from verify_network_incident_route import AwsCli, AwsClient, _parse_arn, _required_string


CANARY_KIND = "network-incident-delivery-canary"
CANARY_ATTRIBUTE = json.dumps(
    {"route_canary": {"DataType": "String", "StringValue": "true"}},
    separators=(",", ":"),
    sort_keys=True,
)


@dataclass(frozen=True)
class CanaryRoute:
    topic_arn: str
    queue_arn: str
    partition: str
    region: str
    account_id: str

    @classmethod
    def from_document(cls, document: Any) -> "CanaryRoute":
        if (
            isinstance(document, dict)
            and "value" in document
            and isinstance(document["value"], dict)
        ):
            document = document["value"]
        if not isinstance(document, dict):
            raise ValueError("route document must be a JSON object")

        topic_arn = _required_string(document.get("topic_arn"), "topic_arn")
        queue_arn = _required_string(
            document.get("delivery_canary_queue_arn"), "delivery_canary_queue_arn"
        )
        topic = _parse_arn(topic_arn, expected_service="sns")
        queue = _parse_arn(queue_arn, expected_service="sqs")
        if (queue[0], queue[2], queue[3]) != (topic[0], topic[2], topic[3]):
            raise ValueError("topic and canary queue must share partition, Region and account")
        if not queue[4].endswith("-canary"):
            raise ValueError("delivery_canary_queue_arn must identify a dedicated -canary queue")
        protected = {
            value
            for value in (
                document.get("queue_arn"),
                document.get("dead_letter_queue_arn"),
            )
            if isinstance(value, str) and value
        }
        if queue_arn in protected:
            raise ValueError("delivery canary queue must differ from incident and dead-letter queues")
        return cls(
            topic_arn=topic_arn,
            queue_arn=queue_arn,
            partition=topic[0],
            region=topic[2],
            account_id=topic[3],
        )


def run_canary(
    route: CanaryRoute,
    aws: AwsClient,
    *,
    run_id: str,
    sent_at: str,
    max_attempts: int = 3,
    wait_seconds: int = 10,
) -> dict[str, Any]:
    """Publish one canary and delete only its verified delivery."""

    if not run_id or len(run_id) > 128:
        raise ValueError("run_id must contain 1-128 characters")
    if max_attempts < 1 or max_attempts > 10:
        raise ValueError("max_attempts must be between 1 and 10")
    if wait_seconds < 1 or wait_seconds > 20:
        raise ValueError("wait_seconds must be between 1 and 20")

    queue_name = route.queue_arn.rsplit(":", 1)[1]
    queue_url = aws.call(
        "sqs",
        "get-queue-url",
        queue_name=queue_name,
        queue_owner_aws_account_id=route.account_id,
        region=route.region,
    ).get("QueueUrl")
    if not isinstance(queue_url, str) or not queue_url:
        raise RuntimeError("AWS CLI returned no QueueUrl for the delivery canary")

    payload = {
        "kind": CANARY_KIND,
        "run_id": run_id,
        "schema_version": 1,
        "sent_at": sent_at,
    }
    published = aws.call(
        "sns",
        "publish",
        topic_arn=route.topic_arn,
        message=json.dumps(payload, separators=(",", ":"), sort_keys=True),
        message_attributes=CANARY_ATTRIBUTE,
        region=route.region,
    )
    sns_message_id = published.get("MessageId")
    if not isinstance(sns_message_id, str) or not sns_message_id:
        raise RuntimeError("AWS CLI returned no MessageId for the canary publish")

    ignored = 0
    for attempt in range(1, max_attempts + 1):
        response = aws.call(
            "sqs",
            "receive-message",
            queue_url=queue_url,
            max_number_of_messages="10",
            wait_time_seconds=str(wait_seconds),
            message_attribute_names=["All"],
            region=route.region,
        )
        messages = response.get("Messages", [])
        if not isinstance(messages, list):
            raise RuntimeError("AWS CLI returned invalid Messages for the delivery canary")
        for message in messages:
            match = _matching_delivery(message, route, payload)
            if match is None:
                ignored += 1
                continue
            receipt_handle, sqs_message_id = match
            aws.call(
                "sqs",
                "delete-message",
                queue_url=queue_url,
                receipt_handle=receipt_handle,
                region=route.region,
            )
            return {
                "status": "pass",
                "schema_version": 1,
                "run_id": run_id,
                "route": {
                    "topic_arn": route.topic_arn,
                    "delivery_canary_queue_arn": route.queue_arn,
                },
                "observed": {
                    "sns_message_id": sns_message_id,
                    "sqs_message_id": sqs_message_id,
                    "receive_attempt": attempt,
                    "ignored_messages": ignored,
                },
            }
    raise RuntimeError(
        f"delivery canary was not observed after {max_attempts} bounded receive attempts"
    )


def _matching_delivery(
    message: Any, route: CanaryRoute, expected: dict[str, Any]
) -> tuple[str, str] | None:
    if not isinstance(message, dict):
        return None
    body = _json_object(message.get("Body"))
    inner = _json_object(body.get("Message"))
    if inner.get("run_id") != expected["run_id"]:
        return None
    if (
        body.get("Type") != "Notification"
        or body.get("TopicArn") != route.topic_arn
        or inner != expected
        or body.get("MessageAttributes")
        != {"route_canary": {"Type": "String", "Value": "true"}}
    ):
        raise RuntimeError("matching canary arrived with an invalid SNS envelope or payload")
    receipt_handle = message.get("ReceiptHandle")
    message_id = message.get("MessageId")
    if not isinstance(receipt_handle, str) or not receipt_handle:
        raise RuntimeError("matching canary has no receipt handle")
    if not isinstance(message_id, str) or not message_id:
        raise RuntimeError("matching canary has no SQS message ID")
    return receipt_handle, message_id


def _json_object(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if not isinstance(value, str):
        return {}
    try:
        decoded = json.loads(value)
    except json.JSONDecodeError:
        return {}
    return decoded if isinstance(decoded, dict) else {}


def _load_document(path: str) -> Any:
    text = sys.stdin.read() if path == "-" else Path(path).read_text(encoding="utf-8")
    return json.loads(text)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Publish and verify one message on the isolated network-incident canary path."
    )
    parser.add_argument("route_json", help="Terraform route output JSON file, or '-' for stdin.")
    parser.add_argument("--aws-cli", default="aws", help="AWS CLI executable (default: aws).")
    parser.add_argument("--call-timeout-seconds", type=int, default=30)
    parser.add_argument("--receive-attempts", type=int, default=3)
    parser.add_argument("--wait-seconds", type=int, default=10)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.call_timeout_seconds < 1 or args.call_timeout_seconds > 300:
        parser.error("--call-timeout-seconds must be between 1 and 300")
    if args.receive_attempts < 1 or args.receive_attempts > 10:
        parser.error("--receive-attempts must be between 1 and 10")
    if args.wait_seconds < 1 or args.wait_seconds > 20:
        parser.error("--wait-seconds must be between 1 and 20")

    try:
        route = CanaryRoute.from_document(_load_document(args.route_json))
        result = run_canary(
            route,
            AwsCli(executable=args.aws_cli, timeout_seconds=args.call_timeout_seconds),
            run_id=str(uuid.uuid4()),
            sent_at=datetime.now(timezone.utc).isoformat(),
            max_attempts=args.receive_attempts,
            wait_seconds=args.wait_seconds,
        )
    except (OSError, ValueError, json.JSONDecodeError, RuntimeError) as exc:
        result = {"status": "error", "error": str(exc)}
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
