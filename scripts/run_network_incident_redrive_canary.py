#!/usr/bin/env python3
"""Exercise bounded SQS redrive on a dedicated non-production route."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import re
import sys
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

try:
    from scripts.verify_network_incident_route import (
        AwsCli,
        AwsClient,
        _parse_arn,
        _required_string,
    )
except ModuleNotFoundError:  # Direct execution from the scripts directory.
    from verify_network_incident_route import (
        AwsCli,
        AwsClient,
        _parse_arn,
        _required_string,
    )


CANARY_KIND = "network-incident-redrive-canary"
ROUTE_FIELDS = frozenset(
    {"production_queue_arn", "fault_queue_arn", "fault_dead_letter_queue_arn"}
)
PREFLIGHT_FIELDS = frozenset(
    {
        "authorization_id",
        "checks",
        "queue_route_sha256",
        "route_sha256",
        "schema_version",
        "status",
    }
)
PREFLIGHT_CHECKS = frozenset(
    {
        "caller-identity",
        "dead-letter-source-policy",
        "least-privilege-role-policy",
        "oidc-trust",
        "queue-encryption",
        "queue-identities",
        "queue-resource-policies",
        "queue-retention",
        "source-redrive-policy",
    }
)
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
AUTHORIZATION_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
QUEUE_ATTRIBUTES = [
    "QueueArn",
    "RedrivePolicy",
    "RedriveAllowPolicy",
    "ApproximateNumberOfMessages",
    "ApproximateNumberOfMessagesNotVisible",
]


@dataclass(frozen=True)
class RedriveRoute:
    production_queue_arn: str
    fault_queue_arn: str
    fault_dead_letter_queue_arn: str
    partition: str
    region: str
    account_id: str

    @classmethod
    def from_document(cls, document: Any) -> RedriveRoute:
        if (
            isinstance(document, dict)
            and "value" in document
            and isinstance(document["value"], dict)
        ):
            document = document["value"]
        if not isinstance(document, dict):
            raise ValueError("redrive route document must be a JSON object")
        if set(document) != ROUTE_FIELDS:
            missing = sorted(ROUTE_FIELDS.difference(document))
            unexpected = sorted(set(document).difference(ROUTE_FIELDS))
            raise ValueError(
                f"redrive route fields do not match schema; missing={missing}, "
                f"unexpected={unexpected}"
            )

        production_arn = _required_string(
            document["production_queue_arn"], "production_queue_arn"
        )
        fault_arn = _required_string(document["fault_queue_arn"], "fault_queue_arn")
        dlq_arn = _required_string(
            document["fault_dead_letter_queue_arn"], "fault_dead_letter_queue_arn"
        )
        production = _parse_arn(production_arn, expected_service="sqs")
        fault = _parse_arn(fault_arn, expected_service="sqs")
        dlq = _parse_arn(dlq_arn, expected_service="sqs")
        boundary = (production[0], production[2], production[3])
        if (fault[0], fault[2], fault[3]) != boundary or (
            dlq[0],
            dlq[2],
            dlq[3],
        ) != boundary:
            raise ValueError(
                "all redrive queues must share partition, Region and account"
            )
        if len({production_arn, fault_arn, dlq_arn}) != 3:
            raise ValueError(
                "production, fault-injection and dead-letter queues must be distinct"
            )
        if not fault[4].endswith("-fault-injection"):
            raise ValueError(
                "fault_queue_arn must identify a dedicated -fault-injection queue"
            )
        if dlq[4] != f"{fault[4]}-dlq":
            raise ValueError(
                "fault dead-letter queue must be the dedicated fault queue -dlq"
            )
        return cls(
            production_queue_arn=production_arn,
            fault_queue_arn=fault_arn,
            fault_dead_letter_queue_arn=dlq_arn,
            partition=production[0],
            region=production[2],
            account_id=production[3],
        )

    def digest(self) -> str:
        document = {
            "fault_dead_letter_queue_arn": self.fault_dead_letter_queue_arn,
            "fault_queue_arn": self.fault_queue_arn,
            "production_queue_arn": self.production_queue_arn,
        }
        payload = json.dumps(document, separators=(",", ":"), sort_keys=True)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class PreflightAuthorization:
    authorization_id: str
    receipt_sha256: str

    @classmethod
    def from_document(
        cls,
        document: Any,
        route: RedriveRoute,
        expected_authorization_id: str,
    ) -> PreflightAuthorization:
        if not isinstance(document, dict) or set(document) != PREFLIGHT_FIELDS:
            raise ValueError(
                "preflight receipt fields do not match the authorization schema"
            )
        if document.get("status") != "pass" or document.get("schema_version") != 1:
            raise ValueError(
                "preflight receipt is not a passing supported authorization"
            )
        if AUTHORIZATION_ID_PATTERN.fullmatch(expected_authorization_id) is None:
            raise ValueError("expected authorization_id is not a stable identifier")
        authorization_id = document.get("authorization_id")
        if authorization_id != expected_authorization_id:
            raise ValueError(
                "preflight receipt authorization_id does not match this run"
            )
        if document.get("queue_route_sha256") != route.digest():
            raise ValueError("preflight receipt does not authorize this queue route")
        if SHA256_PATTERN.fullmatch(str(document.get("route_sha256", ""))) is None:
            raise ValueError("preflight receipt has an invalid boundary commitment")

        checks = document.get("checks")
        if not isinstance(checks, list) or len(checks) != len(PREFLIGHT_CHECKS):
            raise ValueError("preflight receipt has an incomplete check set")
        names: list[str] = []
        for check in checks:
            if not isinstance(check, dict) or set(check) != {
                "detail",
                "name",
                "passed",
            }:
                raise ValueError("preflight receipt check fields do not match schema")
            name = check.get("name")
            detail = check.get("detail")
            if (
                not isinstance(name, str)
                or check.get("passed") is not True
                or not isinstance(detail, str)
                or not detail
                or len(detail) > 256
            ):
                raise ValueError(
                    "preflight receipt contains an invalid or failed check"
                )
            names.append(name)
        if len(set(names)) != len(names) or set(names) != PREFLIGHT_CHECKS:
            raise ValueError(
                "preflight receipt check names do not match the reviewed contract"
            )

        try:
            canonical = json.dumps(
                document,
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("ascii")
        except (TypeError, ValueError, UnicodeEncodeError) as exc:
            raise ValueError("preflight receipt is not canonicalizable") from exc
        return cls(
            authorization_id=authorization_id,
            receipt_sha256=hashlib.sha256(canonical).hexdigest(),
        )


def run_canary(
    route: RedriveRoute,
    aws: AwsClient,
    *,
    run_id: str,
    sent_at: str,
    preflight_sha256: str,
    dlq_receive_attempts: int = 5,
    wait_seconds: int = 5,
) -> dict[str, Any]:
    """Send one poison canary and verify bounded redrive into its dedicated DLQ."""

    if not run_id or len(run_id) > 128:
        raise ValueError("run_id must contain 1-128 characters")
    if (
        not isinstance(preflight_sha256, str)
        or SHA256_PATTERN.fullmatch(preflight_sha256) is None
    ):
        raise ValueError("preflight_sha256 must be a lowercase SHA-256 digest")
    if dlq_receive_attempts < 1 or dlq_receive_attempts > 10:
        raise ValueError("dlq_receive_attempts must be between 1 and 10")
    if wait_seconds < 1 or wait_seconds > 20:
        raise ValueError("wait_seconds must be between 1 and 20")

    fault_url, fault_attributes = _queue(aws, route, route.fault_queue_arn)
    dlq_url, dlq_attributes = _queue(aws, route, route.fault_dead_letter_queue_arn)
    _validate_live_route(route, fault_attributes, dlq_attributes)

    payload = {
        "kind": CANARY_KIND,
        "run_id": run_id,
        "schema_version": 2,
        "sent_at": sent_at,
        "preflight_sha256": preflight_sha256,
    }
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    published = aws.call(
        "sqs",
        "send-message",
        queue_url=fault_url,
        message_body=body,
        region=route.region,
    )
    source_message_id = published.get("MessageId")
    if not isinstance(source_message_id, str) or not source_message_id:
        raise RuntimeError("AWS CLI returned no MessageId for the redrive canary")

    max_receive_count = int(
        _json_object(fault_attributes["RedrivePolicy"])["maxReceiveCount"]
    )
    receive_counts: list[int] = []
    last_source_receipt: str | None = None
    try:
        for _ in range(max_receive_count + 2):
            response = aws.call(
                "sqs",
                "receive-message",
                queue_url=fault_url,
                max_number_of_messages="1",
                wait_time_seconds=str(wait_seconds),
                attribute_names=["ApproximateReceiveCount"],
                region=route.region,
            )
            messages = _messages(response, "fault-injection queue")
            if not messages:
                break
            receipt, observed_count = _matching_source(messages, body)
            if observed_count <= (receive_counts[-1] if receive_counts else 0):
                raise RuntimeError(
                    "source receive count did not increase monotonically"
                )
            receive_counts.append(observed_count)
            last_source_receipt = receipt
            aws.call(
                "sqs",
                "change-message-visibility",
                queue_url=fault_url,
                receipt_handle=receipt,
                visibility_timeout="0",
                region=route.region,
            )

        if len(receive_counts) < max_receive_count:
            raise RuntimeError(
                "poison canary did not exhaust the bounded receive policy"
            )

        for attempt in range(1, dlq_receive_attempts + 1):
            response = aws.call(
                "sqs",
                "receive-message",
                queue_url=dlq_url,
                max_number_of_messages="1",
                wait_time_seconds=str(wait_seconds),
                region=route.region,
            )
            messages = _messages(response, "fault-injection dead-letter queue")
            if not messages:
                continue
            receipt, dlq_message_id = _matching_dlq(messages, body)
            aws.call(
                "sqs",
                "delete-message",
                queue_url=dlq_url,
                receipt_handle=receipt,
                region=route.region,
            )
            return {
                "status": "pass",
                "schema_version": 2,
                "run_id": run_id,
                "route_sha256": route.digest(),
                "preflight_sha256": preflight_sha256,
                "observed": {
                    "source_message_id": source_message_id,
                    "dead_letter_message_id": dlq_message_id,
                    "max_receive_count": max_receive_count,
                    "source_receive_counts": receive_counts,
                    "dead_letter_receive_attempt": attempt,
                    "cleanup": "deleted_verified_dead_letter_message",
                },
            }
        raise RuntimeError(
            "poison canary was not observed in the dead-letter queue after bounded polling"
        )
    except (RuntimeError, ValueError):
        if last_source_receipt is not None:
            _best_effort_delete(aws, route, fault_url, last_source_receipt)
        raise


def _queue(
    aws: AwsClient, route: RedriveRoute, queue_arn: str
) -> tuple[str, dict[str, Any]]:
    queue_name = queue_arn.rsplit(":", 1)[1]
    queue_url = aws.call(
        "sqs",
        "get-queue-url",
        queue_name=queue_name,
        queue_owner_aws_account_id=route.account_id,
        region=route.region,
    ).get("QueueUrl")
    if not isinstance(queue_url, str) or not queue_url:
        raise RuntimeError("AWS CLI returned no QueueUrl for a redrive-canary queue")
    attributes = aws.call(
        "sqs",
        "get-queue-attributes",
        queue_url=queue_url,
        attribute_names=QUEUE_ATTRIBUTES,
        region=route.region,
    ).get("Attributes")
    if not isinstance(attributes, dict):
        raise RuntimeError(
            "AWS CLI returned invalid queue attributes for the redrive canary"
        )
    return queue_url, attributes


def _validate_live_route(
    route: RedriveRoute, fault: dict[str, Any], dlq: dict[str, Any]
) -> None:
    if fault.get("QueueArn") != route.fault_queue_arn:
        raise RuntimeError("fault queue URL resolved to an unexpected ARN")
    if dlq.get("QueueArn") != route.fault_dead_letter_queue_arn:
        raise RuntimeError("fault dead-letter queue URL resolved to an unexpected ARN")
    redrive = _json_object(fault.get("RedrivePolicy"))
    count = _bounded_count(redrive.get("maxReceiveCount"))
    if (
        redrive.get("deadLetterTargetArn") != route.fault_dead_letter_queue_arn
        or count is None
    ):
        raise RuntimeError(
            "fault queue redrive policy is missing, unbounded or misrouted"
        )
    allow = _json_object(dlq.get("RedriveAllowPolicy"))
    if allow != {
        "redrivePermission": "byQueue",
        "sourceQueueArns": [route.fault_queue_arn],
    }:
        raise RuntimeError(
            "fault DLQ must allow redrive only from the dedicated fault queue"
        )
    for attributes in (fault, dlq):
        if (
            attributes.get("ApproximateNumberOfMessages") != "0"
            or attributes.get("ApproximateNumberOfMessagesNotVisible") != "0"
        ):
            raise RuntimeError("redrive canary queues must be empty before the drill")


def _bounded_count(value: Any) -> int | None:
    try:
        count = int(value)
    except (TypeError, ValueError):
        return None
    return count if 2 <= count <= 5 and str(count) == str(value) else None


def _messages(response: dict[str, Any], queue: str) -> list[Any]:
    messages = response.get("Messages", [])
    if not isinstance(messages, list) or len(messages) > 1:
        raise RuntimeError(f"AWS CLI returned invalid Messages for the {queue}")
    return messages


def _matching_source(messages: list[Any], expected_body: str) -> tuple[str, int]:
    message = messages[0]
    if not isinstance(message, dict) or message.get("Body") != expected_body:
        raise RuntimeError(
            "fault queue returned a message outside the isolated canary run"
        )
    receipt = _required_string(message.get("ReceiptHandle"), "ReceiptHandle")
    attributes = message.get("Attributes")
    if not isinstance(attributes, dict):
        raise RuntimeError("source canary message has no receive-count attributes")
    try:
        count = int(attributes.get("ApproximateReceiveCount"))
    except (TypeError, ValueError) as exc:
        raise RuntimeError(
            "source canary has an invalid approximate receive count"
        ) from exc
    if count < 1:
        raise RuntimeError("source canary has an invalid approximate receive count")
    return receipt, count


def _matching_dlq(messages: list[Any], expected_body: str) -> tuple[str, str]:
    message = messages[0]
    if not isinstance(message, dict) or message.get("Body") != expected_body:
        raise RuntimeError(
            "dead-letter queue returned a message outside the isolated canary run"
        )
    return (
        _required_string(message.get("ReceiptHandle"), "ReceiptHandle"),
        _required_string(message.get("MessageId"), "MessageId"),
    )


def _best_effort_delete(
    aws: AwsClient, route: RedriveRoute, queue_url: str, receipt_handle: str
) -> None:
    with contextlib.suppress(RuntimeError):
        aws.call(
            "sqs",
            "delete-message",
            queue_url=queue_url,
            receipt_handle=receipt_handle,
            region=route.region,
        )


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
        description="Verify bounded redrive on an isolated non-production SQS route."
    )
    parser.add_argument(
        "route_json", help="Validated redrive route JSON, or '-' for stdin."
    )
    parser.add_argument("--preflight-receipt", required=True)
    parser.add_argument("--authorization-id", required=True)
    parser.add_argument(
        "--aws-cli", default="aws", help="AWS CLI executable (default: aws)."
    )
    parser.add_argument("--call-timeout-seconds", type=int, default=30)
    parser.add_argument("--dlq-receive-attempts", type=int, default=5)
    parser.add_argument("--wait-seconds", type=int, default=5)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.call_timeout_seconds < 1 or args.call_timeout_seconds > 300:
        parser.error("--call-timeout-seconds must be between 1 and 300")
    if args.dlq_receive_attempts < 1 or args.dlq_receive_attempts > 10:
        parser.error("--dlq-receive-attempts must be between 1 and 10")
    if args.wait_seconds < 1 or args.wait_seconds > 20:
        parser.error("--wait-seconds must be between 1 and 20")

    try:
        route = RedriveRoute.from_document(_load_document(args.route_json))
        authorization = PreflightAuthorization.from_document(
            _load_document(args.preflight_receipt), route, args.authorization_id
        )
        result = run_canary(
            route,
            AwsCli(executable=args.aws_cli, timeout_seconds=args.call_timeout_seconds),
            run_id=str(uuid.uuid4()),
            sent_at=datetime.now(UTC).isoformat(),
            preflight_sha256=authorization.receipt_sha256,
            dlq_receive_attempts=args.dlq_receive_attempts,
            wait_seconds=args.wait_seconds,
        )
    except (OSError, ValueError, json.JSONDecodeError, RuntimeError) as exc:
        result = {"status": "error", "error": str(exc)}
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
