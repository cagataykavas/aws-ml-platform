from __future__ import annotations

import json
import unittest
from typing import Any

from scripts.run_network_incident_redrive_canary import (
    CANARY_KIND,
    PREFLIGHT_CHECKS,
    PreflightAuthorization,
    RedriveRoute,
    run_canary,
)

ACCOUNT = "123456789012"
REGION = "eu-central-1"
PRODUCTION_ARN = (
    f"arn:aws:sqs:{REGION}:{ACCOUNT}:ml-platform-network-incidents-consumer"
)
FAULT_ARN = (
    f"arn:aws:sqs:{REGION}:{ACCOUNT}:ml-platform-network-incidents-fault-injection"
)
DLQ_ARN = f"{FAULT_ARN}-dlq"
FAULT_URL = f"https://sqs.{REGION}.amazonaws.com/{ACCOUNT}/fault-injection"
DLQ_URL = f"{FAULT_URL}-dlq"
RUN_ID = "redrive-run-1"
SENT_AT = "2026-10-28T05:00:00+00:00"
AUTHORIZATION_ID = "40903776746:1"
PREFLIGHT_SHA256 = "a" * 64


def route_document() -> dict[str, str]:
    return {
        "production_queue_arn": PRODUCTION_ARN,
        "fault_queue_arn": FAULT_ARN,
        "fault_dead_letter_queue_arn": DLQ_ARN,
    }


def payload(run_id: str = RUN_ID) -> str:
    return json.dumps(
        {
            "kind": CANARY_KIND,
            "preflight_sha256": PREFLIGHT_SHA256,
            "run_id": run_id,
            "schema_version": 2,
            "sent_at": SENT_AT,
        },
        separators=(",", ":"),
        sort_keys=True,
    )


def source_message(count: int, *, body: str | None = None) -> dict[str, Any]:
    return {
        "Body": payload() if body is None else body,
        "ReceiptHandle": f"source-receipt-{count}",
        "MessageId": "source-message-1",
        "Attributes": {"ApproximateReceiveCount": str(count)},
    }


def dlq_message(*, body: str | None = None) -> dict[str, str]:
    return {
        "Body": payload() if body is None else body,
        "ReceiptHandle": "dlq-receipt-1",
        "MessageId": "dlq-message-1",
    }


def attributes(max_receive_count: str = "2") -> dict[str, dict[str, str]]:
    empty = {
        "ApproximateNumberOfMessages": "0",
        "ApproximateNumberOfMessagesNotVisible": "0",
    }
    return {
        FAULT_URL: {
            **empty,
            "QueueArn": FAULT_ARN,
            "RedrivePolicy": json.dumps(
                {
                    "deadLetterTargetArn": DLQ_ARN,
                    "maxReceiveCount": max_receive_count,
                }
            ),
        },
        DLQ_URL: {
            **empty,
            "QueueArn": DLQ_ARN,
            "RedriveAllowPolicy": json.dumps(
                {"redrivePermission": "byQueue", "sourceQueueArns": [FAULT_ARN]}
            ),
        },
    }


def preflight_receipt(route: RedriveRoute) -> dict[str, Any]:
    return {
        "status": "pass",
        "schema_version": 1,
        "authorization_id": AUTHORIZATION_ID,
        "queue_route_sha256": route.digest(),
        "route_sha256": "b" * 64,
        "checks": [
            {"name": name, "passed": True, "detail": f"{name} passed"}
            for name in sorted(PREFLIGHT_CHECKS)
        ],
    }


class FakeAws:
    def __init__(
        self,
        *,
        source_receives: list[dict[str, Any]] | None = None,
        dlq_receives: list[dict[str, Any]] | None = None,
        queue_attributes: dict[str, dict[str, str]] | None = None,
    ) -> None:
        self.source_receives = list(source_receives or [])
        self.dlq_receives = list(dlq_receives or [])
        self.queue_attributes = queue_attributes or attributes()
        self.calls: list[tuple[str, str, dict[str, str | list[str]]]] = []

    def call(
        self, service: str, operation: str, **parameters: str | list[str]
    ) -> dict[str, Any]:
        self.calls.append((service, operation, parameters))
        if (service, operation) == ("sqs", "get-queue-url"):
            return {
                "QueueUrl": DLQ_URL
                if str(parameters["queue_name"]).endswith("-dlq")
                else FAULT_URL
            }
        if (service, operation) == ("sqs", "get-queue-attributes"):
            return {"Attributes": self.queue_attributes[str(parameters["queue_url"])]}
        if (service, operation) == ("sqs", "send-message"):
            return {"MessageId": "source-message-1"}
        if (service, operation) == ("sqs", "receive-message"):
            receives = (
                self.dlq_receives
                if parameters["queue_url"] == DLQ_URL
                else self.source_receives
            )
            return receives.pop(0) if receives else {}
        if (service, operation) in {
            ("sqs", "change-message-visibility"),
            ("sqs", "delete-message"),
        }:
            return {}
        raise AssertionError(f"unexpected call: {service} {operation}")


class RedriveRouteTests(unittest.TestCase):
    def test_accepts_wrapped_route_and_hashes_it(self) -> None:
        route = RedriveRoute.from_document(
            {"value": route_document(), "type": ["object"]}
        )

        self.assertEqual(route.region, REGION)
        self.assertEqual(len(route.digest()), 64)

    def test_rejects_unknown_route_fields(self) -> None:
        document = {**route_document(), "topic_arn": "unused"}

        with self.assertRaisesRegex(ValueError, "unexpected"):
            RedriveRoute.from_document(document)

    def test_rejects_cross_account_fault_queue(self) -> None:
        document = route_document()
        document["fault_queue_arn"] = FAULT_ARN.replace(ACCOUNT, "999999999999")

        with self.assertRaisesRegex(ValueError, "share partition, Region and account"):
            RedriveRoute.from_document(document)


class PreflightAuthorizationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.route = RedriveRoute.from_document(route_document())

    def test_binds_exact_passing_receipt_to_this_run_and_route(self) -> None:
        authorization = PreflightAuthorization.from_document(
            preflight_receipt(self.route), self.route, AUTHORIZATION_ID
        )

        self.assertEqual(authorization.authorization_id, AUTHORIZATION_ID)
        self.assertEqual(len(authorization.receipt_sha256), 64)

    def test_rejects_failed_tampered_or_replayed_receipt(self) -> None:
        failed = preflight_receipt(self.route)
        failed["checks"][0]["passed"] = False
        with self.assertRaisesRegex(ValueError, "invalid or failed check"):
            PreflightAuthorization.from_document(failed, self.route, AUTHORIZATION_ID)

        replayed = preflight_receipt(self.route)
        with self.assertRaisesRegex(ValueError, "does not match this run"):
            PreflightAuthorization.from_document(replayed, self.route, "another-run:1")

        wrong_route = preflight_receipt(self.route)
        wrong_route["queue_route_sha256"] = "c" * 64
        with self.assertRaisesRegex(ValueError, "does not authorize this queue route"):
            PreflightAuthorization.from_document(
                wrong_route, self.route, AUTHORIZATION_ID
            )

    def test_rejects_missing_duplicate_or_unknown_checks(self) -> None:
        missing = preflight_receipt(self.route)
        missing["checks"].pop()
        with self.assertRaisesRegex(ValueError, "incomplete check set"):
            PreflightAuthorization.from_document(missing, self.route, AUTHORIZATION_ID)

        duplicate = preflight_receipt(self.route)
        duplicate["checks"][0]["name"] = duplicate["checks"][1]["name"]
        with self.assertRaisesRegex(ValueError, "check names"):
            PreflightAuthorization.from_document(
                duplicate, self.route, AUTHORIZATION_ID
            )


class RunRedriveCanaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.route = RedriveRoute.from_document(route_document())

    def test_exhausts_receive_policy_observes_dlq_and_deletes_only_match(self) -> None:
        aws = FakeAws(
            source_receives=[
                {"Messages": [source_message(1)]},
                {"Messages": [source_message(2)]},
                {},
            ],
            dlq_receives=[{}, {"Messages": [dlq_message()]}],
        )

        result = run_canary(
            self.route,
            aws,
            run_id=RUN_ID,
            sent_at=SENT_AT,
            preflight_sha256=PREFLIGHT_SHA256,
            dlq_receive_attempts=3,
            wait_seconds=1,
        )

        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["observed"]["source_receive_counts"], [1, 2])
        self.assertEqual(result["observed"]["dead_letter_receive_attempt"], 2)
        self.assertEqual(len(result["route_sha256"]), 64)
        self.assertEqual(result["preflight_sha256"], PREFLIGHT_SHA256)
        self.assertNotIn("route", result)
        deletes = [call for call in aws.calls if call[:2] == ("sqs", "delete-message")]
        self.assertEqual(len(deletes), 1)
        self.assertEqual(deletes[0][2]["queue_url"], DLQ_URL)
        self.assertEqual(deletes[0][2]["receipt_handle"], "dlq-receipt-1")
        resolved_names = [
            call[2]["queue_name"]
            for call in aws.calls
            if call[:2] == ("sqs", "get-queue-url")
        ]
        self.assertNotIn(PRODUCTION_ARN.rsplit(":", 1)[1], resolved_names)

    def test_rejects_unbounded_redrive_before_publishing(self) -> None:
        aws = FakeAws(queue_attributes=attributes("6"))

        with self.assertRaisesRegex(RuntimeError, "missing, unbounded or misrouted"):
            run_canary(
                self.route,
                aws,
                run_id=RUN_ID,
                sent_at=SENT_AT,
                preflight_sha256=PREFLIGHT_SHA256,
            )

        self.assertFalse(any(call[:2] == ("sqs", "send-message") for call in aws.calls))

    def test_rejects_dlq_that_admits_another_redrive_source(self) -> None:
        queue_attributes = attributes()
        queue_attributes[DLQ_URL]["RedriveAllowPolicy"] = json.dumps(
            {
                "redrivePermission": "byQueue",
                "sourceQueueArns": [FAULT_ARN, PRODUCTION_ARN],
            }
        )
        aws = FakeAws(queue_attributes=queue_attributes)

        with self.assertRaisesRegex(
            RuntimeError, "only from the dedicated fault queue"
        ):
            run_canary(
                self.route,
                aws,
                run_id=RUN_ID,
                sent_at=SENT_AT,
                preflight_sha256=PREFLIGHT_SHA256,
            )

        self.assertFalse(any(call[:2] == ("sqs", "send-message") for call in aws.calls))

    def test_rejects_nonempty_queue_before_publishing(self) -> None:
        queue_attributes = attributes()
        queue_attributes[FAULT_URL]["ApproximateNumberOfMessages"] = "1"
        aws = FakeAws(queue_attributes=queue_attributes)

        with self.assertRaisesRegex(RuntimeError, "must be empty"):
            run_canary(
                self.route,
                aws,
                run_id=RUN_ID,
                sent_at=SENT_AT,
                preflight_sha256=PREFLIGHT_SHA256,
            )

        self.assertFalse(any(call[:2] == ("sqs", "send-message") for call in aws.calls))

    def test_rejects_unrelated_source_message_without_deleting_it(self) -> None:
        aws = FakeAws(
            source_receives=[{"Messages": [source_message(1, body=payload("other"))]}]
        )

        with self.assertRaisesRegex(RuntimeError, "outside the isolated canary run"):
            run_canary(
                self.route,
                aws,
                run_id=RUN_ID,
                sent_at=SENT_AT,
                preflight_sha256=PREFLIGHT_SHA256,
            )

        self.assertFalse(
            any(call[:2] == ("sqs", "delete-message") for call in aws.calls)
        )

    def test_rejects_unrelated_dlq_message_without_deleting_it(self) -> None:
        aws = FakeAws(
            source_receives=[
                {"Messages": [source_message(1)]},
                {"Messages": [source_message(2)]},
                {},
            ],
            dlq_receives=[{"Messages": [dlq_message(body=payload("other"))]}],
        )

        with self.assertRaisesRegex(RuntimeError, "outside the isolated canary run"):
            run_canary(
                self.route,
                aws,
                run_id=RUN_ID,
                sent_at=SENT_AT,
                preflight_sha256=PREFLIGHT_SHA256,
                dlq_receive_attempts=1,
                wait_seconds=1,
            )

        deletes = [call for call in aws.calls if call[:2] == ("sqs", "delete-message")]
        self.assertEqual(len(deletes), 1)
        self.assertEqual(deletes[0][2]["queue_url"], FAULT_URL)

    def test_cleans_up_last_source_receipt_when_dlq_polling_times_out(self) -> None:
        aws = FakeAws(
            source_receives=[
                {"Messages": [source_message(1)]},
                {"Messages": [source_message(2)]},
                {},
            ],
            dlq_receives=[{}],
        )

        with self.assertRaisesRegex(
            RuntimeError, "not observed in the dead-letter queue"
        ):
            run_canary(
                self.route,
                aws,
                run_id=RUN_ID,
                sent_at=SENT_AT,
                preflight_sha256=PREFLIGHT_SHA256,
                dlq_receive_attempts=1,
                wait_seconds=1,
            )

        deletes = [call for call in aws.calls if call[:2] == ("sqs", "delete-message")]
        self.assertEqual(len(deletes), 1)
        self.assertEqual(deletes[0][2]["queue_url"], FAULT_URL)
        self.assertEqual(deletes[0][2]["receipt_handle"], "source-receipt-2")

    def test_rejects_unbounded_poll_configuration_before_aws_calls(self) -> None:
        aws = FakeAws()

        with self.assertRaisesRegex(ValueError, "dlq_receive_attempts"):
            run_canary(
                self.route,
                aws,
                run_id=RUN_ID,
                sent_at=SENT_AT,
                preflight_sha256=PREFLIGHT_SHA256,
                dlq_receive_attempts=11,
            )

        self.assertEqual(aws.calls, [])

    def test_rejects_invalid_preflight_commitment_before_aws_calls(self) -> None:
        aws = FakeAws()

        with self.assertRaisesRegex(ValueError, "preflight_sha256"):
            run_canary(
                self.route,
                aws,
                run_id=RUN_ID,
                sent_at=SENT_AT,
                preflight_sha256="not-a-digest",
            )

        self.assertEqual(aws.calls, [])


if __name__ == "__main__":
    unittest.main()
