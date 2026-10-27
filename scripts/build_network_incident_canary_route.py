#!/usr/bin/env python3
"""Build a validated route document for the live incident-delivery canary."""

from __future__ import annotations

import argparse
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any

try:
    from scripts.run_network_incident_delivery_canary import CanaryRoute
    from scripts.verify_network_incident_route import _parse_arn
except ModuleNotFoundError:  # Direct execution from the scripts directory.
    from run_network_incident_delivery_canary import CanaryRoute
    from verify_network_incident_route import _parse_arn


ACCOUNT_ID_PATTERN = re.compile(r"[0-9]{12}")


def build_route_document(
    *,
    topic_arn: str,
    queue_arn: str,
    dead_letter_queue_arn: str,
    delivery_canary_queue_arn: str,
    expected_account_id: str,
    expected_region: str,
) -> dict[str, str]:
    """Validate environment configuration and return the canary route document."""

    if not ACCOUNT_ID_PATTERN.fullmatch(expected_account_id):
        raise ValueError("expected_account_id must be a 12-digit AWS account ID")
    if not expected_region or expected_region.strip() != expected_region:
        raise ValueError("expected_region must be a non-empty canonical Region name")

    document = {
        "topic_arn": topic_arn,
        "queue_arn": queue_arn,
        "dead_letter_queue_arn": dead_letter_queue_arn,
        "delivery_canary_queue_arn": delivery_canary_queue_arn,
    }
    route = CanaryRoute.from_document(document)
    if route.account_id != expected_account_id:
        raise ValueError("configured route does not belong to the expected AWS account")
    if route.region != expected_region:
        raise ValueError("configured route does not belong to the expected AWS Region")

    protected_arns = (queue_arn, dead_letter_queue_arn)
    if len(set(protected_arns)) != len(protected_arns):
        raise ValueError("incident and dead-letter queues must be distinct")
    for label, arn in (
        ("queue_arn", queue_arn),
        ("dead_letter_queue_arn", dead_letter_queue_arn),
    ):
        parsed = _parse_arn(arn, expected_service="sqs")
        if (parsed[0], parsed[2], parsed[3]) != (
            route.partition,
            route.region,
            route.account_id,
        ):
            raise ValueError(
                f"{label} must share partition, Region and account with the topic"
            )
    return document


def write_route_document(document: dict[str, Any], output: Path) -> None:
    """Atomically write a private, deterministic JSON route document."""

    output.parent.mkdir(parents=True, exist_ok=True)
    file_descriptor, temporary_name = tempfile.mkstemp(
        dir=output.parent,
        prefix=f".{output.name}.",
        suffix=".tmp",
        text=True,
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(file_descriptor, "w", encoding="utf-8") as handle:
            json.dump(document, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.chmod(temporary_path, 0o600)
        temporary_path.replace(output)
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate GitHub Environment values and write a canary route JSON file."
    )
    parser.add_argument("--topic-arn", required=True)
    parser.add_argument("--queue-arn", required=True)
    parser.add_argument("--dead-letter-queue-arn", required=True)
    parser.add_argument("--delivery-canary-queue-arn", required=True)
    parser.add_argument("--expected-account-id", required=True)
    parser.add_argument("--expected-region", required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        document = build_route_document(
            topic_arn=args.topic_arn,
            queue_arn=args.queue_arn,
            dead_letter_queue_arn=args.dead_letter_queue_arn,
            delivery_canary_queue_arn=args.delivery_canary_queue_arn,
            expected_account_id=args.expected_account_id,
            expected_region=args.expected_region,
        )
        write_route_document(document, args.output)
    except (OSError, ValueError) as exc:
        raise SystemExit(
            f"refusing invalid canary environment configuration: {exc}"
        ) from exc
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
