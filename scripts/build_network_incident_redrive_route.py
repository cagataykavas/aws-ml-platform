#!/usr/bin/env python3
"""Build a validated route document for the non-production redrive drill."""

from __future__ import annotations

import argparse
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any

try:
    from scripts.run_network_incident_redrive_canary import RedriveRoute
except ModuleNotFoundError:  # Direct execution from the scripts directory.
    from run_network_incident_redrive_canary import RedriveRoute


ACCOUNT_ID_PATTERN = re.compile(r"[0-9]{12}")
ROLE_ARN_PATTERN = re.compile(
    r"arn:(?P<partition>aws(?:-us-gov|-cn)?):iam::(?P<account>[0-9]{12}):role/"
    r"(?P<name>[A-Za-z0-9+=,.@_/-]{1,512})"
)


def build_route_document(
    *,
    production_queue_arn: str,
    fault_queue_arn: str,
    fault_dead_letter_queue_arn: str,
    redrive_canary_role_arn: str,
    expected_account_id: str,
    expected_region: str,
) -> dict[str, str]:
    """Validate protected Environment values before requesting AWS credentials."""

    if not ACCOUNT_ID_PATTERN.fullmatch(expected_account_id):
        raise ValueError("expected_account_id must be a 12-digit AWS account ID")
    if not expected_region or expected_region.strip() != expected_region:
        raise ValueError("expected_region must be a non-empty canonical Region name")

    document = {
        "production_queue_arn": production_queue_arn,
        "fault_queue_arn": fault_queue_arn,
        "fault_dead_letter_queue_arn": fault_dead_letter_queue_arn,
    }
    route = RedriveRoute.from_document(document)
    if route.account_id != expected_account_id:
        raise ValueError("configured redrive route does not belong to the expected AWS account")
    if route.region != expected_region:
        raise ValueError("configured redrive route does not belong to the expected AWS Region")
    role = ROLE_ARN_PATTERN.fullmatch(redrive_canary_role_arn)
    if role is None:
        raise ValueError("redrive_canary_role_arn must be a canonical IAM role ARN")
    if role["partition"] != route.partition or role["account"] != route.account_id:
        raise ValueError("redrive canary role must share the route partition and account")
    return document


def write_route_document(document: dict[str, Any], output: Path) -> None:
    """Atomically write deterministic route JSON with private file permissions."""

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
        description="Validate a dedicated non-production SQS redrive route."
    )
    parser.add_argument("--production-queue-arn", required=True)
    parser.add_argument("--fault-queue-arn", required=True)
    parser.add_argument("--fault-dead-letter-queue-arn", required=True)
    parser.add_argument("--redrive-canary-role-arn", required=True)
    parser.add_argument("--expected-account-id", required=True)
    parser.add_argument("--expected-region", required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        document = build_route_document(
            production_queue_arn=args.production_queue_arn,
            fault_queue_arn=args.fault_queue_arn,
            fault_dead_letter_queue_arn=args.fault_dead_letter_queue_arn,
            redrive_canary_role_arn=args.redrive_canary_role_arn,
            expected_account_id=args.expected_account_id,
            expected_region=args.expected_region,
        )
        write_route_document(document, args.output)
    except (OSError, ValueError) as exc:
        raise SystemExit(
            f"refusing invalid redrive-canary environment configuration: {exc}"
        ) from exc
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
