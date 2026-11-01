#!/usr/bin/env python3
"""Fail-closed admission policy for private Terraform plan JSON."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Any

PLAN_POLICY_SCHEMA = "terraform-plan-policy/v1"
PLAN_AUDIT_SCHEMA = "terraform-plan-audit/v1"
MAX_PLAN_BYTES = 25 * 1024 * 1024
MAX_POLICY_BYTES = 256 * 1024
MAX_RESOURCE_CHANGES = 10_000

_FORMAT_VERSION = re.compile(r"1\.[0-9]+")
_TERRAFORM_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?")
_VALID_ACTIONS = {
    ("no-op",),
    ("create",),
    ("read",),
    ("update",),
    ("delete",),
    ("delete", "create"),
    ("create", "delete"),
}
_DESTRUCTIVE_ACTIONS = {
    ("delete",),
    ("delete", "create"),
    ("create", "delete"),
}
_POLICY_KEYS = {
    "schema_version",
    "max_creates",
    "max_updates",
    "max_reads",
    "approved_destructive_changes",
    "approved_moves",
}


class PlanAuditError(ValueError):
    """The Terraform plan or its reviewed policy is malformed."""

    code = "TERRAFORM_PLAN_AUDIT_INVALID"

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(f"{self.code}: {reason}")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise PlanAuditError("JSON contains duplicate keys")
        result[key] = value
    return result


def _load_json(
    path: Path, *, max_bytes: int, label: str
) -> tuple[dict[str, Any], bytes]:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise PlanAuditError(f"cannot read {label}") from exc
    if not 1 <= size <= max_bytes:
        raise PlanAuditError(f"{label} size is outside the allowed range")
    try:
        raw = path.read_bytes()
        if not 1 <= len(raw) <= max_bytes:
            raise PlanAuditError(f"{label} size changed outside the allowed range")
        document = json.loads(raw, object_pairs_hook=_unique_object)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PlanAuditError(f"{label} is not valid JSON") from exc
    if not isinstance(document, dict):
        raise PlanAuditError(f"{label} must be a JSON object")
    return document, raw


def _bounded_integer(value: object, field: str) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not 0 <= value <= 10_000
    ):
        raise PlanAuditError(f"{field} must be an integer from 0 through 10000")
    return value


def _address(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 512
        or any(ord(character) < 32 or ord(character) > 126 for character in value)
    ):
        raise PlanAuditError(f"{field} must be a bounded printable Terraform address")
    return value


def _actions(value: object, field: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise PlanAuditError(f"{field} must be a supported action list")
    result = tuple(value)
    if result not in _VALID_ACTIONS:
        raise PlanAuditError(f"{field} must be a supported action list")
    return result


def _reason(value: object, field: str) -> str | None:
    if value is None:
        return None
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 128
        or any(ord(character) < 32 or ord(character) > 126 for character in value)
    ):
        raise PlanAuditError(f"{field} must be null or a bounded printable string")
    return value


def _parse_policy(document: dict[str, Any]) -> dict[str, Any]:
    unknown = set(document) - _POLICY_KEYS
    missing = _POLICY_KEYS - set(document)
    if unknown or missing:
        raise PlanAuditError("policy keys do not match the v1 schema")
    if document["schema_version"] != PLAN_POLICY_SCHEMA:
        raise PlanAuditError(f"policy schema_version must be {PLAN_POLICY_SCHEMA}")

    destructive = document["approved_destructive_changes"]
    if not isinstance(destructive, list) or len(destructive) > MAX_RESOURCE_CHANGES:
        raise PlanAuditError("approved_destructive_changes must be a bounded list")
    approved_destructive: list[tuple[str, tuple[str, ...], str | None]] = []
    for position, entry in enumerate(destructive):
        if not isinstance(entry, dict) or set(entry) != {
            "address",
            "actions",
            "action_reason",
        }:
            raise PlanAuditError(f"destructive approval {position} has invalid keys")
        actions = _actions(entry["actions"], f"destructive approval {position} actions")
        if actions not in _DESTRUCTIVE_ACTIONS:
            raise PlanAuditError(f"destructive approval {position} is not destructive")
        approved_destructive.append(
            (
                _address(entry["address"], f"destructive approval {position} address"),
                actions,
                _reason(
                    entry["action_reason"],
                    f"destructive approval {position} action_reason",
                ),
            )
        )
    approvals_are_unique = len(set(approved_destructive)) == len(approved_destructive)
    if approved_destructive != sorted(approved_destructive) or not approvals_are_unique:
        raise PlanAuditError("destructive approvals must be sorted and unique")

    moves = document["approved_moves"]
    if not isinstance(moves, list) or len(moves) > MAX_RESOURCE_CHANGES:
        raise PlanAuditError("approved_moves must be a bounded list")
    approved_moves: list[tuple[str, str]] = []
    for position, entry in enumerate(moves):
        if not isinstance(entry, dict) or set(entry) != {"previous_address", "address"}:
            raise PlanAuditError(f"move approval {position} has invalid keys")
        previous = _address(
            entry["previous_address"], f"move approval {position} previous_address"
        )
        current = _address(entry["address"], f"move approval {position} address")
        if previous == current:
            raise PlanAuditError(f"move approval {position} must change the address")
        approved_moves.append((previous, current))
    if approved_moves != sorted(approved_moves) or len(set(approved_moves)) != len(
        approved_moves
    ):
        raise PlanAuditError("move approvals must be sorted and unique")

    return {
        "max_creates": _bounded_integer(document["max_creates"], "max_creates"),
        "max_updates": _bounded_integer(document["max_updates"], "max_updates"),
        "max_reads": _bounded_integer(document["max_reads"], "max_reads"),
        "approved_destructive": set(approved_destructive),
        "approved_moves": set(approved_moves),
    }


def audit_plan(
    plan: dict[str, Any], policy: dict[str, Any], plan_sha256: str
) -> dict[str, Any]:
    """Return a privacy-reduced plan admission report."""

    format_version = plan.get("format_version")
    terraform_version = plan.get("terraform_version")
    if (
        not isinstance(format_version, str)
        or _FORMAT_VERSION.fullmatch(format_version) is None
    ):
        raise PlanAuditError("plan format_version must use supported major version 1")
    if (
        not isinstance(terraform_version, str)
        or _TERRAFORM_VERSION.fullmatch(terraform_version) is None
    ):
        raise PlanAuditError("plan terraform_version is invalid")
    for field in ("applyable", "complete", "errored"):
        if not isinstance(plan.get(field), bool):
            raise PlanAuditError(f"plan {field} must be a boolean")
    changes = plan.get("resource_changes")
    if not isinstance(changes, list) or len(changes) > MAX_RESOURCE_CHANGES:
        raise PlanAuditError("plan resource_changes must be a bounded list")

    counts = {
        "no-op": 0,
        "create": 0,
        "read": 0,
        "update": 0,
        "delete": 0,
        "replace": 0,
    }
    destructive: list[tuple[str, tuple[str, ...], str | None]] = []
    moves: list[tuple[str, str]] = []
    seen: set[tuple[str, str | None]] = set()
    deposed_addresses: list[str] = []
    for position, entry in enumerate(changes):
        if not isinstance(entry, dict):
            raise PlanAuditError(f"resource change {position} must be an object")
        address = _address(entry.get("address"), f"resource change {position} address")
        deposed = entry.get("deposed")
        if deposed is not None:
            deposed = _address(deposed, f"resource change {position} deposed key")
            deposed_addresses.append(address)
        identity = (address, deposed)
        if identity in seen:
            raise PlanAuditError("plan contains duplicate resource-change identities")
        seen.add(identity)

        change = entry.get("change")
        if not isinstance(change, dict):
            raise PlanAuditError(f"resource change {position} change must be an object")
        actions = _actions(change.get("actions"), f"resource change {position} actions")
        reason = _reason(
            entry.get("action_reason"), f"resource change {position} action_reason"
        )
        if actions == ("no-op",):
            counts["no-op"] += 1
        elif actions == ("create",):
            counts["create"] += 1
        elif actions == ("read",):
            counts["read"] += 1
        elif actions == ("update",):
            counts["update"] += 1
        elif actions == ("delete",):
            counts["delete"] += 1
            destructive.append((address, actions, reason))
        else:
            counts["replace"] += 1
            destructive.append((address, actions, reason))

        previous = entry.get("previous_address")
        if previous is not None:
            previous_address = _address(
                previous, f"resource change {position} previous_address"
            )
            if previous_address == address:
                raise PlanAuditError(
                    f"resource change {position} has a redundant previous_address"
                )
            moves.append((previous_address, address))

    destructive.sort()
    moves.sort()
    findings: list[str] = []
    actionable = len(changes) - counts["no-op"] - counts["read"]
    if plan["errored"]:
        findings.append("plan_errored")
    if not plan["complete"]:
        findings.append("plan_incomplete")
    if actionable and not plan["applyable"]:
        findings.append("plan_not_applyable")
    if counts["create"] > policy["max_creates"]:
        findings.append("create_budget_exceeded")
    if counts["update"] > policy["max_updates"]:
        findings.append("update_budget_exceeded")
    if counts["read"] > policy["max_reads"]:
        findings.append("read_budget_exceeded")
    if deposed_addresses:
        findings.append("deposed_objects_present")

    observed_destructive = set(destructive)
    observed_moves = set(moves)
    if observed_destructive - policy["approved_destructive"]:
        findings.append("unapproved_destructive_change")
    if policy["approved_destructive"] - observed_destructive:
        findings.append("approved_destructive_change_not_observed")
    if observed_moves - policy["approved_moves"]:
        findings.append("unapproved_move")
    if policy["approved_moves"] - observed_moves:
        findings.append("approved_move_not_observed")

    return {
        "schema_version": PLAN_AUDIT_SCHEMA,
        "accepted": not findings,
        "finding_codes": findings,
        "plan_sha256": plan_sha256,
        "format_version": format_version,
        "terraform_version": terraform_version,
        "summary": counts,
        "destructive_changes": [
            {"address": address, "actions": list(actions), "action_reason": reason}
            for address, actions, reason in destructive
        ],
        "moves": [
            {"previous_address": previous, "address": address}
            for previous, address in moves
        ],
        "deposed_addresses": sorted(deposed_addresses),
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Audit private `terraform show -json` output without echoing plan values."
    )
    parser.add_argument("plan", type=Path)
    parser.add_argument("policy", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        if args.output is not None and args.output.resolve() in {
            args.plan.resolve(),
            args.policy.resolve(),
        }:
            raise PlanAuditError("output must not replace the private plan or policy")
        plan, raw_plan = _load_json(args.plan, max_bytes=MAX_PLAN_BYTES, label="plan")
        policy_document, raw_policy = _load_json(
            args.policy, max_bytes=MAX_POLICY_BYTES, label="policy"
        )
        report = audit_plan(
            plan,
            _parse_policy(policy_document),
            hashlib.sha256(raw_plan).hexdigest(),
        )
        report["policy_sha256"] = hashlib.sha256(raw_policy).hexdigest()
        payload = json.dumps(report, allow_nan=False, indent=2, sort_keys=True) + "\n"
        if args.output is None:
            print(payload, end="")
        else:
            temporary_path: Path | None = None
            try:
                with tempfile.NamedTemporaryFile(
                    mode="w",
                    encoding="utf-8",
                    dir=args.output.parent,
                    prefix=f".{args.output.name}.",
                    suffix=".tmp",
                    delete=False,
                ) as temporary:
                    temporary.write(payload)
                    temporary.flush()
                    os.fsync(temporary.fileno())
                    temporary_path = Path(temporary.name)
                temporary_path.replace(args.output)
            finally:
                if temporary_path is not None:
                    temporary_path.unlink(missing_ok=True)
        return 0 if report["accepted"] else 2
    except (OSError, PlanAuditError) as exc:
        print(f"terraform plan audit failed: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
