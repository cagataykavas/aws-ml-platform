"""Fail-closed policy gate for Terraform plan JSON in the AWS ML platform."""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Violation:
    code: str
    address: str
    message: str


@dataclass(frozen=True)
class PolicyReport:
    passed: bool
    checked_resources: int
    violations: tuple[Violation, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "passed": self.passed,
            "checked_resources": self.checked_resources,
            "violations": [asdict(item) for item in self.violations],
        }


REQUIRED_TYPES = {
    "aws_s3_bucket_public_access_block",
    "aws_s3_bucket_server_side_encryption_configuration",
    "aws_s3_bucket_versioning",
    "aws_s3_bucket_ownership_controls",
    "aws_kms_key",
}


def evaluate_plan(plan: dict[str, Any]) -> PolicyReport:
    changes = plan.get("resource_changes")
    if not isinstance(changes, list):
        raise TypeError("plan must contain a resource_changes list")

    violations: list[Violation] = []
    present_types: set[str] = set()
    for change in changes:
        if not isinstance(change, dict):
            raise TypeError("each resource change must be an object")
        address = _required_string(change, "address")
        resource_type = _required_string(change, "type")
        present_types.add(resource_type)
        body = change.get("change")
        if not isinstance(body, dict) or not isinstance(body.get("actions"), list):
            raise TypeError(f"{address}: missing change.actions")
        actions = body["actions"]
        after = body.get("after")

        if "delete" in actions:
            violations.append(
                Violation("destructive_change", address, f"actions={actions}")
            )
        if after is None:
            continue
        if not isinstance(after, dict):
            raise TypeError(f"{address}: change.after must be an object or null")

        if resource_type == "aws_security_group":
            _check_security_group(address, after, violations)
        elif resource_type == "aws_s3_bucket_public_access_block":
            _require_true_fields(
                address,
                after,
                (
                    "block_public_acls",
                    "block_public_policy",
                    "ignore_public_acls",
                    "restrict_public_buckets",
                ),
                "s3_public_access_not_blocked",
                violations,
            )
        elif resource_type == "aws_s3_bucket_versioning":
            status = _nested_first(after, "versioning_configuration", "status")
            if status != "Enabled":
                violations.append(
                    Violation("s3_versioning_disabled", address, f"status={status!r}")
                )
        elif resource_type == "aws_s3_bucket_ownership_controls":
            ownership = _nested_first(after, "rule", "object_ownership")
            if ownership != "BucketOwnerEnforced":
                violations.append(
                    Violation(
                        "s3_ownership_not_enforced",
                        address,
                        f"object_ownership={ownership!r}",
                    )
                )
        elif resource_type == "aws_s3_bucket_server_side_encryption_configuration":
            algorithm = _nested_encryption_algorithm(after)
            if algorithm != "aws:kms":
                violations.append(
                    Violation(
                        "s3_kms_encryption_missing", address, f"algorithm={algorithm!r}"
                    )
                )
        elif (
            resource_type == "aws_kms_key"
            and after.get("enable_key_rotation") is not True
        ):
            violations.append(
                Violation(
                    "kms_rotation_disabled", address, "enable_key_rotation must be true"
                )
            )
        elif resource_type == "aws_iam_role_policy":
            _check_iam_policy(address, after.get("policy"), violations)

    for missing in sorted(REQUIRED_TYPES - present_types):
        violations.append(
            Violation(
                "required_control_missing", missing, "resource type absent from plan"
            )
        )
    ordered = tuple(
        sorted(violations, key=lambda item: (item.code, item.address, item.message))
    )
    return PolicyReport(not ordered, len(changes), ordered)


def _check_security_group(
    address: str, after: dict[str, Any], violations: list[Violation]
) -> None:
    ingress = after.get("ingress", [])
    if not isinstance(ingress, list):
        raise TypeError(f"{address}: ingress must be a list")
    for rule in ingress:
        if not isinstance(rule, dict):
            raise TypeError(f"{address}: ingress rule must be an object")
        cidrs = [*rule.get("cidr_blocks", []), *rule.get("ipv6_cidr_blocks", [])]
        if "0.0.0.0/0" in cidrs or "::/0" in cidrs:
            violations.append(
                Violation(
                    "public_security_group_ingress", address, "public IPv4/IPv6 ingress"
                )
            )


def _check_iam_policy(address: str, raw: Any, violations: list[Violation]) -> None:
    if not isinstance(raw, str):
        raise TypeError(f"{address}: IAM policy must be a rendered JSON string")
    try:
        policy = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{address}: malformed IAM policy JSON") from exc
    statements = policy.get("Statement")
    if not isinstance(statements, list):
        raise TypeError(f"{address}: IAM policy Statement must be a list")
    for statement in statements:
        if statement.get("Effect") != "Allow":
            continue
        actions = _as_list(statement.get("Action"))
        resources = _as_list(statement.get("Resource"))
        if any(value == "*" or value.endswith(":*") for value in actions):
            violations.append(
                Violation(
                    "iam_wildcard_action",
                    address,
                    "Allow statement has wildcard action",
                )
            )
        if "*" in resources:
            violations.append(
                Violation(
                    "iam_wildcard_resource",
                    address,
                    "Allow statement has wildcard resource",
                )
            )


def _require_true_fields(address, after, fields, code, violations):
    missing = [field for field in fields if after.get(field) is not True]
    if missing:
        violations.append(
            Violation(code, address, f"fields not true: {','.join(missing)}")
        )


def _nested_first(after: dict[str, Any], collection: str, field: str) -> Any:
    values = after.get(collection)
    return (
        values[0].get(field)
        if isinstance(values, list) and values and isinstance(values[0], dict)
        else None
    )


def _nested_encryption_algorithm(after: dict[str, Any]) -> Any:
    rules = after.get("rule")
    if not isinstance(rules, list) or not rules:
        return None
    defaults = rules[0].get("apply_server_side_encryption_by_default")
    return (
        defaults[0].get("sse_algorithm")
        if isinstance(defaults, list) and defaults
        else None
    )


def _as_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return value
    return []


def _required_string(value: dict[str, Any], key: str) -> str:
    result = value.get(key)
    if not isinstance(result, str) or not result:
        raise ValueError(f"resource change requires non-empty {key}")
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("plan", type=Path)
    args = parser.parse_args()
    try:
        payload = json.loads(args.plan.read_text(encoding="utf-8"))
        report = evaluate_plan(payload)
    except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
        print(json.dumps({"passed": False, "error": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    return 0 if report.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
