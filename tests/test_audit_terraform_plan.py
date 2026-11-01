from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "audit_terraform_plan.py"
SPEC = importlib.util.spec_from_file_location("audit_terraform_plan", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def _change(
    address: str,
    actions: list[str],
    *,
    reason: str | None = None,
    previous_address: str | None = None,
    deposed: str | None = None,
) -> dict[str, object]:
    result: dict[str, object] = {
        "address": address,
        "mode": "managed",
        "type": address.split(".")[0],
        "name": address.split(".")[-1],
        "change": {"actions": actions, "before": {}, "after": {}},
    }
    if reason is not None:
        result["action_reason"] = reason
    if previous_address is not None:
        result["previous_address"] = previous_address
    if deposed is not None:
        result["deposed"] = deposed
    return result


def _plan(*changes: dict[str, object], **overrides: object) -> dict[str, object]:
    result: dict[str, object] = {
        "format_version": "1.2",
        "terraform_version": "1.9.8",
        "applyable": bool(changes),
        "complete": True,
        "errored": False,
        "resource_changes": list(changes),
        "variables": {"private_token": {"value": "must-not-leak"}},
    }
    result.update(overrides)
    return result


def _policy(**overrides: object) -> dict[str, object]:
    result: dict[str, object] = {
        "schema_version": MODULE.PLAN_POLICY_SCHEMA,
        "max_creates": 2,
        "max_updates": 2,
        "max_reads": 2,
        "approved_destructive_changes": [],
        "approved_moves": [],
    }
    result.update(overrides)
    return result


class TerraformPlanAuditTests(unittest.TestCase):
    def _run(
        self, plan: dict[str, object] | str, policy: dict[str, object] | str
    ) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan_path = root / "plan.json"
            policy_path = root / "policy.json"
            plan_path.write_text(
                plan if isinstance(plan, str) else json.dumps(plan),
                encoding="utf-8",
            )
            policy_path.write_text(
                policy if isinstance(policy, str) else json.dumps(policy),
                encoding="utf-8",
            )
            return subprocess.run(
                [sys.executable, str(SCRIPT), str(plan_path), str(policy_path)],
                check=False,
                capture_output=True,
                text=True,
            )

    def test_accepts_bounded_non_destructive_plan_without_echoing_values(self) -> None:
        plan = _plan(
            _change("aws_s3_bucket.logs", ["create"]),
            _change("aws_cloudwatch_log_group.flow", ["update"]),
            _change("data.aws_caller_identity.current", ["read"]),
        )
        result = self._run(plan, _policy())
        report = json.loads(result.stdout)

        self.assertEqual(result.returncode, 0)
        self.assertTrue(report["accepted"])
        self.assertEqual(report["summary"]["create"], 1)
        self.assertEqual(report["summary"]["update"], 1)
        self.assertNotIn("must-not-leak", result.stdout)
        self.assertEqual(
            report["plan_sha256"],
            hashlib.sha256(json.dumps(plan).encode()).hexdigest(),
        )
        self.assertRegex(report["policy_sha256"], r"^[0-9a-f]{64}$")

    def test_accepts_no_change_plan_that_is_not_applyable(self) -> None:
        result = self._run(_plan(), _policy())

        self.assertEqual(result.returncode, 0)
        self.assertTrue(json.loads(result.stdout)["accepted"])

    def test_rejects_unapproved_delete_and_replacement(self) -> None:
        plan = _plan(
            _change(
                "aws_s3_bucket.old",
                ["delete"],
                reason="delete_because_no_resource_config",
            ),
            _change(
                "aws_iam_role.runner",
                ["delete", "create"],
                reason="replace_because_cannot_update",
            ),
        )
        result = self._run(plan, _policy())
        report = json.loads(result.stdout)

        self.assertEqual(result.returncode, 2)
        self.assertEqual(report["finding_codes"], ["unapproved_destructive_change"])
        self.assertEqual(len(report["destructive_changes"]), 2)

    def test_exact_one_shot_destructive_approval_passes(self) -> None:
        plan = _plan(
            _change(
                "aws_iam_role.runner",
                ["create", "delete"],
                reason="replace_because_cannot_update",
            )
        )
        approval = {
            "address": "aws_iam_role.runner",
            "actions": ["create", "delete"],
            "action_reason": "replace_because_cannot_update",
        }

        result = self._run(plan, _policy(approved_destructive_changes=[approval]))

        self.assertEqual(result.returncode, 0)
        self.assertTrue(json.loads(result.stdout)["accepted"])

    def test_stale_or_mismatched_destructive_approval_fails(self) -> None:
        approval = {
            "address": "aws_iam_role.runner",
            "actions": ["delete", "create"],
            "action_reason": "replace_because_cannot_update",
        }
        result = self._run(
            _plan(_change("aws_iam_role.runner", ["update"])),
            _policy(approved_destructive_changes=[approval]),
        )

        self.assertEqual(result.returncode, 2)
        self.assertIn(
            "approved_destructive_change_not_observed",
            json.loads(result.stdout)["finding_codes"],
        )

    def test_moves_require_exact_source_and_destination(self) -> None:
        plan = _plan(
            _change(
                "module.current.aws_s3_bucket.logs",
                ["no-op"],
                previous_address="module.old.aws_s3_bucket.logs",
            )
        )
        rejected = self._run(plan, _policy())
        accepted = self._run(
            plan,
            _policy(
                approved_moves=[
                    {
                        "previous_address": "module.old.aws_s3_bucket.logs",
                        "address": "module.current.aws_s3_bucket.logs",
                    }
                ]
            ),
        )

        self.assertEqual(rejected.returncode, 2)
        self.assertEqual(
            json.loads(rejected.stdout)["finding_codes"], ["unapproved_move"]
        )
        self.assertEqual(accepted.returncode, 0)

    def test_enforces_create_update_and_read_budgets(self) -> None:
        plan = _plan(
            _change("aws_s3_bucket.one", ["create"]),
            _change("aws_s3_bucket.two", ["create"]),
            _change("aws_s3_bucket.three", ["create"]),
            _change("aws_iam_role.one", ["update"]),
            _change("data.aws_region.one", ["read"]),
        )
        result = self._run(plan, _policy(max_creates=2, max_updates=0, max_reads=0))

        self.assertEqual(
            json.loads(result.stdout)["finding_codes"],
            [
                "create_budget_exceeded",
                "update_budget_exceeded",
                "read_budget_exceeded",
            ],
        )

    def test_rejects_errored_incomplete_and_non_applyable_action_plan(self) -> None:
        plan = _plan(
            _change("aws_s3_bucket.logs", ["create"]),
            errored=True,
            complete=False,
            applyable=False,
        )
        result = self._run(plan, _policy())

        self.assertEqual(
            json.loads(result.stdout)["finding_codes"],
            ["plan_errored", "plan_incomplete", "plan_not_applyable"],
        )

    def test_rejects_deposed_objects_even_when_delete_is_approved(self) -> None:
        plan = _plan(_change("aws_instance.worker", ["delete"], deposed="deadbeef"))
        approval = {
            "address": "aws_instance.worker",
            "actions": ["delete"],
            "action_reason": None,
        }
        result = self._run(plan, _policy(approved_destructive_changes=[approval]))

        self.assertEqual(
            json.loads(result.stdout)["finding_codes"], ["deposed_objects_present"]
        )

    def test_rejects_unsupported_format_actions_and_duplicate_change_identity(
        self,
    ) -> None:
        invalid_format = self._run(_plan(format_version="2.0"), _policy())
        invalid_action = self._run(
            _plan(_change("aws_s3_bucket.logs", ["forget"])), _policy()
        )
        duplicate = self._run(
            _plan(
                _change("aws_s3_bucket.logs", ["no-op"]),
                _change("aws_s3_bucket.logs", ["no-op"]),
            ),
            _policy(),
        )

        self.assertEqual(invalid_format.returncode, 3)
        self.assertIn("supported major version 1", invalid_format.stderr)
        self.assertEqual(invalid_action.returncode, 3)
        self.assertIn("supported action list", invalid_action.stderr)
        self.assertEqual(duplicate.returncode, 3)
        self.assertIn("duplicate resource-change identities", duplicate.stderr)

    def test_policy_requires_canonical_exact_approvals(self) -> None:
        first = {
            "address": "aws_s3_bucket.z",
            "actions": ["delete"],
            "action_reason": None,
        }
        second = {
            "address": "aws_s3_bucket.a",
            "actions": ["delete"],
            "action_reason": None,
        }
        unsorted = self._run(
            _plan(), _policy(approved_destructive_changes=[first, second])
        )
        wildcard = self._run(
            _plan(),
            _policy(
                approved_destructive_changes=[
                    {"address": "*", "actions": ["update"], "action_reason": None}
                ]
            ),
        )

        self.assertEqual(unsorted.returncode, 3)
        self.assertIn("sorted and unique", unsorted.stderr)
        self.assertEqual(wildcard.returncode, 3)
        self.assertIn("is not destructive", wildcard.stderr)

    def test_rejects_duplicate_json_keys_without_echoing_private_values(self) -> None:
        duplicate_plan = (
            '{"format_version":"1.2","format_version":"1.2","private":"must-not-leak"}'
        )
        result = self._run(duplicate_plan, _policy())

        self.assertEqual(result.returncode, 3)
        self.assertIn("duplicate keys", result.stderr)
        self.assertNotIn("must-not-leak", result.stderr)

    def test_refuses_to_replace_private_input_with_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            plan_path = Path(directory) / "plan.json"
            policy_path = Path(directory) / "policy.json"
            plan_path.write_text(json.dumps(_plan()), encoding="utf-8")
            policy_path.write_text(json.dumps(_policy()), encoding="utf-8")
            original = plan_path.read_bytes()

            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    str(plan_path),
                    str(policy_path),
                    "--output",
                    str(plan_path),
                ],
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertEqual(result.returncode, 3)
            self.assertIn("must not replace", result.stderr)
            self.assertEqual(plan_path.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
