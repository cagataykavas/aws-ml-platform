from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "apply_bound_terraform_plan.py"
AUDIT_SCRIPT = ROOT / "scripts" / "audit_terraform_plan.py"
SPEC = importlib.util.spec_from_file_location("audit_terraform_plan", AUDIT_SCRIPT)
assert SPEC and SPEC.loader
AUDIT = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = AUDIT
SPEC.loader.exec_module(AUDIT)

COMMIT = "a" * 40


def _plan(value: str = "reviewed") -> dict[str, object]:
    return {
        "format_version": "1.2",
        "terraform_version": "1.9.8",
        "applyable": True,
        "complete": True,
        "errored": False,
        "resource_changes": [
            {
                "address": "aws_s3_bucket.logs",
                "mode": "managed",
                "type": "aws_s3_bucket",
                "name": "logs",
                "change": {
                    "actions": ["update"],
                    "before": {"private": value},
                    "after": {"private": f"{value}-new"},
                },
            }
        ],
    }


def _policy(max_updates: int = 1) -> dict[str, object]:
    return {
        "schema_version": AUDIT.PLAN_POLICY_SCHEMA,
        "max_creates": 0,
        "max_updates": max_updates,
        "max_reads": 0,
        "approved_destructive_changes": [],
        "approved_moves": [],
    }


FAKE_TERRAFORM = """#!/usr/bin/env python3
import os
from pathlib import Path
import sys

command = sys.argv[1]
if command == "show":
    if os.environ.get("FAKE_SHOW_FAILURE") == "1":
        raise SystemExit(9)
    sys.stdout.buffer.write(Path(os.environ["FAKE_PLAN_JSON"]).read_bytes())
    raise SystemExit(0)
if command == "apply":
    plan = Path(sys.argv[-1]).read_bytes()
    Path(os.environ["FAKE_APPLIED_PLAN"]).write_bytes(plan)
    raise SystemExit(int(os.environ.get("FAKE_APPLY_EXIT", "0")))
raise SystemExit(8)
"""


class BoundTerraformApplyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.working = self.root / "infra"
        self.working.mkdir()
        self.binary = self.root / "tfplan"
        self.binary.write_bytes(b"private-saved-plan\x00bytes")
        self.policy = self.root / "policy.json"
        self.raw_policy = json.dumps(_policy(), separators=(",", ":")).encode()
        self.policy.write_bytes(self.raw_policy)
        self.plan_json = self.root / "plan.json"
        self.raw_plan = json.dumps(_plan(), separators=(",", ":")).encode()
        self.plan_json.write_bytes(self.raw_plan)
        self.report = self.root / "audit.json"
        self.audit = AUDIT.audit_payloads(self.raw_plan, self.raw_policy)
        self.report.write_text(json.dumps(self.audit, sort_keys=True), encoding="utf-8")
        self.fake = self.root / "terraform"
        self.fake.write_text(FAKE_TERRAFORM, encoding="utf-8")
        self.fake.chmod(0o700)
        self.applied = self.root / "applied-plan"
        self.receipt = self.root / "receipt.json"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _run(
        self,
        *,
        expected_plan: str | None = None,
        expected_policy: str | None = None,
        expected_commit: str = COMMIT,
        actual_commit: str = COMMIT,
        extra_environment: dict[str, str] | None = None,
        binary: Path | None = None,
        report: Path | None = None,
        policy: Path | None = None,
        output: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        environment = {
            **os.environ,
            "FAKE_PLAN_JSON": str(self.plan_json),
            "FAKE_APPLIED_PLAN": str(self.applied),
            **(extra_environment or {}),
        }
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                str(binary or self.binary),
                str(policy or self.policy),
                str(report or self.report),
                "--expected-plan-sha256",
                expected_plan or self.audit["plan_sha256"],
                "--expected-policy-sha256",
                expected_policy or self.audit["policy_sha256"],
                "--expected-commit-sha",
                expected_commit,
                "--actual-commit-sha",
                actual_commit,
                "--working-directory",
                str(self.working),
                "--terraform",
                str(self.fake),
                "--timeout-seconds",
                "10",
                "--output",
                str(output or self.receipt),
            ],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )

    def test_applies_the_exact_sealed_plan_and_emits_reduced_receipt(self) -> None:
        result = self._run()
        receipt = json.loads(self.receipt.read_text(encoding="utf-8"))

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.applied.read_bytes(), self.binary.read_bytes())
        self.assertEqual(receipt["schema_version"], "terraform-apply-binding/v1")
        self.assertEqual(receipt["status"], "applied")
        self.assertEqual(receipt["commit_sha"], COMMIT)
        self.assertEqual(
            receipt["plan_binary_sha256"],
            hashlib.sha256(self.binary.read_bytes()).hexdigest(),
        )
        self.assertEqual(receipt["plan_sha256"], self.audit["plan_sha256"])
        self.assertNotIn("private-saved-plan", str(receipt))
        self.assertNotIn("aws_s3_bucket.logs", str(receipt))

    def test_rejects_replanned_json_drift_before_apply(self) -> None:
        self.plan_json.write_text(json.dumps(_plan("drifted")), encoding="utf-8")

        result = self._run()

        self.assertEqual(result.returncode, 3)
        self.assertIn("does not match the reviewed report", result.stderr)
        self.assertFalse(self.applied.exists())
        self.assertFalse(self.receipt.exists())

    def test_rejects_tampered_audit_report_before_apply(self) -> None:
        tampered = dict(self.audit)
        tampered["terraform_version"] = "1.10.0"
        self.report.write_text(json.dumps(tampered), encoding="utf-8")

        result = self._run()

        self.assertEqual(result.returncode, 3)
        self.assertIn("does not match the reviewed report", result.stderr)
        self.assertFalse(self.applied.exists())

    def test_rejects_changed_policy_and_stale_approved_digests(self) -> None:
        stale_policy_digest = self.audit["policy_sha256"]
        self.policy.write_text(json.dumps(_policy(max_updates=2)), encoding="utf-8")
        result = self._run(expected_policy=stale_policy_digest)

        self.assertEqual(result.returncode, 3)
        self.assertIn("does not match the reviewed report", result.stderr)
        self.assertFalse(self.applied.exists())

        self.policy.write_bytes(self.raw_policy)
        result = self._run(expected_plan="0" * 64)
        self.assertEqual(result.returncode, 3)
        self.assertIn("approved digest", result.stderr)
        self.assertFalse(self.applied.exists())

    def test_rejects_commit_substitution_before_terraform_execution(self) -> None:
        result = self._run(actual_commit="b" * 40)

        self.assertEqual(result.returncode, 3)
        self.assertIn("checked-out commit", result.stderr)
        self.assertFalse(self.applied.exists())

    def test_rejects_symlinked_plan_source(self) -> None:
        link = self.root / "linked-plan"
        link.symlink_to(self.binary)

        result = self._run(binary=link)

        self.assertEqual(result.returncode, 3)
        self.assertIn("without following links", result.stderr)
        self.assertFalse(self.applied.exists())

    def test_apply_failure_has_distinct_exit_and_no_success_receipt(self) -> None:
        result = self._run(extra_environment={"FAKE_APPLY_EXIT": "7"})

        self.assertEqual(result.returncode, 4)
        self.assertIn("apply returned non-zero", result.stderr)
        self.assertTrue(self.applied.exists())
        self.assertFalse(self.receipt.exists())

    def test_show_failure_is_sanitized_and_never_applies(self) -> None:
        result = self._run(extra_environment={"FAKE_SHOW_FAILURE": "1"})

        self.assertEqual(result.returncode, 3)
        self.assertIn("show rejected", result.stderr)
        self.assertNotIn(str(self.binary), result.stderr)
        self.assertFalse(self.applied.exists())

    def test_rejects_output_alias_and_duplicate_key_report(self) -> None:
        alias = self._run(output=self.report)
        self.assertEqual(alias.returncode, 3)
        self.assertIn("paths must be distinct", alias.stderr)

        duplicate = self.root / "duplicate-audit.json"
        duplicate.write_text(
            '{"schema_version":"x","schema_version":"y"}', encoding="utf-8"
        )
        result = self._run(report=duplicate)
        self.assertEqual(result.returncode, 3)
        self.assertIn("duplicate keys", result.stderr)
        self.assertFalse(self.applied.exists())

    def test_rejects_noncanonical_or_unbounded_control_inputs(self) -> None:
        invalid_digest = self._run(expected_plan="ABC")
        invalid_timeout = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                str(self.binary),
                str(self.policy),
                str(self.report),
                "--expected-plan-sha256",
                self.audit["plan_sha256"],
                "--expected-policy-sha256",
                self.audit["policy_sha256"],
                "--expected-commit-sha",
                COMMIT,
                "--actual-commit-sha",
                COMMIT,
                "--terraform",
                str(self.fake),
                "--timeout-seconds",
                "0",
                "--output",
                str(self.receipt),
            ],
            check=False,
            capture_output=True,
            text=True,
        )

        self.assertEqual(invalid_digest.returncode, 3)
        self.assertIn("not canonical", invalid_digest.stderr)
        self.assertEqual(invalid_timeout.returncode, 3)
        self.assertIn("timeout_seconds", invalid_timeout.stderr)


if __name__ == "__main__":
    unittest.main()
