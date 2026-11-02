#!/usr/bin/env python3
"""Apply an immutable saved Terraform plan only after exact evidence rebinding."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import hmac
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from audit_terraform_plan import (
    MAX_PLAN_BYTES,
    MAX_POLICY_BYTES,
    PLAN_AUDIT_SCHEMA,
    PlanAuditError,
    _load_json_bytes,
    audit_payloads,
)

APPLY_BINDING_SCHEMA = "terraform-apply-binding/v1"
MAX_PLAN_BINARY_BYTES = 100 * 1024 * 1024
MAX_AUDIT_BYTES = 2 * 1024 * 1024
_DIGEST = re.compile(r"[0-9a-f]{64}")
_COMMIT = re.compile(r"[0-9a-f]{40}")
_F_ADD_SEALS = getattr(fcntl, "F_ADD_SEALS", 1033)
_F_SEAL_SEAL = getattr(fcntl, "F_SEAL_SEAL", 0x0001)
_F_SEAL_SHRINK = getattr(fcntl, "F_SEAL_SHRINK", 0x0002)
_F_SEAL_GROW = getattr(fcntl, "F_SEAL_GROW", 0x0004)
_F_SEAL_WRITE = getattr(fcntl, "F_SEAL_WRITE", 0x0008)


class ApplyBindingError(ValueError):
    """The reviewed evidence does not bind the plan selected for apply."""

    code = "TERRAFORM_APPLY_BINDING_INVALID"

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(f"{self.code}: {reason}")


def _canonical_digest(value: object) -> str:
    payload = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def _expected(value: str, pattern: re.Pattern[str], field: str) -> str:
    if pattern.fullmatch(value) is None:
        raise ApplyBindingError(f"{field} is not canonical")
    return value


def _read_bounded(path: Path, maximum: int, label: str) -> bytes:
    try:
        size = path.stat().st_size
        if not 1 <= size <= maximum:
            raise ApplyBindingError(f"{label} size is outside the allowed range")
        raw = path.read_bytes()
    except OSError as exc:
        raise ApplyBindingError(f"cannot read {label}") from exc
    if len(raw) != size:
        raise ApplyBindingError(f"{label} changed while being read")
    return raw


def _sealed_plan(path: Path) -> tuple[int, str]:
    if not hasattr(os, "memfd_create") or not Path("/proc/self/fd").is_dir():
        raise ApplyBindingError("sealed in-memory plan descriptors are unavailable")
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        source = os.open(path, flags)
    except OSError as exc:
        raise ApplyBindingError(
            "cannot open plan binary without following links"
        ) from exc
    descriptor = -1
    try:
        metadata = os.fstat(source)
        if not stat.S_ISREG(metadata.st_mode):
            raise ApplyBindingError("plan binary must be a regular file")
        if not 1 <= metadata.st_size <= MAX_PLAN_BINARY_BYTES:
            raise ApplyBindingError("plan binary size is outside the allowed range")
        descriptor = os.memfd_create(
            "terraform-plan",
            flags=os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING,
        )
        digest = hashlib.sha256()
        copied = 0
        while chunk := os.read(source, 1024 * 1024):
            copied += len(chunk)
            if copied > MAX_PLAN_BINARY_BYTES:
                raise ApplyBindingError("plan binary grew outside the allowed range")
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise ApplyBindingError("cannot copy plan into sealed memory")
                view = view[written:]
        if copied != metadata.st_size:
            raise ApplyBindingError("plan binary changed while being copied")
        seals = _F_SEAL_WRITE | _F_SEAL_GROW | _F_SEAL_SHRINK | _F_SEAL_SEAL
        fcntl.fcntl(descriptor, _F_ADD_SEALS, seals)
        os.lseek(descriptor, 0, os.SEEK_SET)
        return descriptor, digest.hexdigest()
    except Exception:
        if descriptor >= 0:
            os.close(descriptor)
        raise
    finally:
        os.close(source)


def _terraform_executable(value: str) -> Path:
    resolved = shutil.which(value)
    if resolved is None:
        raise ApplyBindingError("terraform executable was not found")
    path = Path(resolved).resolve()
    try:
        if not path.is_file():
            raise ApplyBindingError("terraform executable is not a regular file")
    except OSError as exc:
        raise ApplyBindingError("cannot inspect terraform executable") from exc
    return path


def _terraform_show(
    executable: Path,
    descriptor: int,
    working_directory: Path,
    timeout_seconds: int,
) -> bytes:
    command = [str(executable), "show", "-json", f"/proc/self/fd/{descriptor}"]
    try:
        process = subprocess.Popen(
            command,
            cwd=working_directory,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            pass_fds=(descriptor,),
        )
        output, _ = process.communicate(timeout=timeout_seconds)
    except subprocess.TimeoutExpired as exc:
        process.kill()
        process.communicate()
        raise ApplyBindingError("terraform show timed out") from exc
    except OSError as exc:
        raise ApplyBindingError("terraform show could not start") from exc
    if process.returncode != 0:
        raise ApplyBindingError("terraform show rejected the saved plan")
    if not 1 <= len(output) <= MAX_PLAN_BYTES:
        raise ApplyBindingError(
            "terraform show output size is outside the allowed range"
        )
    return output


def _write_atomic(path: Path, document: dict[str, Any]) -> None:
    payload = json.dumps(document, allow_nan=False, indent=2, sort_keys=True) + "\n"
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary.write(payload)
            temporary.flush()
            os.fsync(temporary.fileno())
            temporary_path = Path(temporary.name)
        temporary_path.replace(path)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Rebind reviewed Terraform evidence and apply the exact immutable plan bytes."
    )
    parser.add_argument("plan_binary", type=Path)
    parser.add_argument("policy", type=Path)
    parser.add_argument("audit_report", type=Path)
    parser.add_argument("--expected-plan-sha256", required=True)
    parser.add_argument("--expected-policy-sha256", required=True)
    parser.add_argument("--expected-commit-sha", required=True)
    parser.add_argument("--actual-commit-sha", required=True)
    parser.add_argument("--working-directory", type=Path, default=Path.cwd())
    parser.add_argument("--terraform", default="terraform")
    parser.add_argument("--timeout-seconds", type=int, default=1800)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    descriptor = -1
    try:
        expected_plan = _expected(
            args.expected_plan_sha256, _DIGEST, "expected_plan_sha256"
        )
        expected_policy = _expected(
            args.expected_policy_sha256, _DIGEST, "expected_policy_sha256"
        )
        expected_commit = _expected(
            args.expected_commit_sha, _COMMIT, "expected_commit_sha"
        )
        actual_commit = _expected(args.actual_commit_sha, _COMMIT, "actual_commit_sha")
        if not hmac.compare_digest(expected_commit, actual_commit):
            raise ApplyBindingError(
                "checked-out commit does not match the approved commit"
            )
        if not 1 <= args.timeout_seconds <= 7200:
            raise ApplyBindingError("timeout_seconds must be from 1 through 7200")
        if not args.working_directory.is_dir():
            raise ApplyBindingError("working_directory must be an existing directory")
        resolved_inputs = {
            args.plan_binary.resolve(),
            args.policy.resolve(),
            args.audit_report.resolve(),
        }
        if len(resolved_inputs) != 3 or args.output.resolve() in resolved_inputs:
            raise ApplyBindingError(
                "plan, policy, audit, and output paths must be distinct"
            )

        raw_policy = _read_bounded(args.policy, MAX_POLICY_BYTES, "policy")
        raw_audit = _read_bounded(args.audit_report, MAX_AUDIT_BYTES, "audit report")
        reviewed = _load_json_bytes(
            raw_audit, max_bytes=MAX_AUDIT_BYTES, label="audit report"
        )
        if reviewed.get("schema_version") != PLAN_AUDIT_SCHEMA:
            raise ApplyBindingError("audit report schema is unsupported")

        executable = _terraform_executable(args.terraform)
        descriptor, plan_binary_sha256 = _sealed_plan(args.plan_binary)
        raw_plan = _terraform_show(
            executable,
            descriptor,
            args.working_directory,
            args.timeout_seconds,
        )
        current = audit_payloads(raw_plan, raw_policy)
        if not current["accepted"] or current["finding_codes"]:
            raise ApplyBindingError("current plan does not pass the reviewed policy")
        if current != reviewed:
            raise ApplyBindingError(
                "current plan audit does not match the reviewed report"
            )
        if not hmac.compare_digest(current["plan_sha256"], expected_plan):
            raise ApplyBindingError(
                "current plan digest does not match the approved digest"
            )
        if not hmac.compare_digest(current["policy_sha256"], expected_policy):
            raise ApplyBindingError(
                "current policy digest does not match the approved digest"
            )

        os.lseek(descriptor, 0, os.SEEK_SET)
        command = [
            str(executable),
            "apply",
            "-input=false",
            "-no-color",
            f"/proc/self/fd/{descriptor}",
        ]
        try:
            result = subprocess.run(
                command,
                cwd=args.working_directory,
                stdin=subprocess.DEVNULL,
                check=False,
                timeout=args.timeout_seconds,
                pass_fds=(descriptor,),
            )
        except subprocess.TimeoutExpired:
            print(
                "bound Terraform apply failed: terraform apply timed out",
                file=sys.stderr,
            )
            return 4
        except OSError:
            print(
                "bound Terraform apply failed: terraform apply could not start",
                file=sys.stderr,
            )
            return 4
        if result.returncode != 0:
            print(
                "bound Terraform apply failed: terraform apply returned non-zero",
                file=sys.stderr,
            )
            return 4

        receipt = {
            "schema_version": APPLY_BINDING_SCHEMA,
            "status": "applied",
            "commit_sha": actual_commit,
            "plan_binary_sha256": plan_binary_sha256,
            "plan_sha256": current["plan_sha256"],
            "policy_sha256": current["policy_sha256"],
            "audit_report_sha256": hashlib.sha256(raw_audit).hexdigest(),
            "audit_document_sha256": _canonical_digest(reviewed),
            "terraform_executable_sha256": hashlib.sha256(
                executable.read_bytes()
            ).hexdigest(),
        }
        _write_atomic(args.output, receipt)
        return 0
    except (OSError, PlanAuditError, ApplyBindingError) as exc:
        print(f"bound Terraform apply rejected: {exc}", file=sys.stderr)
        return 3
    finally:
        if descriptor >= 0:
            os.close(descriptor)


if __name__ == "__main__":
    raise SystemExit(main())
