#!/usr/bin/env python3
"""Cross-bind Terraform backend control evidence before release to planning."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from scripts.audit_live_terraform_backend import (
        BackendAuditReceipt,
        _canonical,
        _load_receipt,
        _sha256,
        _validated_boundary,
    )
    from scripts.audit_terraform_backend import _now_utc, _observed_at, _write_atomic
    from scripts.probe_terraform_backend_lock import (
        LOCK_CANARY_PAYLOAD_SCHEMA,
        LOCK_CANARY_SCHEMA,
        LiveAuditReceipt,
        _authorization,
        _state_key,
    )
except ModuleNotFoundError:  # Direct execution from the scripts directory.
    from audit_live_terraform_backend import (
        BackendAuditReceipt,
        _canonical,
        _load_receipt,
        _sha256,
        _validated_boundary,
    )
    from audit_terraform_backend import _now_utc, _observed_at, _write_atomic
    from probe_terraform_backend_lock import (
        LOCK_CANARY_PAYLOAD_SCHEMA,
        LOCK_CANARY_SCHEMA,
        LiveAuditReceipt,
        _authorization,
        _state_key,
    )


BACKEND_ADMISSION_SCHEMA = "terraform-backend-admission/v2"
MAX_EVIDENCE_AGE_SECONDS = 15 * 60

_DIGEST = re.compile(r"[0-9a-f]{64}")
_CANARY_FIELDS = {
    "schema_version",
    "observed_at",
    "backend_observed_at",
    "live_observed_at",
    "accepted",
    "partition",
    "account_id",
    "region",
    "bucket_sha256",
    "state_key_sha256",
    "kms_key_arn_sha256",
    "role_arn_sha256",
    "role_session_sha256",
    "authorization_sha256",
    "backend_audit_sha256",
    "live_backend_audit_sha256",
    "canary_key_sha256",
    "payload_sha256",
    "object_version_sha256",
    "etag_sha256",
    "conditional_acquisition_verified",
    "contention_rejection_verified",
    "exact_version_cleanup_verified",
    "evidence_sha256",
}
_CANARY_DIGEST_FIELDS = {
    "bucket_sha256",
    "state_key_sha256",
    "kms_key_arn_sha256",
    "role_arn_sha256",
    "role_session_sha256",
    "authorization_sha256",
    "backend_audit_sha256",
    "live_backend_audit_sha256",
    "canary_key_sha256",
    "payload_sha256",
    "object_version_sha256",
    "etag_sha256",
    "evidence_sha256",
}
_CANARY_CHECKS = (
    "conditional_acquisition_verified",
    "contention_rejection_verified",
    "exact_version_cleanup_verified",
)


class BackendAdmissionError(ValueError):
    """One or more backend admission receipts are invalid or cross-run mixed."""

    code = "TERRAFORM_BACKEND_ADMISSION_INVALID"

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(f"{self.code}: {reason}")


def _validate_canary(
    document: dict[str, Any],
    *,
    backend_audit_sha256: str,
    live_backend_audit_sha256: str,
    partition: str,
    account_id: str,
    region: str,
    bucket: str,
    state_key: str,
    kms_key_arn: str,
    role_arn: str,
    session_name: str,
    authorization_id: str,
    backend_observed_at: str,
    live_observed_at: str,
) -> tuple[str, str]:
    if set(document) != _CANARY_FIELDS:
        raise BackendAdmissionError(
            "lock canary receipt fields do not match the schema"
        )
    authorization_sha256 = _sha256(authorization_id)
    canary_key = f"{state_key}.lock-canary/{authorization_sha256}.tflock"
    payload = _canonical(
        {
            "schema_version": LOCK_CANARY_PAYLOAD_SCHEMA,
            "authorization_sha256": authorization_sha256,
            "backend_audit_sha256": backend_audit_sha256,
            "live_backend_audit_sha256": live_backend_audit_sha256,
            "backend_observed_at": backend_observed_at,
            "live_observed_at": live_observed_at,
            "observed_at": document.get("observed_at"),
            "canary_key_sha256": _sha256(canary_key),
        }
    )
    unsigned = {
        key: value for key, value in document.items() if key != "evidence_sha256"
    }
    expected_evidence_sha256 = hashlib.sha256(_canonical(unsigned)).hexdigest()
    if (
        document.get("schema_version") != LOCK_CANARY_SCHEMA
        or document.get("accepted") is not True
        or document.get("partition") != partition
        or document.get("account_id") != account_id
        or document.get("region") != region
        or document.get("bucket_sha256") != _sha256(bucket)
        or document.get("state_key_sha256") != _sha256(state_key)
        or document.get("kms_key_arn_sha256") != _sha256(kms_key_arn)
        or document.get("role_arn_sha256") != _sha256(role_arn)
        or document.get("role_session_sha256") != _sha256(session_name)
        or document.get("authorization_sha256") != authorization_sha256
        or document.get("backend_audit_sha256") != backend_audit_sha256
        or document.get("live_backend_audit_sha256") != live_backend_audit_sha256
        or document.get("backend_observed_at") != backend_observed_at
        or document.get("live_observed_at") != live_observed_at
        or document.get("canary_key_sha256") != _sha256(canary_key)
        or document.get("payload_sha256") != hashlib.sha256(payload).hexdigest()
        or any(document.get(check) is not True for check in _CANARY_CHECKS)
        or any(
            not isinstance(document.get(field), str)
            or _DIGEST.fullmatch(document[field]) is None
            for field in _CANARY_DIGEST_FIELDS
        )
        or document.get("evidence_sha256") != expected_evidence_sha256
    ):
        raise BackendAdmissionError(
            "lock canary receipt is invalid or targets another run"
        )
    try:
        observed_at = _observed_at(document.get("observed_at"))
    except (ValueError, TypeError) as exc:
        raise BackendAdmissionError("lock canary observation time is invalid") from exc
    return expected_evidence_sha256, observed_at


def _utc_datetime(value: str) -> datetime:
    return datetime.strptime(_observed_at(value), "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )


def _validate_evidence_window(
    *,
    backend_observed_at: str,
    live_observed_at: str,
    canary_observed_at: str,
    verification_time: str,
) -> str:
    try:
        timestamps = tuple(
            _utc_datetime(value)
            for value in (
                backend_observed_at,
                live_observed_at,
                canary_observed_at,
                verification_time,
            )
        )
    except (ValueError, TypeError) as exc:
        raise BackendAdmissionError("backend evidence time is invalid") from exc
    if timestamps != tuple(sorted(timestamps)):
        raise BackendAdmissionError("backend evidence observations are out of order")
    age_seconds = int((timestamps[-1] - timestamps[0]).total_seconds())
    if age_seconds > MAX_EVIDENCE_AGE_SECONDS:
        raise BackendAdmissionError("backend evidence exceeds the 15-minute window")
    return hashlib.sha256(
        _canonical(
            {
                "backend_observed_at": backend_observed_at,
                "live_observed_at": live_observed_at,
                "canary_observed_at": canary_observed_at,
                "verification_time": verification_time,
                "max_evidence_age_seconds": MAX_EVIDENCE_AGE_SECONDS,
            }
        )
    ).hexdigest()


def verify_backend_admission(
    backend_receipt_document: dict[str, Any],
    live_receipt_document: dict[str, Any],
    canary_receipt_document: dict[str, Any],
    *,
    partition: str,
    account_id: str,
    region: str,
    bucket: str,
    state_key: str,
    kms_key_arn: str,
    role_arn: str,
    session_name: str,
    authorization_id: str,
    verification_time: str | None = None,
) -> dict[str, object]:
    """Require one exact local/live/canary evidence chain before planning."""

    _assumed_role_arn, role_name = _validated_boundary(
        partition=partition,
        account_id=account_id,
        region=region,
        bucket=bucket,
        kms_key_arn=kms_key_arn,
        role_arn=role_arn,
        session_name=session_name,
    )
    state_key = _state_key(state_key)
    authorization_id = _authorization(authorization_id, session_name)
    backend_receipt = BackendAuditReceipt.validate_and_bind(
        backend_receipt_document,
        partition=partition,
        account_id=account_id,
        region=region,
        bucket=bucket,
        kms_key_arn=kms_key_arn,
    )
    if backend_receipt.key_sha256 != _sha256(state_key):
        raise BackendAdmissionError("backend receipt does not bind this state key")
    live_receipt = LiveAuditReceipt.validate_and_bind(
        live_receipt_document,
        backend_audit_sha256=backend_receipt.evidence_sha256,
        state_key_sha256=backend_receipt.key_sha256,
        partition=partition,
        account_id=account_id,
        region=region,
        bucket=bucket,
        kms_key_arn=kms_key_arn,
        role_arn=role_arn,
        role_name=role_name,
        session_name=session_name,
    )
    canary_evidence_sha256, canary_observed_at = _validate_canary(
        canary_receipt_document,
        backend_audit_sha256=backend_receipt.evidence_sha256,
        live_backend_audit_sha256=live_receipt.evidence_sha256,
        partition=partition,
        account_id=account_id,
        region=region,
        bucket=bucket,
        state_key=state_key,
        kms_key_arn=kms_key_arn,
        role_arn=role_arn,
        session_name=session_name,
        authorization_id=authorization_id,
        backend_observed_at=backend_receipt.observed_at,
        live_observed_at=live_receipt.observed_at,
    )
    try:
        verified_at = _observed_at(verification_time or _now_utc())
    except (ValueError, TypeError) as exc:
        raise BackendAdmissionError("verification time is invalid") from exc
    evidence_window_sha256 = _validate_evidence_window(
        backend_observed_at=backend_receipt.observed_at,
        live_observed_at=live_receipt.observed_at,
        canary_observed_at=canary_observed_at,
        verification_time=verified_at,
    )
    boundary_sha256 = hashlib.sha256(
        _canonical(
            {
                "partition": partition,
                "account_id": account_id,
                "region": region,
                "bucket": bucket,
                "state_key": state_key,
                "kms_key_arn": kms_key_arn,
                "role_arn": role_arn,
                "session_name": session_name,
                "authorization_id": authorization_id,
            }
        )
    ).hexdigest()
    evidence: dict[str, object] = {
        "schema_version": BACKEND_ADMISSION_SCHEMA,
        "accepted": True,
        "release_to_plan": True,
        "deployment_boundary_sha256": boundary_sha256,
        "authorization_sha256": _sha256(authorization_id),
        "backend_audit_sha256": backend_receipt.evidence_sha256,
        "live_backend_audit_sha256": live_receipt.evidence_sha256,
        "lock_canary_sha256": canary_evidence_sha256,
        "evidence_window_sha256": evidence_window_sha256,
        "evidence_freshness_verified": True,
        "backend_configuration_verified": True,
        "live_controls_verified": True,
        "conditional_lock_verified": True,
        "exact_cleanup_verified": True,
    }
    evidence["evidence_sha256"] = hashlib.sha256(_canonical(evidence)).hexdigest()
    return evidence


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Cross-bind backend audit receipts before release to terraform plan."
    )
    parser.add_argument("backend_receipt", type=Path)
    parser.add_argument("live_backend_receipt", type=Path)
    parser.add_argument("lock_canary_receipt", type=Path)
    parser.add_argument(
        "--partition", choices=("aws", "aws-us-gov", "aws-cn"), required=True
    )
    parser.add_argument("--account-id", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--bucket", required=True)
    parser.add_argument("--state-key", required=True)
    parser.add_argument("--kms-key-arn", required=True)
    parser.add_argument("--role-arn", required=True)
    parser.add_argument("--session-name", required=True)
    parser.add_argument("--authorization-id", required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        input_paths = {
            args.backend_receipt.resolve(),
            args.live_backend_receipt.resolve(),
            args.lock_canary_receipt.resolve(),
        }
        if len(input_paths) != 3:
            raise BackendAdmissionError("input receipts must be distinct files")
        if args.output is not None and args.output.resolve() in input_paths:
            raise BackendAdmissionError("output must not replace an input receipt")
        evidence = verify_backend_admission(
            _load_receipt(args.backend_receipt),
            _load_receipt(args.live_backend_receipt),
            _load_receipt(args.lock_canary_receipt),
            partition=args.partition,
            account_id=args.account_id,
            region=args.region,
            bucket=args.bucket,
            state_key=args.state_key,
            kms_key_arn=args.kms_key_arn,
            role_arn=args.role_arn,
            session_name=args.session_name,
            authorization_id=args.authorization_id,
        )
        if args.output is None:
            print(json.dumps(evidence, allow_nan=False, indent=2, sort_keys=True))
        else:
            _write_atomic(args.output, evidence)
        return 0
    except (BackendAdmissionError, OSError, TypeError, ValueError) as exc:
        print(f"Terraform backend admission rejected: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
