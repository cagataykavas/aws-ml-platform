#!/usr/bin/env python3
"""Attest the OIDC caller before auditing one retained backend consumption."""

from __future__ import annotations

import argparse
import json
import sys

try:
    from scripts.run_retained_evidence_live_audit import attest_caller_identity
    from scripts.verify_retained_redrive_evidence import AwsEvidenceCli, EvidenceReader
    from scripts.verify_retained_terraform_backend_consumption import (
        ConsumptionArchiveReceipt,
        _load_json,
        verify_retained_consumption,
    )
except ModuleNotFoundError:  # Direct execution from the scripts directory.
    from run_retained_evidence_live_audit import attest_caller_identity
    from verify_retained_redrive_evidence import AwsEvidenceCli, EvidenceReader
    from verify_retained_terraform_backend_consumption import (
        ConsumptionArchiveReceipt,
        _load_json,
        verify_retained_consumption,
    )


def run_live_backend_consumption_audit(
    aws: EvidenceReader,
    receipt: ConsumptionArchiveReceipt,
    *,
    role_arn: str,
    session_name: str,
    bucket: str,
    key: str,
    version_id: str,
    expected_consumption_sha256: str,
    owner_account_id: str,
    region: str,
) -> dict[str, object]:
    """Require the exact protected OIDC role before any retained-object read."""

    identity = attest_caller_identity(
        aws,
        role_arn=role_arn,
        session_name=session_name,
        account_id=owner_account_id,
    )
    audit = verify_retained_consumption(
        aws,
        receipt,
        bucket=bucket,
        key=key,
        version_id=version_id,
        expected_consumption_sha256=expected_consumption_sha256,
        owner_account_id=owner_account_id,
        region=region,
    )
    return {**audit, **identity}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Attest an OIDC auditor and verify one retained backend-consumption version."
        )
    )
    parser.add_argument("archive_receipt")
    parser.add_argument("--auditor-role-arn", required=True)
    parser.add_argument("--session-name", required=True)
    parser.add_argument("--bucket", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--version-id", required=True)
    parser.add_argument("--expected-consumption-sha256", required=True)
    parser.add_argument("--owner-account-id", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--aws-cli", default="aws")
    parser.add_argument("--timeout-seconds", type=int, default=30)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if not 1 <= args.timeout_seconds <= 60:
            raise ValueError("timeout must be between 1 and 60 seconds")
        audit = run_live_backend_consumption_audit(
            AwsEvidenceCli(
                executable=args.aws_cli, timeout_seconds=args.timeout_seconds
            ),
            ConsumptionArchiveReceipt.from_document(_load_json(args.archive_receipt)),
            role_arn=args.auditor_role_arn,
            session_name=args.session_name,
            bucket=args.bucket,
            key=args.key,
            version_id=args.version_id,
            expected_consumption_sha256=args.expected_consumption_sha256,
            owner_account_id=args.owner_account_id,
            region=args.region,
        )
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"live retained backend-consumption audit failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(audit, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
