#!/usr/bin/env python3
"""Attest the OIDC caller before auditing one retained S3 object version."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from typing import Any, Protocol

try:
    from scripts.verify_retained_redrive_evidence import (
        ArchiveReceipt,
        AwsEvidenceCli,
        EvidenceReader,
        _load_json,
        verify_retained_evidence,
    )
except ModuleNotFoundError:  # Direct execution from the scripts directory.
    from verify_retained_redrive_evidence import (
        ArchiveReceipt,
        AwsEvidenceCli,
        EvidenceReader,
        _load_json,
        verify_retained_evidence,
    )


ROLE_ARN_PATTERN = re.compile(
    r"^arn:(aws|aws-us-gov|aws-cn):iam::([0-9]{12}):role/"
    r"([A-Za-z0-9+=,.@_-]+(?:/[A-Za-z0-9+=,.@_-]+)*)$"
)
SESSION_NAME_PATTERN = re.compile(r"^retained-audit-([1-9][0-9]{0,19})-([1-9][0-9]{0,4})$")


class CallerIdentityClient(Protocol):
    def call(
        self, service: str, operation: str, **parameters: str | list[str]
    ) -> dict[str, Any]: ...


@dataclass(frozen=True)
class AuditorIdentity:
    role_arn: str
    session_name: str

    @classmethod
    def expected(
        cls, *, role_arn: str, session_name: str, account_id: str
    ) -> AuditorIdentity:
        match = ROLE_ARN_PATTERN.fullmatch(role_arn)
        if match is None:
            raise ValueError("auditor role ARN is invalid")
        if match.group(2) != account_id or re.fullmatch(r"[0-9]{12}", account_id) is None:
            raise ValueError("auditor role ARN does not match the expected account")
        if SESSION_NAME_PATTERN.fullmatch(session_name) is None:
            raise ValueError("auditor session name is not bound to a workflow run")
        return cls(role_arn=role_arn, session_name=session_name)

    @property
    def assumed_role_arn(self) -> str:
        match = ROLE_ARN_PATTERN.fullmatch(self.role_arn)
        assert match is not None  # Construction validates the ARN.
        partition, account_id, role_path = match.groups()
        role_name = role_path.rsplit("/", 1)[-1]
        return (
            f"arn:{partition}:sts::{account_id}:assumed-role/"
            f"{role_name}/{self.session_name}"
        )


def attest_caller_identity(
    aws: CallerIdentityClient,
    *,
    role_arn: str,
    session_name: str,
    account_id: str,
) -> dict[str, object]:
    """Fail closed unless the active credentials are the exact reviewed role session."""
    expected = AuditorIdentity.expected(
        role_arn=role_arn, session_name=session_name, account_id=account_id
    )
    response = aws.call("sts", "get-caller-identity")
    if (
        response.get("Account") != account_id
        or response.get("Arn") != expected.assumed_role_arn
        or not isinstance(response.get("UserId"), str)
        or not response["UserId"].endswith(f":{session_name}")
    ):
        raise RuntimeError("active AWS credentials do not match the expected auditor session")
    return {
        "auditor_role_sha256": hashlib.sha256(role_arn.encode("utf-8")).hexdigest(),
        "auditor_session_sha256": hashlib.sha256(
            session_name.encode("utf-8")
        ).hexdigest(),
        "caller_identity_verified": True,
    }


def run_live_audit(
    aws: EvidenceReader,
    receipt: ArchiveReceipt,
    *,
    role_arn: str,
    session_name: str,
    bucket: str,
    key: str,
    version_id: str,
    owner_account_id: str,
    region: str,
) -> dict[str, object]:
    identity = attest_caller_identity(
        aws,
        role_arn=role_arn,
        session_name=session_name,
        account_id=owner_account_id,
    )
    audit = verify_retained_evidence(
        aws,
        receipt,
        bucket=bucket,
        key=key,
        version_id=version_id,
        owner_account_id=owner_account_id,
        region=region,
    )
    return {**audit, **identity}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Attest an OIDC auditor and verify one retained evidence version."
    )
    parser.add_argument("retention_receipt")
    parser.add_argument("--auditor-role-arn", required=True)
    parser.add_argument("--session-name", required=True)
    parser.add_argument("--bucket", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--version-id", required=True)
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
        audit = run_live_audit(
            AwsEvidenceCli(
                executable=args.aws_cli, timeout_seconds=args.timeout_seconds
            ),
            ArchiveReceipt.from_document(
                _load_json(args.retention_receipt, "archive receipt")
            ),
            role_arn=args.auditor_role_arn,
            session_name=args.session_name,
            bucket=args.bucket,
            key=args.key,
            version_id=args.version_id,
            owner_account_id=args.owner_account_id,
            region=args.region,
        )
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"live retained evidence audit failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(audit, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

