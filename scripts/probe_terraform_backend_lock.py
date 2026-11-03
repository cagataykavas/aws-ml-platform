#!/usr/bin/env python3
"""Prove isolated S3 lock acquisition, contention, and exact-version cleanup."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

try:
    from scripts.audit_live_terraform_backend import (
        LIVE_BACKEND_AUDIT_SCHEMA,
        BackendAuditReceipt,
        LiveBackendAuditError,
        _canonical,
        _load_receipt,
        _sha256,
        _validated_boundary,
    )
    from scripts.audit_terraform_backend import _write_atomic
except ModuleNotFoundError:  # Direct execution from the scripts directory.
    from audit_live_terraform_backend import (
        LIVE_BACKEND_AUDIT_SCHEMA,
        BackendAuditReceipt,
        LiveBackendAuditError,
        _canonical,
        _load_receipt,
        _sha256,
        _validated_boundary,
    )
    from audit_terraform_backend import _write_atomic


LOCK_CANARY_SCHEMA = "terraform-backend-lock-canary/v1"
LOCK_CANARY_PAYLOAD_SCHEMA = "terraform-backend-lock-canary-payload/v1"

_DIGEST = re.compile(r"[0-9a-f]{64}")
_AUTHORIZATION = re.compile(r"[1-9][0-9]{0,19}-[1-9][0-9]{0,4}")
_VERSION_ID = re.compile(r"[\x21-\x7e]{1,1024}")
_ETAG = re.compile(r'"[A-Za-z0-9+/=_-]{1,256}"')
_AWS_ERROR = re.compile(r"An error occurred \(([^)]+)\) when calling")
_LIVE_RECEIPT_FIELDS = {
    "schema_version",
    "accepted",
    "partition",
    "account_id",
    "region",
    "bucket_sha256",
    "kms_key_arn_sha256",
    "role_arn_sha256",
    "role_name_sha256",
    "role_session_sha256",
    "backend_audit_sha256",
    "state_key_sha256",
    "control_snapshot_sha256",
    "caller_identity_verified",
    "bucket_region_verified",
    "bucket_versioning_verified",
    "bucket_kms_encryption_verified",
    "bucket_public_access_blocked",
    "bucket_owner_enforced",
    "bucket_policy_nonpublic",
    "kms_key_verified",
    "kms_rotation_verified",
    "evidence_sha256",
}
_LIVE_CHECKS = (
    "caller_identity_verified",
    "bucket_region_verified",
    "bucket_versioning_verified",
    "bucket_kms_encryption_verified",
    "bucket_public_access_blocked",
    "bucket_owner_enforced",
    "bucket_policy_nonpublic",
    "kms_key_verified",
    "kms_rotation_verified",
)


class BackendLockCanaryError(ValueError):
    """The lock canary inputs, AWS response, or cleanup violated the boundary."""

    code = "TERRAFORM_BACKEND_LOCK_CANARY_INVALID"

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(f"{self.code}: {reason}")


class LockStore(Protocol):
    def acquire(
        self,
        *,
        bucket: str,
        key: str,
        body: bytes,
        checksum_sha256: str,
        expected_owner: str,
        region: str,
        kms_key_arn: str,
    ) -> dict[str, Any]: ...

    def assert_contended(
        self,
        *,
        bucket: str,
        key: str,
        body: bytes,
        checksum_sha256: str,
        expected_owner: str,
        region: str,
        kms_key_arn: str,
    ) -> dict[str, Any] | None: ...

    def release(
        self,
        *,
        bucket: str,
        key: str,
        version_id: str,
        expected_owner: str,
        region: str,
    ) -> dict[str, Any]: ...


class AwsCliLockStore:
    """AWS CLI adapter that exposes only the three canary operations."""

    def __init__(self, *, executable: str = "aws", timeout_seconds: int = 30) -> None:
        self.executable = executable
        self.timeout_seconds = timeout_seconds

    def _run(self, command: list[str]) -> tuple[int, dict[str, Any] | None, str | None]:
        command.extend(["--output", "json", "--no-cli-pager"])
        try:
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
            )
        except FileNotFoundError as exc:
            raise RuntimeError("AWS CLI executable was not found") from exc
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("AWS CLI lock operation timed out") from exc
        if completed.returncode != 0:
            match = _AWS_ERROR.search(completed.stderr)
            return completed.returncode, None, match.group(1) if match else None
        try:
            document = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError("AWS CLI lock operation returned invalid JSON") from exc
        if not isinstance(document, dict):
            raise TypeError("AWS CLI lock operation returned a non-object")
        return 0, document, None

    def _put_command(
        self,
        *,
        bucket: str,
        key: str,
        body_path: str,
        checksum_sha256: str,
        expected_owner: str,
        region: str,
        kms_key_arn: str,
    ) -> list[str]:
        return [
            self.executable,
            "s3api",
            "put-object",
            "--bucket",
            bucket,
            "--key",
            key,
            "--body",
            body_path,
            "--if-none-match",
            "*",
            "--checksum-algorithm",
            "SHA256",
            "--checksum-sha256",
            checksum_sha256,
            "--server-side-encryption",
            "aws:kms",
            "--ssekms-key-id",
            kms_key_arn,
            "--bucket-key-enabled",
            "--content-type",
            "application/json",
            "--expected-bucket-owner",
            expected_owner,
            "--region",
            region,
        ]

    def _put(
        self,
        *,
        bucket: str,
        key: str,
        body: bytes,
        checksum_sha256: str,
        expected_owner: str,
        region: str,
        kms_key_arn: str,
    ) -> tuple[int, dict[str, Any] | None, str | None]:
        descriptor, path = tempfile.mkstemp(
            prefix="terraform-lock-canary-", suffix=".json"
        )
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb", closefd=True) as stream:
                descriptor = -1
                stream.write(body)
                stream.flush()
                os.fsync(stream.fileno())
            return self._run(
                self._put_command(
                    bucket=bucket,
                    key=key,
                    body_path=path,
                    checksum_sha256=checksum_sha256,
                    expected_owner=expected_owner,
                    region=region,
                    kms_key_arn=kms_key_arn,
                )
            )
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass

    def acquire(self, **parameters: Any) -> dict[str, Any]:
        return_code, document, _error_code = self._put(**parameters)
        if return_code != 0 or document is None:
            raise RuntimeError("conditional S3 lock acquisition failed")
        return document

    def assert_contended(self, **parameters: Any) -> dict[str, Any] | None:
        return_code, document, error_code = self._put(**parameters)
        if return_code == 0:
            if document is None:
                raise RuntimeError(
                    "second conditional S3 lock acquisition was ambiguous"
                )
            return document
        if error_code != "PreconditionFailed":
            raise RuntimeError(
                "second conditional S3 lock acquisition was not rejected safely"
            )
        return None

    def release(
        self,
        *,
        bucket: str,
        key: str,
        version_id: str,
        expected_owner: str,
        region: str,
    ) -> dict[str, Any]:
        return_code, document, _error_code = self._run(
            [
                self.executable,
                "s3api",
                "delete-object",
                "--bucket",
                bucket,
                "--key",
                key,
                "--version-id",
                version_id,
                "--expected-bucket-owner",
                expected_owner,
                "--region",
                region,
            ]
        )
        if return_code != 0 or document is None:
            raise RuntimeError("exact-version S3 lock cleanup failed")
        return document


@dataclass(frozen=True)
class LiveAuditReceipt:
    evidence_sha256: str

    @classmethod
    def validate_and_bind(
        cls,
        document: dict[str, Any],
        *,
        backend_audit_sha256: str,
        state_key_sha256: str,
        partition: str,
        account_id: str,
        region: str,
        bucket: str,
        kms_key_arn: str,
        role_arn: str,
        role_name: str,
        session_name: str,
    ) -> LiveAuditReceipt:
        if set(document) != _LIVE_RECEIPT_FIELDS:
            raise BackendLockCanaryError(
                "live audit receipt fields do not match the schema"
            )
        unsigned = {
            key: value for key, value in document.items() if key != "evidence_sha256"
        }
        expected_digest = hashlib.sha256(_canonical(unsigned)).hexdigest()
        digest_fields = (
            "control_snapshot_sha256",
            "evidence_sha256",
        )
        if (
            document.get("schema_version") != LIVE_BACKEND_AUDIT_SCHEMA
            or document.get("accepted") is not True
            or document.get("partition") != partition
            or document.get("account_id") != account_id
            or document.get("region") != region
            or document.get("bucket_sha256") != _sha256(bucket)
            or document.get("kms_key_arn_sha256") != _sha256(kms_key_arn)
            or document.get("role_arn_sha256") != _sha256(role_arn)
            or document.get("role_name_sha256") != _sha256(role_name)
            or document.get("role_session_sha256") != _sha256(session_name)
            or document.get("backend_audit_sha256") != backend_audit_sha256
            or document.get("state_key_sha256") != state_key_sha256
            or any(document.get(check) is not True for check in _LIVE_CHECKS)
            or any(
                not isinstance(document.get(field), str)
                or _DIGEST.fullmatch(document[field]) is None
                for field in digest_fields
            )
            or document.get("evidence_sha256") != expected_digest
        ):
            raise BackendLockCanaryError(
                "live audit receipt is invalid or targets another run"
            )
        return cls(evidence_sha256=expected_digest)


def _state_key(value: object) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 900
        or value.startswith("/")
        or "//" in value
        or any(part in {"", ".", ".."} for part in value.split("/"))
        or any(ord(character) < 0x21 or ord(character) > 0x7E for character in value)
    ):
        raise BackendLockCanaryError(
            "state key cannot safely derive an isolated canary key"
        )
    return value


def _authorization(value: object, session_name: str) -> str:
    if not isinstance(value, str) or _AUTHORIZATION.fullmatch(value) is None:
        raise BackendLockCanaryError("authorization ID must be RUN_ID-RUN_ATTEMPT")
    if session_name != f"terraform-lock-{value}":
        raise BackendLockCanaryError(
            "role session is not bound to this authorization ID"
        )
    return value


def _validate_acquisition(
    response: dict[str, Any], *, checksum_sha256: str, kms_key_arn: str
) -> tuple[str, str]:
    version_id = response.get("VersionId")
    etag = response.get("ETag")
    if (
        not isinstance(version_id, str)
        or _VERSION_ID.fullmatch(version_id) is None
        or not isinstance(etag, str)
        or _ETAG.fullmatch(etag) is None
        or response.get("ChecksumSHA256") != checksum_sha256
        or response.get("ServerSideEncryption") != "aws:kms"
        or response.get("SSEKMSKeyId") != kms_key_arn
        or response.get("BucketKeyEnabled") is not True
        or "RequestCharged" in response
    ):
        raise BackendLockCanaryError(
            "lock acquisition response is incomplete or unsafe"
        )
    return version_id, etag


def _validate_release(response: dict[str, Any], version_id: str) -> None:
    if (
        response.get("VersionId") != version_id
        or (
            response.get("DeleteMarker") is not None
            and response.get("DeleteMarker") is not False
        )
        or "RequestCharged" in response
    ):
        raise BackendLockCanaryError("exact-version cleanup response is invalid")


def probe_backend_lock(
    store: LockStore,
    backend_receipt_document: dict[str, Any],
    live_receipt_document: dict[str, Any],
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
) -> dict[str, object]:
    """Acquire an isolated lock, prove contention, and delete its exact version."""

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
        raise BackendLockCanaryError("backend receipt does not bind this state key")
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
    authorization_sha256 = _sha256(authorization_id)
    canary_key = f"{state_key}.lock-canary/{authorization_sha256}.tflock"
    if len(canary_key.encode("utf-8")) > 1_024 or canary_key == f"{state_key}.tflock":
        raise BackendLockCanaryError(
            "derived canary key is outside the isolated namespace"
        )
    payload = _canonical(
        {
            "schema_version": LOCK_CANARY_PAYLOAD_SCHEMA,
            "authorization_sha256": authorization_sha256,
            "backend_audit_sha256": backend_receipt.evidence_sha256,
            "live_backend_audit_sha256": live_receipt.evidence_sha256,
            "canary_key_sha256": _sha256(canary_key),
        }
    )
    payload_sha256 = hashlib.sha256(payload).hexdigest()
    checksum_sha256 = base64.b64encode(bytes.fromhex(payload_sha256)).decode("ascii")
    parameters = {
        "bucket": bucket,
        "key": canary_key,
        "body": payload,
        "checksum_sha256": checksum_sha256,
        "expected_owner": account_id,
        "region": region,
        "kms_key_arn": kms_key_arn,
    }

    created_versions: list[str] = []
    cleanup_uncertain = False
    etag: str | None = None
    primary_error: Exception | None = None
    try:
        acquisition = store.acquire(**parameters)
        candidate_version = acquisition.get("VersionId")
        if isinstance(candidate_version, str) and _VERSION_ID.fullmatch(
            candidate_version
        ):
            created_versions.append(candidate_version)
        else:
            cleanup_uncertain = True
        version_id, etag = _validate_acquisition(
            acquisition,
            checksum_sha256=checksum_sha256,
            kms_key_arn=kms_key_arn,
        )
        contention = store.assert_contended(**parameters)
        if contention is not None:
            contender_version = contention.get("VersionId")
            if isinstance(contender_version, str) and _VERSION_ID.fullmatch(
                contender_version
            ):
                created_versions.append(contender_version)
            else:
                cleanup_uncertain = True
            _validate_acquisition(
                contention,
                checksum_sha256=checksum_sha256,
                kms_key_arn=kms_key_arn,
            )
            raise BackendLockCanaryError(
                "second conditional lock acquisition unexpectedly succeeded"
            )
    except (
        BackendLockCanaryError,
        OSError,
        RuntimeError,
        TypeError,
        ValueError,
    ) as exc:
        primary_error = exc
    finally:
        cleanup_error: Exception | None = None
        for created_version in reversed(created_versions):
            try:
                cleanup = store.release(
                    bucket=bucket,
                    key=canary_key,
                    version_id=created_version,
                    expected_owner=account_id,
                    region=region,
                )
                _validate_release(cleanup, created_version)
            except (
                BackendLockCanaryError,
                OSError,
                RuntimeError,
                TypeError,
                ValueError,
            ) as exc:
                cleanup_error = exc
        if cleanup_error is not None or cleanup_uncertain:
            raise BackendLockCanaryError(
                "exact-version lock cleanup failed; operator inspection is required"
            ) from cleanup_error
    if primary_error is not None:
        if isinstance(primary_error, BackendLockCanaryError):
            raise primary_error
        raise BackendLockCanaryError("conditional lock probe failed") from primary_error
    assert len(created_versions) == 1 and etag is not None
    version_id = created_versions[0]
    evidence: dict[str, object] = {
        "schema_version": LOCK_CANARY_SCHEMA,
        "accepted": True,
        "partition": partition,
        "account_id": account_id,
        "region": region,
        "bucket_sha256": _sha256(bucket),
        "state_key_sha256": backend_receipt.key_sha256,
        "kms_key_arn_sha256": _sha256(kms_key_arn),
        "role_arn_sha256": _sha256(role_arn),
        "role_session_sha256": _sha256(session_name),
        "authorization_sha256": authorization_sha256,
        "backend_audit_sha256": backend_receipt.evidence_sha256,
        "live_backend_audit_sha256": live_receipt.evidence_sha256,
        "canary_key_sha256": _sha256(canary_key),
        "payload_sha256": payload_sha256,
        "object_version_sha256": _sha256(version_id),
        "etag_sha256": _sha256(etag),
        "conditional_acquisition_verified": True,
        "contention_rejection_verified": True,
        "exact_version_cleanup_verified": True,
    }
    evidence["evidence_sha256"] = hashlib.sha256(_canonical(evidence)).hexdigest()
    return evidence


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Probe an isolated S3 lock key and remove its exact object version."
    )
    parser.add_argument("backend_receipt", type=Path)
    parser.add_argument("live_backend_receipt", type=Path)
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
    parser.add_argument("--aws-cli", default="aws")
    parser.add_argument("--timeout-seconds", type=int, default=30)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        if not 1 <= args.timeout_seconds <= 60:
            raise BackendLockCanaryError("timeout must be between 1 and 60 seconds")
        input_paths = {
            args.backend_receipt.resolve(),
            args.live_backend_receipt.resolve(),
        }
        if args.output is not None and args.output.resolve() in input_paths:
            raise BackendLockCanaryError("output must not replace an input receipt")
        evidence = probe_backend_lock(
            AwsCliLockStore(
                executable=args.aws_cli,
                timeout_seconds=args.timeout_seconds,
            ),
            _load_receipt(args.backend_receipt),
            _load_receipt(args.live_backend_receipt),
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
    except (
        BackendLockCanaryError,
        LiveBackendAuditError,
        OSError,
        RuntimeError,
    ) as exc:
        print(f"Terraform backend lock canary rejected: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
