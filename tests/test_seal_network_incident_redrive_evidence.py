from __future__ import annotations

import base64
import copy
import hashlib
import unittest
from typing import Any

from scripts.run_network_incident_redrive_canary import (
    PREFLIGHT_CHECKS,
    PreflightAuthorization,
    RedriveRoute,
)
from scripts.seal_network_incident_redrive_evidence import (
    SIGNING_ALGORITHM,
    EvidencePair,
    KmsSigningKey,
)

ACCOUNT = "123456789012"
REGION = "eu-central-1"
KEY_ID = "12345678-1234-1234-1234-123456789abc"
KEY_ARN = f"arn:aws:kms:{REGION}:{ACCOUNT}:key/{KEY_ID}"
AUTHORIZATION_ID = "40999270849:1"
RUN_ID = "12345678-1234-1234-1234-123456789abc"


def route_document() -> dict[str, str]:
    production = (
        f"arn:aws:sqs:{REGION}:{ACCOUNT}:ml-platform-network-incidents-consumer"
    )
    fault = (
        f"arn:aws:sqs:{REGION}:{ACCOUNT}:ml-platform-network-incidents-fault-injection"
    )
    return {
        "production_queue_arn": production,
        "fault_queue_arn": fault,
        "fault_dead_letter_queue_arn": f"{fault}-dlq",
    }


def preflight(route: RedriveRoute) -> dict[str, Any]:
    return {
        "status": "pass",
        "schema_version": 1,
        "authorization_id": AUTHORIZATION_ID,
        "queue_route_sha256": route.digest(),
        "route_sha256": "a" * 64,
        "checks": [
            {"name": name, "passed": True, "detail": f"{name} passed"}
            for name in sorted(PREFLIGHT_CHECKS)
        ],
    }


def canary(route: RedriveRoute, preflight_receipt: dict[str, Any]) -> dict[str, Any]:
    authorization = PreflightAuthorization.from_document(
        preflight_receipt, route, AUTHORIZATION_ID
    )
    return {
        "status": "pass",
        "schema_version": 2,
        "run_id": RUN_ID,
        "route_sha256": route.digest(),
        "preflight_sha256": authorization.receipt_sha256,
        "observed": {
            "source_message_id": "source-1",
            "dead_letter_message_id": "dlq-1",
            "source_receive_counts": [1, 2, 3],
            "dead_letter_receive_attempt": 1,
        },
    }


class FakeAws:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict[str, str | list[str]]]] = []
        self.metadata: dict[str, Any] = {
            "Arn": KEY_ARN,
            "KeyId": KEY_ID,
            "Enabled": True,
            "KeyState": "Enabled",
            "KeyManager": "CUSTOMER",
            "KeyUsage": "SIGN_VERIFY",
            "KeySpec": "ECC_NIST_P256",
            "SigningAlgorithms": [SIGNING_ALGORITHM],
        }
        self.public: dict[str, Any] = {
            "KeyId": KEY_ARN,
            "PublicKey": base64.b64encode(b"p" * 91).decode("ascii"),
            "KeyUsage": "SIGN_VERIFY",
            "KeySpec": "ECC_NIST_P256",
            "SigningAlgorithms": [SIGNING_ALGORITHM],
        }
        self.signature = base64.b64encode(b"s" * 70).decode("ascii")
        self.signature_valid: object = True

    def call(
        self, service: str, operation: str, **parameters: str | list[str]
    ) -> dict[str, Any]:
        self.calls.append((service, operation, parameters))
        if operation == "describe-key":
            return {"KeyMetadata": dict(self.metadata)}
        if operation == "get-public-key":
            return dict(self.public)
        if operation == "sign":
            return {
                "KeyId": KEY_ARN,
                "SigningAlgorithm": SIGNING_ALGORITHM,
                "Signature": self.signature,
            }
        if operation == "verify":
            return {
                "KeyId": KEY_ARN,
                "SigningAlgorithm": SIGNING_ALGORITHM,
                "SignatureValid": self.signature_valid,
            }
        raise AssertionError(f"unexpected AWS operation: {operation}")


class EvidencePairTests(unittest.TestCase):
    def setUp(self) -> None:
        self.route = RedriveRoute.from_document(route_document())
        self.preflight = preflight(self.route)
        self.canary = canary(self.route, self.preflight)

    def test_binds_exact_preflight_canary_and_route(self) -> None:
        pair = EvidencePair.from_documents(
            self.route, self.preflight, self.canary, AUTHORIZATION_ID
        )

        self.assertEqual(pair.authorization_id, AUTHORIZATION_ID)
        self.assertEqual(pair.run_id, RUN_ID)
        self.assertEqual(pair.route_sha256, self.route.digest())
        self.assertEqual(pair.preflight_sha256, self.canary["preflight_sha256"])
        self.assertEqual(len(pair.canary_sha256), 64)

    def test_rejects_tampered_replayed_or_failed_receipts(self) -> None:
        tampered = copy.deepcopy(self.canary)
        tampered["preflight_sha256"] = "b" * 64
        with self.assertRaisesRegex(ValueError, "not linked"):
            EvidencePair.from_documents(
                self.route, self.preflight, tampered, AUTHORIZATION_ID
            )

        replayed = copy.deepcopy(self.preflight)
        with self.assertRaisesRegex(ValueError, "does not match this run"):
            EvidencePair.from_documents(
                self.route, replayed, self.canary, "another-run:1"
            )

        failed = copy.deepcopy(self.canary)
        failed["status"] = "error"
        with self.assertRaisesRegex(ValueError, "not a passing"):
            EvidencePair.from_documents(
                self.route, self.preflight, failed, AUTHORIZATION_ID
            )


class KmsSigningKeyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.aws = FakeAws()
        self.route = RedriveRoute.from_document(route_document())
        receipt = preflight(self.route)
        self.pair = EvidencePair.from_documents(
            self.route, receipt, canary(self.route, receipt), AUTHORIZATION_ID
        )

    def test_inspects_key_signs_claims_and_verifies_before_returning(self) -> None:
        key = KmsSigningKey.inspect(self.aws, KEY_ARN, self.route)
        envelope = key.seal(self.aws, self.pair)

        self.assertEqual(key.public_key_sha256, hashlib.sha256(b"p" * 91).hexdigest())
        self.assertEqual(envelope["claims"]["key_arn"], KEY_ARN)
        self.assertEqual(envelope["claims"]["canary_sha256"], self.pair.canary_sha256)
        self.assertEqual(envelope["signature"]["value"], self.aws.signature)
        self.assertEqual(
            envelope["verification_key"]["value"],
            base64.b64encode(b"p" * 91).decode("ascii"),
        )
        self.assertEqual(
            [operation for _, operation, _ in self.aws.calls],
            ["describe-key", "get-public-key", "sign", "verify"],
        )
        for _, operation, parameters in self.aws.calls:
            self.assertEqual(parameters["key_id"], KEY_ARN)
            self.assertEqual(parameters["region"], REGION)
            if operation in {"sign", "verify"}:
                self.assertEqual(parameters["message_type"], "RAW")
                self.assertEqual(parameters["signing_algorithm"], SIGNING_ALGORITHM)

    def test_rejects_disabled_wrong_use_or_aws_managed_key(self) -> None:
        for field, value in [
            ("Enabled", False),
            ("KeyUsage", "ENCRYPT_DECRYPT"),
            ("KeyManager", "AWS"),
            ("KeySpec", "RSA_2048"),
        ]:
            with self.subTest(field=field):
                aws = FakeAws()
                aws.metadata[field] = value
                with self.assertRaisesRegex(RuntimeError, "reviewed contract"):
                    KmsSigningKey.inspect(aws, KEY_ARN, self.route)

    def test_rejects_malformed_provider_responses(self) -> None:
        self.aws.public["PublicKey"] = "not base64!"
        with self.assertRaisesRegex(RuntimeError, "canonical base64"):
            KmsSigningKey.inspect(self.aws, KEY_ARN, self.route)

        aws = FakeAws()
        key = KmsSigningKey.inspect(aws, KEY_ARN, self.route)
        aws.signature_valid = 1
        with self.assertRaisesRegex(RuntimeError, "did not verify"):
            key.seal(aws, self.pair)

    def test_rejects_key_outside_route_account(self) -> None:
        other_account = KEY_ARN.replace(ACCOUNT, "210987654321")
        with self.assertRaisesRegex(ValueError, "partition, Region and account"):
            KmsSigningKey.inspect(self.aws, other_account, self.route)


if __name__ == "__main__":
    unittest.main()
