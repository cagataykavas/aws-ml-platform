import json

import pytest

from tools.aws_plan_policy import evaluate_plan


def change(address, resource_type, after, actions=None):
    return {
        "address": address,
        "type": resource_type,
        "change": {"actions": actions or ["create"], "after": after},
    }


def safe_plan():
    policy = json.dumps(
        {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject"],
                    "Resource": ["arn:aws:s3:::models/*"],
                }
            ]
        }
    )
    return {
        "resource_changes": [
            change(
                "aws_s3_bucket_public_access_block.artifacts",
                "aws_s3_bucket_public_access_block",
                {
                    "block_public_acls": True,
                    "block_public_policy": True,
                    "ignore_public_acls": True,
                    "restrict_public_buckets": True,
                },
            ),
            change(
                "aws_s3_bucket_versioning.artifacts",
                "aws_s3_bucket_versioning",
                {"versioning_configuration": [{"status": "Enabled"}]},
            ),
            change(
                "aws_s3_bucket_ownership_controls.artifacts",
                "aws_s3_bucket_ownership_controls",
                {"rule": [{"object_ownership": "BucketOwnerEnforced"}]},
            ),
            change(
                "aws_s3_bucket_server_side_encryption_configuration.artifacts",
                "aws_s3_bucket_server_side_encryption_configuration",
                {
                    "rule": [
                        {"apply_server_side_encryption_by_default": [{"sse_algorithm": "aws:kms"}]}
                    ]
                },
            ),
            change("aws_kms_key.ml", "aws_kms_key", {"enable_key_rotation": True}),
            change(
                "aws_security_group.endpoints",
                "aws_security_group",
                {"ingress": [{"cidr_blocks": ["10.50.0.0/16"], "ipv6_cidr_blocks": []}]},
            ),
            change(
                "aws_iam_role_policy.least_privilege", "aws_iam_role_policy", {"policy": policy}
            ),
        ]
    }


def test_safe_plan_passes():
    report = evaluate_plan(safe_plan())
    assert report.passed
    assert report.checked_resources == 7
    assert report.to_dict()["violations"] == []


@pytest.mark.parametrize(
    ("mutate", "code"),
    [
        (
            lambda p: p["resource_changes"][0]["change"]["after"].update(block_public_policy=False),
            "s3_public_access_not_blocked",
        ),
        (
            lambda p: p["resource_changes"][1]["change"]["after"]["versioning_configuration"][
                0
            ].update(status="Suspended"),
            "s3_versioning_disabled",
        ),
        (
            lambda p: p["resource_changes"][3]["change"]["after"]["rule"][0][
                "apply_server_side_encryption_by_default"
            ][0].update(sse_algorithm="AES256"),
            "s3_kms_encryption_missing",
        ),
        (
            lambda p: p["resource_changes"][4]["change"]["after"].update(enable_key_rotation=False),
            "kms_rotation_disabled",
        ),
        (
            lambda p: p["resource_changes"][5]["change"]["after"]["ingress"][0][
                "cidr_blocks"
            ].append("0.0.0.0/0"),
            "public_security_group_ingress",
        ),
    ],
)
def test_security_regressions_fail(mutate, code):
    plan = safe_plan()
    mutate(plan)
    assert code in {item.code for item in evaluate_plan(plan).violations}


def test_delete_and_replacement_are_blocked():
    plan = safe_plan()
    plan["resource_changes"][4]["change"]["actions"] = ["delete", "create"]
    assert "destructive_change" in {item.code for item in evaluate_plan(plan).violations}


@pytest.mark.parametrize(
    ("action", "resource", "code"),
    [
        ("s3:*", "arn:aws:s3:::models/*", "iam_wildcard_action"),
        ("s3:GetObject", "*", "iam_wildcard_resource"),
    ],
)
def test_iam_wildcards_are_blocked(action, resource, code):
    plan = safe_plan()
    plan["resource_changes"][-1]["change"]["after"]["policy"] = json.dumps(
        {"Statement": [{"Effect": "Allow", "Action": action, "Resource": resource}]}
    )
    assert code in {item.code for item in evaluate_plan(plan).violations}


def test_missing_required_control_is_reported():
    plan = safe_plan()
    plan["resource_changes"] = [
        item for item in plan["resource_changes"] if item["type"] != "aws_kms_key"
    ]
    report = evaluate_plan(plan)
    assert any(
        item.code == "required_control_missing" and item.address == "aws_kms_key"
        for item in report.violations
    )


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"resource_changes": [None]},
        {"resource_changes": [{"address": "x", "type": "aws_kms_key", "change": {}}]},
    ],
)
def test_malformed_plan_fails_closed(payload):
    with pytest.raises((TypeError, ValueError)):
        evaluate_plan(payload)
