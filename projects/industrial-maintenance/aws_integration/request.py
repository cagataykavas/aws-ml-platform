"""Prepare a SageMaker CreateAutoMLJobV2 request, without a client or network."""
from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urlparse

from botocore.session import Session
from botocore.validate import validate_parameters


def _s3_prefix(uri: str) -> str:
    parsed = urlparse(uri)
    if (parsed.scheme != "s3" or not parsed.netloc or not parsed.path.strip("/")
            or parsed.query or parsed.fragment or "@" in parsed.netloc):
        raise ValueError("Use an s3://bucket/nonempty-prefix URI without query or fragment")
    return uri


def validate_sdk_shape(request: dict[str, Any]) -> None:
    """Validate against installed botocore model only; no credentials or client."""
    shape = Session().get_service_model("sagemaker").operation_model(
        "CreateAutoMLJobV2"
    ).input_shape
    validate_parameters(request, shape)


def build_request(*, job_name: str, role_arn: str, training_s3: str,
                  validation_s3: str, output_s3: str, target: str = "Machine failure",
                  max_candidates: int = 2, max_candidate_seconds: int = 600,
                  max_job_seconds: int = 1800) -> dict[str, Any]:
    """Build a bounded HPO experiment payload. Does not upload, train, or deploy.

    Distinct S3 prefixes do not establish row disjointness. Caller must preserve
    the local grouped/time-aware train/validation split and exclude test data.
    Limits below are project guardrails, not a monetary cap or AWS availability
    guarantee. AWS-side semantics still require live validation if authorized.
    """
    if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,30}[A-Za-z0-9])?", job_name):
        raise ValueError("job_name must be 1-32 alphanumeric/hyphen characters")
    if not re.fullmatch(r"arn:aws(?:-us-gov|-cn)?:iam::\d{12}:role/[\w+=,.@/-]+", role_arn):
        raise ValueError("role_arn must identify an IAM role")
    if not target or not target.strip():
        raise ValueError("target must be nonempty")
    uris = [_s3_prefix(u) for u in (training_s3, validation_s3, output_s3)]
    for i, left in enumerate(uris):
        for right in uris[i + 1:]:
            if left.startswith(right) or right.startswith(left):
                raise ValueError("Input/output S3 prefixes must not overlap")
    for name, value, upper in (
        ("max_candidates", max_candidates, 2),
        ("max_candidate_seconds", max_candidate_seconds, 600),
        ("max_job_seconds", max_job_seconds, 1800),
    ):
        if type(value) is not int or not 1 <= value <= upper:
            raise ValueError(f"{name} must be an integer in [1, {upper}]")
    if max_candidate_seconds > max_job_seconds:
        raise ValueError("Candidate runtime cannot exceed overall job runtime")
    request = {
        "AutoMLJobName": job_name,
        "RoleArn": role_arn,
        "AutoMLJobInputDataConfig": [
            {"ChannelType": kind, "ContentType": "text/csv;header=present",
             "CompressionType": "None",
             "DataSource": {"S3DataSource": {"S3DataType": "S3Prefix", "S3Uri": uri}}}
            for kind, uri in (("training", training_s3), ("validation", validation_s3))
        ],
        "OutputDataConfig": {"S3OutputPath": output_s3},
        "AutoMLProblemTypeConfig": {"TabularJobConfig": {
            "TargetAttributeName": target,
            "ProblemType": "BinaryClassification",
            "Mode": "HYPERPARAMETER_TUNING",
            "CandidateGenerationConfig": {"AlgorithmsConfig": [
                {"AutoMLAlgorithms": ["xgboost"]}
            ]},
            "CompletionCriteria": {
                "MaxCandidates": max_candidates,
                "MaxRuntimePerTrainingJobInSeconds": max_candidate_seconds,
                "MaxAutoMLJobRuntimeInSeconds": max_job_seconds,
            },
        }},
        "AutoMLJobObjective": {"MetricName": "F1"},
        "Tags": [{"Key": "Project", "Value": "industrial-maintenance-portfolio"}],
    }
    # Deliberately omit ModelDeployConfig and DataSplitConfig: no deployment,
    # and use the explicit validation channel instead of a new random split.
    validate_sdk_shape(request)
    return request


def example_request() -> dict[str, Any]:
    """Nonexistent placeholders for review, never an executable submission."""
    return build_request(
        job_name="maintenance-demo-offline",
        role_arn="arn:aws:iam::000000000000:role/REPLACE-ME",
        training_s3="s3://replace-me-maintenance/train/",
        validation_s3="s3://replace-me-maintenance/validation/",
        output_s3="s3://replace-me-maintenance/output/",
    )


if __name__ == "__main__":
    print(json.dumps(example_request(), indent=2))
