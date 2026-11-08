"""SDK boundary tests, not integration tests against AWS."""
import socket

import boto3
import pytest
from botocore.exceptions import ParamValidationError, UnStubbedResponseError
from botocore.stub import Stubber

from aws_integration.request import build_request, example_request, validate_sdk_shape


@pytest.fixture(autouse=True)
def prohibit_network_and_profile_reads(monkeypatch):
    monkeypatch.setenv("AWS_CONFIG_FILE", "/dev/null")
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", "/dev/null")
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    monkeypatch.delenv("AWS_DEFAULT_PROFILE", raising=False)
    def forbidden(*args, **kwargs):
        raise AssertionError("Network is forbidden in offline SDK tests")
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)


@pytest.fixture
def client():
    # Explicit dummy values prevent credential-chain discovery. Session is fresh.
    return boto3.Session().client(
        "sagemaker", region_name="us-east-1",
        aws_access_key_id="OFFLINE_NOT_A_KEY",
        aws_secret_access_key="OFFLINE_NOT_A_SECRET",
        aws_session_token="OFFLINE_NOT_A_TOKEN",
    )


def test_request_structure():
    request = example_request()
    assert [c["ChannelType"] for c in request["AutoMLJobInputDataConfig"]] == ["training", "validation"]
    assert request["AutoMLProblemTypeConfig"]["TabularJobConfig"]["TargetAttributeName"] == "Machine failure"
    assert "ModelDeployConfig" not in request
    assert "DataSplitConfig" not in request
    assert request["AutoMLJobObjective"] == {"MetricName": "F1"}
    validate_sdk_shape(request)


def test_real_boto3_stubbed_create_boundary(client):
    request = example_request()
    response = {"AutoMLJobArn": "arn:aws:sagemaker:us-east-1:000000000000:automl-job/maintenance-demo-offline"}
    with Stubber(client) as stubber:
        stubber.add_response("create_auto_ml_job_v2", response, expected_params=request)
        assert client.create_auto_ml_job_v2(**request) == response
        stubber.assert_no_pending_responses()
        # An extra operation is rejected locally, rather than reaching AWS.
        with pytest.raises(UnStubbedResponseError):
            client.create_auto_ml_job_v2(**request)


@pytest.mark.parametrize("mutation", [
    lambda r: r.pop("RoleArn"),
    lambda r: r.update(UnknownParameter=True),
    lambda r: r["AutoMLProblemTypeConfig"]["TabularJobConfig"]["CompletionCriteria"].update(MaxCandidates="two"),
])
def test_botocore_rejects_invalid_sdk_shape(mutation):
    request = example_request()
    mutation(request)
    with pytest.raises(ParamValidationError):
        validate_sdk_shape(request)


@pytest.mark.parametrize("override", [
    {"max_candidates": 3}, {"max_candidate_seconds": 601},
    {"max_job_seconds": 1801}, {"max_candidates": True},
    {"training_s3": "https://example.com/train"},
    {"validation_s3": "s3://offline-bucket/train/subset/"},
    {"output_s3": "s3://offline-bucket/train/"},
    {"role_arn": "not-an-arn"}, {"job_name": "invalid name"},
    {"max_job_seconds": 30}, {"target": " "},
])
def test_project_guardrails(override):
    kwargs = dict(job_name="offline-test", role_arn="arn:aws:iam::000000000000:role/example",
                  training_s3="s3://offline-bucket/train/", validation_s3="s3://offline-bucket/validation/",
                  output_s3="s3://offline-bucket/output/")
    kwargs.update(override)
    with pytest.raises(ValueError):
        build_request(**kwargs)
