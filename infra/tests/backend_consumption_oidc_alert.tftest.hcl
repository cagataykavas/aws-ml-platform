mock_provider "aws" {
  override_during = plan

  override_data {
    target = data.aws_availability_zones.available
    values = {
      names = ["eu-central-1a", "eu-central-1b"]
    }
  }

  override_data {
    target = data.aws_caller_identity.current
    values = {
      account_id = "123456789012"
    }
  }

  override_data {
    target = data.aws_partition.current
    values = {
      partition = "aws"
    }
  }
}

variables {
  ecs_cluster_name = "test-cluster"
  ecs_service_name = "test-service"
  alb_dimension    = "app/test/0123456789abcdef"
}

run "backend_consumption_oidc_failure_alert_is_absent_by_default" {
  command = plan

  assert {
    condition = (
      length(terraform_data.backend_consumption_oidc_failure_alert_contract) == 0
      && length(aws_cloudwatch_event_rule.backend_consumption_oidc_failure) == 0
      && length(aws_iam_role.backend_consumption_oidc_failure_delivery) == 0
      && length(aws_iam_role_policy.backend_consumption_oidc_failure_delivery) == 0
      && length(aws_cloudwatch_event_target.backend_consumption_oidc_failure) == 0
      && output.backend_consumption_oidc_failure_alert == null
    )
    error_message = "The failed-OIDC alert route must remain absent unless explicitly enabled."
  }
}

run "backend_consumption_oidc_failure_alert_is_exact_and_encrypted" {
  command = plan

  variables {
    enable_managed_network_incident_topic                = true
    enable_backend_consumption_auditor_role              = true
    enable_backend_consumption_oidc_failure_alert        = true
    backend_consumption_archive_bucket_arn               = "arn:aws:s3:::ml-platform-backend-consumptions-123456789012"
    backend_consumption_auditor_github_oidc_provider_arn = "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
    backend_consumption_auditor_github_repository        = "cagataykavas/aws-ml-platform"
    backend_consumption_auditor_github_repository_id     = "1330973918"
    backend_consumption_auditor_github_environment       = "backend-consumption-audit-staging"
    backend_consumption_auditor_github_ref               = "refs/heads/main"
    backend_consumption_auditor_github_workflow          = "backend-consumption-live-audit"
  }

  assert {
    condition = (
      length(terraform_data.backend_consumption_oidc_failure_alert_contract) == 1
      && length(aws_cloudwatch_event_rule.backend_consumption_oidc_failure) == 1
      && length(aws_iam_role.backend_consumption_oidc_failure_delivery) == 1
      && length(aws_iam_role_policy.backend_consumption_oidc_failure_delivery) == 1
      && length(aws_cloudwatch_event_target.backend_consumption_oidc_failure) == 1
    )
    error_message = "Opt-in must create exactly one rule, scoped delivery role, policy, and target."
  }

  assert {
    condition = (
      jsondecode(aws_cloudwatch_event_rule.backend_consumption_oidc_failure[0].event_pattern).source == ["aws.sts"]
      && aws_cloudwatch_event_rule.backend_consumption_oidc_failure[0].state == "ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS"
      && jsondecode(aws_cloudwatch_event_rule.backend_consumption_oidc_failure[0].event_pattern)["detail-type"] == ["AWS API Call via CloudTrail"]
      && jsondecode(aws_cloudwatch_event_rule.backend_consumption_oidc_failure[0].event_pattern).detail.eventSource == ["sts.amazonaws.com"]
      && jsondecode(aws_cloudwatch_event_rule.backend_consumption_oidc_failure[0].event_pattern).detail.eventName == ["AssumeRoleWithWebIdentity"]
      && jsondecode(aws_cloudwatch_event_rule.backend_consumption_oidc_failure[0].event_pattern).detail.requestParameters.roleArn == ["arn:aws:iam::123456789012:role/backend-consumption-auditor"]
      && jsondecode(aws_cloudwatch_event_rule.backend_consumption_oidc_failure[0].event_pattern).detail.errorCode[0].exists == true
    )
    error_message = "The rule must match only CloudTrail OIDC failures requesting the exact auditor role."
  }

  assert {
    condition = (
      jsondecode(aws_iam_role.backend_consumption_oidc_failure_delivery[0].assume_role_policy).Statement[0].Principal.Service == "events.amazonaws.com"
      && jsondecode(aws_iam_role.backend_consumption_oidc_failure_delivery[0].assume_role_policy).Statement[0].Condition.StringEquals["aws:SourceAccount"] == "123456789012"
      && jsondecode(aws_iam_role.backend_consumption_oidc_failure_delivery[0].assume_role_policy).Statement[0].Condition.ArnEquals["aws:SourceArn"] == "arn:aws:events:eu-central-1:123456789012:rule/ml-platform-backend-consumption-oidc-failures"
    )
    error_message = "Only the exact account-local EventBridge rule may assume the delivery role."
  }

  assert {
    condition = (
      jsondecode(aws_iam_role_policy.backend_consumption_oidc_failure_delivery[0].policy).Statement[0].Action == "sns:Publish"
      && jsondecode(aws_iam_role_policy.backend_consumption_oidc_failure_delivery[0].policy).Statement[0].Resource == "arn:aws:sns:eu-central-1:123456789012:ml-platform-network-incidents"
      && toset(jsondecode(aws_iam_role_policy.backend_consumption_oidc_failure_delivery[0].policy).Statement[1].Action) == toset(["kms:Decrypt", "kms:GenerateDataKey*"])
      && jsondecode(aws_iam_role_policy.backend_consumption_oidc_failure_delivery[0].policy).Statement[1].Condition.StringEquals["kms:EncryptionContext:aws:sns:topicArn"] == "arn:aws:sns:eu-central-1:123456789012:ml-platform-network-incidents"
      && jsondecode(aws_iam_role_policy.backend_consumption_oidc_failure_delivery[0].policy).Statement[1].Condition.StringEquals["kms:ViaService"] == "sns.eu-central-1.amazonaws.com"
    )
    error_message = "The delivery role must be limited to one encrypted incident topic and its SNS encryption context."
  }

  assert {
    condition = (
      aws_cloudwatch_event_target.backend_consumption_oidc_failure[0].arn == "arn:aws:sns:eu-central-1:123456789012:ml-platform-network-incidents"
      && jsondecode(aws_sns_topic_policy.network_incidents[0].policy).Statement[2].Sid == "BackendConsumptionOidcFailurePublish"
      && jsondecode(aws_sns_topic_policy.network_incidents[0].policy).Statement[2].Principal.AWS == "arn:aws:iam::123456789012:role/ml-platform-backend-consumption-oidc-alert"
      && jsondecode(aws_sns_topic_policy.network_incidents[0].policy).Statement[2].Action == "SNS:Publish"
      && jsondecode(aws_kms_key.network_incidents[0].policy).Statement[2].Sid == "BackendConsumptionOidcFailureDelivery"
      && jsondecode(aws_kms_key.network_incidents[0].policy).Statement[2].Principal.AWS == "arn:aws:iam::123456789012:role/ml-platform-backend-consumption-oidc-alert"
      && jsondecode(aws_kms_key.network_incidents[0].policy).Statement[2].Condition.StringEquals["kms:EncryptionContext:aws:sns:topicArn"] == "arn:aws:sns:eu-central-1:123456789012:ml-platform-network-incidents"
      && jsondecode(aws_kms_key.network_incidents[0].policy).Statement[2].Condition.StringEquals["kms:ViaService"] == "sns.eu-central-1.amazonaws.com"
    )
    error_message = "The target and KMS key must authorize only the dedicated delivery role and topic context."
  }

  assert {
    condition = (
      output.backend_consumption_oidc_failure_alert.rule_arn == "arn:aws:events:eu-central-1:123456789012:rule/ml-platform-backend-consumption-oidc-failures"
      && output.backend_consumption_oidc_failure_alert.monitored_role_arn == "arn:aws:iam::123456789012:role/backend-consumption-auditor"
      && output.backend_consumption_oidc_failure_alert.incident_topic_arn == "arn:aws:sns:eu-central-1:123456789012:ml-platform-network-incidents"
      && output.backend_consumption_oidc_failure_alert.delivery_role_arn == "arn:aws:iam::123456789012:role/ml-platform-backend-consumption-oidc-alert"
    )
    error_message = "The alert output must expose the exact reviewed route boundaries."
  }
}

run "backend_consumption_oidc_failure_alert_requires_auditor" {
  command = plan

  variables {
    enable_managed_network_incident_topic         = true
    enable_backend_consumption_oidc_failure_alert = true
  }

  expect_failures = [terraform_data.backend_consumption_oidc_failure_alert_contract[0]]
}

run "backend_consumption_oidc_failure_alert_requires_managed_topic" {
  command = plan

  variables {
    enable_backend_consumption_auditor_role              = true
    enable_backend_consumption_oidc_failure_alert        = true
    backend_consumption_archive_bucket_arn               = "arn:aws:s3:::ml-platform-backend-consumptions-123456789012"
    backend_consumption_auditor_github_oidc_provider_arn = "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
    backend_consumption_auditor_github_repository        = "cagataykavas/aws-ml-platform"
    backend_consumption_auditor_github_repository_id     = "1330973918"
    backend_consumption_auditor_github_environment       = "backend-consumption-audit-staging"
    backend_consumption_auditor_github_ref               = "refs/heads/main"
    backend_consumption_auditor_github_workflow          = "backend-consumption-live-audit"
  }

  expect_failures = [terraform_data.backend_consumption_oidc_failure_alert_contract[0]]
}
