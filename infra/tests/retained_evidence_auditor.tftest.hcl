mock_provider "aws" {
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

run "retained_evidence_auditor_is_absent_by_default" {
  command = plan

  assert {
    condition = (
      length(terraform_data.retained_evidence_auditor_contract) == 0
      && length(aws_iam_role.retained_evidence_auditor) == 0
      && length(aws_iam_role_policy.retained_evidence_auditor) == 0
      && output.retained_evidence_auditor == null
    )
    error_message = "The retained-evidence auditor must remain absent unless explicitly enabled."
  }
}

run "retained_evidence_auditor_is_environment_bound_and_read_only" {
  command = plan

  variables {
    enable_network_incident_redrive_drill                 = true
    network_incident_redrive_production_queue_arn         = "arn:aws:sqs:eu-central-1:123456789012:production-incidents"
    network_incident_redrive_github_oidc_provider_arn     = "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
    network_incident_redrive_github_repository            = "cagataykavas/aws-ml-platform"
    network_incident_redrive_github_environment           = "redrive-staging"
    enable_network_incident_redrive_evidence_archive      = true
    network_incident_redrive_evidence_archive_bucket_name = "ml-platform-redrive-evidence-123456789012"

    enable_retained_evidence_auditor_role                 = true
    retained_evidence_auditor_github_oidc_provider_arn    = "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
    retained_evidence_auditor_github_repository           = "cagataykavas/aws-ml-platform"
    retained_evidence_auditor_github_environment          = "retained-evidence-audit-staging"
  }

  assert {
    condition = (
      jsondecode(aws_iam_role.retained_evidence_auditor[0].assume_role_policy).Statement[0].Principal.Federated == "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
      && jsondecode(aws_iam_role.retained_evidence_auditor[0].assume_role_policy).Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:aud"] == "sts.amazonaws.com"
      && jsondecode(aws_iam_role.retained_evidence_auditor[0].assume_role_policy).Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:sub"] == "repo:cagataykavas/aws-ml-platform:environment:retained-evidence-audit-staging"
      && !strcontains(aws_iam_role.retained_evidence_auditor[0].assume_role_policy, "ref:refs/heads/")
    )
    error_message = "The auditor trust must bind the account-local provider, audience and exact protected Environment subject."
  }

  assert {
    condition = (
      toset(jsondecode(aws_iam_role_policy.retained_evidence_auditor[0].policy).Statement[0].Action) == toset([
        "s3:GetObjectRetention",
        "s3:GetObjectVersion",
      ])
      && jsondecode(aws_iam_role_policy.retained_evidence_auditor[0].policy).Statement[0].Resource == "arn:aws:s3:::ml-platform-redrive-evidence-123456789012/redrive-evidence/v1/*"
      && !strcontains(aws_iam_role_policy.retained_evidence_auditor[0].policy, "s3:ListBucket")
      && !strcontains(aws_iam_role_policy.retained_evidence_auditor[0].policy, "s3:PutObject")
      && !strcontains(aws_iam_role_policy.retained_evidence_auditor[0].policy, "s3:Delete")
      && !strcontains(aws_iam_role_policy.retained_evidence_auditor[0].policy, "s3:BypassGovernanceRetention")
    )
    error_message = "The auditor may read retained object versions and retention only within the evidence prefix."
  }

  assert {
    condition = (
      output.retained_evidence_auditor.role_arn == "arn:aws:iam::123456789012:role/retained-evidence-auditor"
      && output.retained_evidence_auditor.github_oidc_subject == "repo:cagataykavas/aws-ml-platform:environment:retained-evidence-audit-staging"
      && output.retained_evidence_auditor.github_environment_variables.AWS_REGION == "eu-central-1"
      && output.retained_evidence_auditor.github_environment_variables.AWS_ACCOUNT_ID == "123456789012"
      && output.retained_evidence_auditor.github_environment_variables.AWS_RETAINED_EVIDENCE_AUDITOR_ROLE_ARN == "arn:aws:iam::123456789012:role/retained-evidence-auditor"
      && output.retained_evidence_auditor.github_environment_variables.RETAINED_EVIDENCE_AUDIT_ENABLED == "true"
    )
    error_message = "The output must expose the exact reviewed variables consumed by the protected audit workflow."
  }
}

run "retained_evidence_auditor_requires_archive" {
  command = plan

  variables {
    enable_retained_evidence_auditor_role              = true
    retained_evidence_auditor_github_oidc_provider_arn = "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
    retained_evidence_auditor_github_repository        = "cagataykavas/aws-ml-platform"
    retained_evidence_auditor_github_environment       = "retained-evidence-audit-staging"
  }

  expect_failures = [terraform_data.retained_evidence_auditor_contract[0]]
}

run "retained_evidence_auditor_rejects_cross_account_provider" {
  command = plan

  variables {
    enable_network_incident_redrive_drill                 = true
    network_incident_redrive_production_queue_arn         = "arn:aws:sqs:eu-central-1:123456789012:production-incidents"
    network_incident_redrive_github_oidc_provider_arn     = "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
    network_incident_redrive_github_repository            = "cagataykavas/aws-ml-platform"
    network_incident_redrive_github_environment           = "redrive-staging"
    enable_network_incident_redrive_evidence_archive      = true
    network_incident_redrive_evidence_archive_bucket_name = "ml-platform-redrive-evidence-123456789012"

    enable_retained_evidence_auditor_role                 = true
    retained_evidence_auditor_github_oidc_provider_arn    = "arn:aws:iam::999999999999:oidc-provider/token.actions.githubusercontent.com"
    retained_evidence_auditor_github_repository           = "cagataykavas/aws-ml-platform"
    retained_evidence_auditor_github_environment          = "retained-evidence-audit-staging"
  }

  expect_failures = [terraform_data.retained_evidence_auditor_contract[0]]
}
