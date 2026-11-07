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

run "backend_consumption_auditor_is_absent_by_default" {
  command = plan

  assert {
    condition = (
      length(terraform_data.backend_consumption_auditor_contract) == 0
      && length(aws_iam_role.backend_consumption_auditor) == 0
      && length(aws_iam_role_policy.backend_consumption_auditor) == 0
      && output.backend_consumption_auditor == null
    )
    error_message = "The backend-consumption auditor must remain absent unless explicitly enabled."
  }
}

run "backend_consumption_auditor_is_environment_bound_and_prefix_read_only" {
  command = plan

  variables {
    enable_backend_consumption_auditor_role              = true
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
      jsondecode(aws_iam_role.backend_consumption_auditor[0].assume_role_policy).Statement[0].Principal.Federated == "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
      && jsondecode(aws_iam_role.backend_consumption_auditor[0].assume_role_policy).Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:aud"] == "sts.amazonaws.com"
      && jsondecode(aws_iam_role.backend_consumption_auditor[0].assume_role_policy).Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:sub"] == "repo:cagataykavas/aws-ml-platform:environment:backend-consumption-audit-staging"
      && jsondecode(aws_iam_role.backend_consumption_auditor[0].assume_role_policy).Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:repository"] == "cagataykavas/aws-ml-platform"
      && jsondecode(aws_iam_role.backend_consumption_auditor[0].assume_role_policy).Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:repository_id"] == "1330973918"
      && jsondecode(aws_iam_role.backend_consumption_auditor[0].assume_role_policy).Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:environment"] == "backend-consumption-audit-staging"
      && jsondecode(aws_iam_role.backend_consumption_auditor[0].assume_role_policy).Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:ref"] == "refs/heads/main"
      && jsondecode(aws_iam_role.backend_consumption_auditor[0].assume_role_policy).Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:workflow"] == "backend-consumption-live-audit"
      && jsondecode(aws_iam_role.backend_consumption_auditor[0].assume_role_policy).Statement[0].Condition.StringLike["sts:RoleSessionName"] == "retained-audit-?*"
      && !strcontains(aws_iam_role.backend_consumption_auditor[0].assume_role_policy, "ref:refs/heads/")
    )
    error_message = "The auditor trust must bind the account-local provider, protected Environment, repository, ref, workflow, and traceable session name."
  }

  assert {
    condition = (
      toset(jsondecode(aws_iam_role_policy.backend_consumption_auditor[0].policy).Statement[0].Action) == toset([
        "s3:GetObjectRetention",
        "s3:GetObjectVersion",
      ])
      && jsondecode(aws_iam_role_policy.backend_consumption_auditor[0].policy).Statement[0].Resource == "arn:aws:s3:::ml-platform-backend-consumptions-123456789012/terraform-backend-consumptions/v1/*"
      && !strcontains(aws_iam_role_policy.backend_consumption_auditor[0].policy, "s3:ListBucket")
      && !strcontains(aws_iam_role_policy.backend_consumption_auditor[0].policy, "s3:PutObject")
      && !strcontains(aws_iam_role_policy.backend_consumption_auditor[0].policy, "s3:Delete")
      && !strcontains(aws_iam_role_policy.backend_consumption_auditor[0].policy, "s3:BypassGovernanceRetention")
    )
    error_message = "The auditor may read versions and retention only under the backend-consumption prefix."
  }

  assert {
    condition = (
      output.backend_consumption_auditor.role_arn == "arn:aws:iam::123456789012:role/backend-consumption-auditor"
      && output.backend_consumption_auditor.github_oidc_subject == "repo:cagataykavas/aws-ml-platform:environment:backend-consumption-audit-staging"
      && output.backend_consumption_auditor.github_repository_id == "1330973918"
      && output.backend_consumption_auditor.github_oidc_ref == "refs/heads/main"
      && output.backend_consumption_auditor.github_oidc_workflow == "backend-consumption-live-audit"
      && output.backend_consumption_auditor.role_session_name_pattern == "retained-audit-?*"
      && output.backend_consumption_auditor.github_environment_variables.AWS_REGION == "eu-central-1"
      && output.backend_consumption_auditor.github_environment_variables.AWS_ACCOUNT_ID == "123456789012"
      && output.backend_consumption_auditor.github_environment_variables.AWS_BACKEND_CONSUMPTION_AUDITOR_ROLE_ARN == "arn:aws:iam::123456789012:role/backend-consumption-auditor"
      && output.backend_consumption_auditor.github_environment_variables.BACKEND_CONSUMPTION_AUDIT_ENABLED == "true"
    )
    error_message = "The output must expose only the reviewed protected-Environment variables."
  }
}

run "backend_consumption_auditor_requires_archive_bucket" {
  command = plan

  variables {
    enable_backend_consumption_auditor_role              = true
    backend_consumption_auditor_github_oidc_provider_arn = "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
    backend_consumption_auditor_github_repository        = "cagataykavas/aws-ml-platform"
    backend_consumption_auditor_github_repository_id     = "1330973918"
    backend_consumption_auditor_github_environment       = "backend-consumption-audit-staging"
    backend_consumption_auditor_github_ref               = "refs/heads/main"
    backend_consumption_auditor_github_workflow          = "backend-consumption-live-audit"
  }

  expect_failures = [terraform_data.backend_consumption_auditor_contract[0]]
}

run "backend_consumption_auditor_requires_ref_and_workflow_claims" {
  command = plan

  variables {
    enable_backend_consumption_auditor_role              = true
    backend_consumption_archive_bucket_arn               = "arn:aws:s3:::ml-platform-backend-consumptions-123456789012"
    backend_consumption_auditor_github_oidc_provider_arn = "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
    backend_consumption_auditor_github_repository        = "cagataykavas/aws-ml-platform"
    backend_consumption_auditor_github_repository_id     = "1330973918"
    backend_consumption_auditor_github_environment       = "backend-consumption-audit-staging"
  }

  expect_failures = [terraform_data.backend_consumption_auditor_contract[0]]
}

run "backend_consumption_auditor_rejects_unsafe_ref" {
  command = plan

  variables {
    backend_consumption_auditor_github_ref = "refs/heads/release/../main"
  }

  expect_failures = [var.backend_consumption_auditor_github_ref]
}

run "backend_consumption_auditor_rejects_invalid_repository_id" {
  command = plan

  variables {
    backend_consumption_auditor_github_repository_id = "owner/repository"
  }

  expect_failures = [var.backend_consumption_auditor_github_repository_id]
}

run "backend_consumption_auditor_rejects_unsafe_workflow_name" {
  command = plan

  variables {
    backend_consumption_auditor_github_workflow = "backend consumption audit"
  }

  expect_failures = [var.backend_consumption_auditor_github_workflow]
}

run "backend_consumption_auditor_rejects_cross_account_provider" {
  command = plan

  variables {
    enable_backend_consumption_auditor_role              = true
    backend_consumption_archive_bucket_arn               = "arn:aws:s3:::ml-platform-backend-consumptions-123456789012"
    backend_consumption_auditor_github_oidc_provider_arn = "arn:aws:iam::999999999999:oidc-provider/token.actions.githubusercontent.com"
    backend_consumption_auditor_github_repository        = "cagataykavas/aws-ml-platform"
    backend_consumption_auditor_github_repository_id     = "1330973918"
    backend_consumption_auditor_github_environment       = "backend-consumption-audit-staging"
    backend_consumption_auditor_github_ref               = "refs/heads/main"
    backend_consumption_auditor_github_workflow          = "backend-consumption-live-audit"
  }

  expect_failures = [terraform_data.backend_consumption_auditor_contract[0]]
}
