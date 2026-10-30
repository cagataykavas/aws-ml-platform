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

run "redrive_drill_is_absent_by_default" {
  command = plan

  assert {
    condition = (
      length(terraform_data.network_incident_redrive_drill_contract) == 0
      && length(aws_sqs_queue.network_incident_redrive_fault) == 0
      && length(aws_sqs_queue.network_incident_redrive_fault_dlq) == 0
      && length(aws_sqs_queue_policy.network_incident_redrive_fault) == 0
      && length(aws_iam_role.network_incident_redrive_canary) == 0
      && length(aws_iam_role_policy.network_incident_redrive_canary) == 0
      && length(aws_iam_role_policy.network_incident_redrive_evidence) == 0
      && length(aws_iam_role_policy.network_incident_redrive_archive) == 0
      && length(aws_kms_key.network_incident_redrive_evidence) == 0
      && length(aws_s3_bucket.network_incident_redrive_evidence_archive) == 0
      && length(aws_s3_bucket_object_lock_configuration.network_incident_redrive_evidence_archive) == 0
      && output.network_incident_redrive_drill == null
    )
    error_message = "The redrive drill must remain completely absent unless explicitly enabled."
  }
}

run "redrive_drill_provisions_isolated_encrypted_queues" {
  command = plan

  variables {
    enable_network_incident_redrive_drill             = true
    network_incident_redrive_production_queue_arn     = "arn:aws:sqs:eu-central-1:123456789012:ml-platform-network-incidents-consumer"
    network_incident_redrive_github_oidc_provider_arn = "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
    network_incident_redrive_github_repository        = "cagataykavas/aws-ml-platform"
    network_incident_redrive_github_environment       = "redrive-staging"
  }

  assert {
    condition = (
      length(aws_sqs_queue.network_incident_redrive_fault) == 1
      && length(aws_sqs_queue.network_incident_redrive_fault_dlq) == 1
      && length(aws_sqs_queue_policy.network_incident_redrive_fault) == 2
      && length(aws_kms_key.network_incident_redrive_evidence) == 1
      && aws_sqs_queue.network_incident_redrive_fault[0].name == "ml-platform-network-incidents-fault-injection"
      && aws_sqs_queue.network_incident_redrive_fault_dlq[0].name == "ml-platform-network-incidents-fault-injection-dlq"
      && aws_sqs_queue.network_incident_redrive_fault[0].sqs_managed_sse_enabled
      && aws_sqs_queue.network_incident_redrive_fault_dlq[0].sqs_managed_sse_enabled
      && aws_sqs_queue.network_incident_redrive_fault[0].message_retention_seconds == 3600
      && aws_sqs_queue.network_incident_redrive_fault_dlq[0].message_retention_seconds == 3600
    )
    error_message = "Opt-in must create only the short-lived, encrypted fault queue pair."
  }

  assert {
    condition = (
      aws_kms_key.network_incident_redrive_evidence[0].key_usage == "SIGN_VERIFY"
      && aws_kms_key.network_incident_redrive_evidence[0].customer_master_key_spec == "ECC_NIST_P256"
      && aws_kms_key.network_incident_redrive_evidence[0].deletion_window_in_days == 30
    )
    error_message = "Evidence must use a dedicated P-256 asymmetric signing key."
  }

  assert {
    condition = (
      jsondecode(aws_sqs_queue.network_incident_redrive_fault[0].redrive_policy).deadLetterTargetArn == "arn:aws:sqs:eu-central-1:123456789012:ml-platform-network-incidents-fault-injection-dlq"
      && jsondecode(aws_sqs_queue.network_incident_redrive_fault[0].redrive_policy).maxReceiveCount == 3
      && jsondecode(aws_sqs_queue.network_incident_redrive_fault_dlq[0].redrive_allow_policy).redrivePermission == "byQueue"
      && jsondecode(aws_sqs_queue.network_incident_redrive_fault_dlq[0].redrive_allow_policy).sourceQueueArns == ["arn:aws:sqs:eu-central-1:123456789012:ml-platform-network-incidents-fault-injection"]
    )
    error_message = "The fault route must use the bounded receive count and exact byQueue admission policy."
  }

  assert {
    condition = alltrue([
      for policy in aws_sqs_queue_policy.network_incident_redrive_fault :
      jsondecode(policy.policy).Statement[0].Principal.AWS == "arn:aws:iam::123456789012:role/network-incident-redrive-canary"
      && jsondecode(policy.policy).Statement[1].Effect == "Deny"
      && jsondecode(policy.policy).Statement[1].Condition.Bool["aws:SecureTransport"] == "false"
    ])
    error_message = "Both queues must grant only the canary role and deny insecure transport."
  }
}

run "redrive_drill_binds_oidc_to_one_environment" {
  command = plan

  variables {
    enable_network_incident_redrive_drill             = true
    network_incident_redrive_production_queue_arn     = "arn:aws:sqs:eu-central-1:123456789012:ml-platform-network-incidents-consumer"
    network_incident_redrive_github_oidc_provider_arn = "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
    network_incident_redrive_github_repository        = "cagataykavas/aws-ml-platform"
    network_incident_redrive_github_environment       = "redrive-staging"
  }

  assert {
    condition = (
      length(aws_iam_role.network_incident_redrive_canary) == 1
      && length(aws_iam_role_policy.network_incident_redrive_canary) == 1
      && length(aws_iam_role_policy.network_incident_redrive_evidence) == 1
      && jsondecode(aws_iam_role.network_incident_redrive_canary[0].assume_role_policy).Statement[0].Principal.Federated == "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
      && jsondecode(aws_iam_role.network_incident_redrive_canary[0].assume_role_policy).Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:aud"] == "sts.amazonaws.com"
      && jsondecode(aws_iam_role.network_incident_redrive_canary[0].assume_role_policy).Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:sub"] == "repo:cagataykavas/aws-ml-platform:environment:redrive-staging"
    )
    error_message = "The role trust must bind the exact provider, audience, repository and protected Environment."
  }

  assert {
    condition = (
      toset(jsondecode(aws_iam_role_policy.network_incident_redrive_canary[0].policy).Statement[0].Action) == toset([
        "sqs:ChangeMessageVisibility",
        "sqs:DeleteMessage",
        "sqs:GetQueueAttributes",
        "sqs:GetQueueUrl",
        "sqs:ReceiveMessage",
        "sqs:SendMessage",
      ])
      && jsondecode(aws_iam_role_policy.network_incident_redrive_canary[0].policy).Statement[0].Resource == "arn:aws:sqs:eu-central-1:123456789012:ml-platform-network-incidents-fault-injection"
      && jsondecode(aws_iam_role_policy.network_incident_redrive_canary[0].policy).Statement[1].Resource == "arn:aws:sqs:eu-central-1:123456789012:ml-platform-network-incidents-fault-injection-dlq"
      && toset(jsondecode(aws_iam_role_policy.network_incident_redrive_canary[0].policy).Statement[2].Action) == toset([
        "iam:GetRole",
        "iam:GetRolePolicy",
      ])
      && jsondecode(aws_iam_role_policy.network_incident_redrive_canary[0].policy).Statement[2].Resource == "arn:aws:iam::123456789012:role/network-incident-redrive-canary"
      && !strcontains(aws_iam_role_policy.network_incident_redrive_canary[0].policy, "ml-platform-network-incidents-consumer")
    )
    error_message = "The role policy must contain only the drill actions and never the production queue."
  }

  assert {
    condition = (
      jsondecode(aws_kms_key.network_incident_redrive_evidence[0].policy).Statement[1].Principal.AWS == "arn:aws:iam::123456789012:role/network-incident-redrive-canary"
      && toset(jsondecode(aws_kms_key.network_incident_redrive_evidence[0].policy).Statement[1].Action) == toset([
        "kms:DescribeKey",
        "kms:GetPublicKey",
        "kms:Sign",
        "kms:Verify",
      ])
    )
    error_message = "The key policy must grant only evidence operations to the canary role."
  }

  assert {
    condition = (
      output.network_incident_redrive_drill.github_environment_variables.AWS_REGION == "eu-central-1"
      && output.network_incident_redrive_drill.github_environment_variables.AWS_ACCOUNT_ID == "123456789012"
      && output.network_incident_redrive_drill.github_environment_variables.AWS_REDRIVE_CANARY_ROLE_ARN == "arn:aws:iam::123456789012:role/network-incident-redrive-canary"
      && output.network_incident_redrive_drill.github_environment_variables.NETWORK_INCIDENT_REDRIVE_OIDC_SUBJECT == "repo:cagataykavas/aws-ml-platform:environment:redrive-staging"
      && output.network_incident_redrive_drill.github_environment_variables.NETWORK_INCIDENT_QUEUE_ARN == "arn:aws:sqs:eu-central-1:123456789012:ml-platform-network-incidents-consumer"
      && output.network_incident_redrive_drill.github_environment_variables.NETWORK_INCIDENT_FAULT_QUEUE_ARN == "arn:aws:sqs:eu-central-1:123456789012:ml-platform-network-incidents-fault-injection"
      && output.network_incident_redrive_drill.github_environment_variables.NETWORK_INCIDENT_FAULT_DLQ_ARN == "arn:aws:sqs:eu-central-1:123456789012:ml-platform-network-incidents-fault-injection-dlq"
    )
    error_message = "The output must provide the exact protected Environment configuration."
  }
}

run "redrive_drill_requires_all_trust_boundaries" {
  command = plan

  variables {
    enable_network_incident_redrive_drill = true
  }

  expect_failures = [terraform_data.network_incident_redrive_drill_contract[0]]
}

run "redrive_drill_rejects_cross_region_production_boundary" {
  command = plan

  variables {
    enable_network_incident_redrive_drill             = true
    network_incident_redrive_production_queue_arn     = "arn:aws:sqs:us-east-1:123456789012:production"
    network_incident_redrive_github_oidc_provider_arn = "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
    network_incident_redrive_github_repository        = "cagataykavas/aws-ml-platform"
    network_incident_redrive_github_environment       = "redrive-staging"
  }

  expect_failures = [terraform_data.network_incident_redrive_drill_contract[0]]
}

run "redrive_drill_rejects_cross_account_oidc_provider" {
  command = plan

  variables {
    enable_network_incident_redrive_drill             = true
    network_incident_redrive_production_queue_arn     = "arn:aws:sqs:eu-central-1:123456789012:production"
    network_incident_redrive_github_oidc_provider_arn = "arn:aws:iam::210987654321:oidc-provider/token.actions.githubusercontent.com"
    network_incident_redrive_github_repository        = "cagataykavas/aws-ml-platform"
    network_incident_redrive_github_environment       = "redrive-staging"
  }

  expect_failures = [terraform_data.network_incident_redrive_drill_contract[0]]
}

run "redrive_drill_rejects_unbounded_receive_count" {
  command = plan

  variables {
    network_incident_redrive_max_receive_count = 6
  }

  expect_failures = [var.network_incident_redrive_max_receive_count]
}

run "redrive_drill_rejects_unsafe_environment_subject" {
  command = plan

  variables {
    network_incident_redrive_github_environment = "unsafe:environment"
  }

  expect_failures = [var.network_incident_redrive_github_environment]
}

run "redrive_archive_is_compliance_locked_and_least_privilege" {
  command = plan

  variables {
    enable_network_incident_redrive_drill                 = true
    enable_network_incident_redrive_evidence_archive      = true
    network_incident_redrive_production_queue_arn         = "arn:aws:sqs:eu-central-1:123456789012:ml-platform-network-incidents-consumer"
    network_incident_redrive_github_oidc_provider_arn     = "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
    network_incident_redrive_github_repository            = "cagataykavas/aws-ml-platform"
    network_incident_redrive_github_environment           = "redrive-staging"
    network_incident_redrive_evidence_archive_bucket_name = "ml-platform-redrive-evidence-123456789012"
    network_incident_redrive_evidence_retention_days      = 30
  }

  assert {
    condition = (
      length(aws_s3_bucket.network_incident_redrive_evidence_archive) == 1
      && aws_s3_bucket.network_incident_redrive_evidence_archive[0].object_lock_enabled
      && aws_s3_bucket_versioning.network_incident_redrive_evidence_archive[0].versioning_configuration[0].status == "Enabled"
      && aws_s3_bucket_object_lock_configuration.network_incident_redrive_evidence_archive[0].object_lock_enabled == "Enabled"
      && aws_s3_bucket_object_lock_configuration.network_incident_redrive_evidence_archive[0].rule[0].default_retention[0].mode == "COMPLIANCE"
      && aws_s3_bucket_object_lock_configuration.network_incident_redrive_evidence_archive[0].rule[0].default_retention[0].days == 30
      && aws_s3_bucket_public_access_block.network_incident_redrive_evidence_archive[0].block_public_acls
      && aws_s3_bucket_public_access_block.network_incident_redrive_evidence_archive[0].block_public_policy
      && aws_s3_bucket_public_access_block.network_incident_redrive_evidence_archive[0].ignore_public_acls
      && aws_s3_bucket_public_access_block.network_incident_redrive_evidence_archive[0].restrict_public_buckets
      && aws_s3_bucket_server_side_encryption_configuration.network_incident_redrive_evidence_archive[0].rule[0].apply_server_side_encryption_by_default[0].sse_algorithm == "AES256"
    )
    error_message = "The evidence archive must use versioning, compliance Object Lock, full public blocking and encryption."
  }

  assert {
    condition = (
      toset(jsondecode(aws_iam_role_policy.network_incident_redrive_archive[0].policy).Statement[0].Action) == toset([
        "s3:GetBucketObjectLockConfiguration",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketVersioning",
      ])
      && jsondecode(aws_iam_role_policy.network_incident_redrive_archive[0].policy).Statement[0].Resource == "arn:aws:s3:::ml-platform-redrive-evidence-123456789012"
      && toset(jsondecode(aws_iam_role_policy.network_incident_redrive_archive[0].policy).Statement[1].Action) == toset([
        "s3:GetObjectRetention",
        "s3:PutObject",
      ])
      && jsondecode(aws_iam_role_policy.network_incident_redrive_archive[0].policy).Statement[1].Resource == "arn:aws:s3:::ml-platform-redrive-evidence-123456789012/redrive-evidence/v1/*"
      && !strcontains(aws_iam_role_policy.network_incident_redrive_archive[0].policy, "s3:DeleteObject")
      && !strcontains(aws_iam_role_policy.network_incident_redrive_archive[0].policy, "s3:BypassGovernanceRetention")
      && !strcontains(aws_iam_role_policy.network_incident_redrive_archive[0].policy, "s3:PutObjectRetention")
    )
    error_message = "The runner may inspect the bucket, append evidence and verify retention, but cannot weaken or delete it."
  }

  assert {
    condition = (
      output.network_incident_redrive_drill.github_environment_variables.NETWORK_INCIDENT_REDRIVE_ARCHIVE_BUCKET == "ml-platform-redrive-evidence-123456789012"
      && output.network_incident_redrive_drill.github_environment_variables.NETWORK_INCIDENT_REDRIVE_ARCHIVE_RETENTION_DAYS == "30"
    )
    error_message = "The protected Environment output must include the exact archive contract."
  }
}

run "redrive_archive_requires_drill_and_bucket" {
  command = plan

  variables {
    enable_network_incident_redrive_evidence_archive = true
  }

  expect_failures = [terraform_data.network_incident_redrive_archive_contract[0]]
}
