locals {
  network_incident_redrive_fault_queue_arn = "arn:${data.aws_partition.current.partition}:sqs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:${var.network_incident_redrive_queue_name}"
  network_incident_redrive_fault_dlq_arn   = "${local.network_incident_redrive_fault_queue_arn}-dlq"
  network_incident_redrive_role_arn        = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:role/${var.network_incident_redrive_role_name}"
  network_incident_redrive_oidc_subject = (
    var.network_incident_redrive_github_repository != null
    && var.network_incident_redrive_github_environment != null
    ? "repo:${var.network_incident_redrive_github_repository}:environment:${var.network_incident_redrive_github_environment}"
    : null
  )
  network_incident_redrive_production_queue_parts = split(
    ":",
    var.network_incident_redrive_production_queue_arn != null ? var.network_incident_redrive_production_queue_arn : "",
  )
  network_incident_redrive_oidc_provider_parts = split(
    ":",
    var.network_incident_redrive_github_oidc_provider_arn != null ? var.network_incident_redrive_github_oidc_provider_arn : "",
  )
  network_incident_redrive_queue_arns = [
    local.network_incident_redrive_fault_queue_arn,
    local.network_incident_redrive_fault_dlq_arn,
  ]
}

resource "terraform_data" "network_incident_redrive_drill_contract" {
  count = var.enable_network_incident_redrive_drill ? 1 : 0

  input = {
    production_queue_arn = var.network_incident_redrive_production_queue_arn
    oidc_provider_arn    = var.network_incident_redrive_github_oidc_provider_arn
    github_repository    = var.network_incident_redrive_github_repository
    github_environment   = var.network_incident_redrive_github_environment
  }

  lifecycle {
    precondition {
      condition     = var.network_incident_redrive_production_queue_arn != null
      error_message = "The redrive drill requires an explicit production queue ARN as an isolation boundary."
    }

    precondition {
      condition = try(
        local.network_incident_redrive_production_queue_parts[1] == data.aws_partition.current.partition
        && local.network_incident_redrive_production_queue_parts[2] == "sqs"
        && local.network_incident_redrive_production_queue_parts[3] == var.aws_region
        && local.network_incident_redrive_production_queue_parts[4] == data.aws_caller_identity.current.account_id,
        false,
      )
      error_message = "The production isolation boundary must be an SQS queue in the deployment partition, Region and account."
    }

    precondition {
      condition = (
        var.network_incident_redrive_production_queue_arn != local.network_incident_redrive_fault_queue_arn
        && var.network_incident_redrive_production_queue_arn != local.network_incident_redrive_fault_dlq_arn
      )
      error_message = "Production, fault-injection and fault-DLQ queues must be distinct."
    }

    precondition {
      condition     = var.network_incident_redrive_github_oidc_provider_arn != null
      error_message = "The redrive drill requires the existing account-local GitHub OIDC provider ARN."
    }

    precondition {
      condition = try(
        local.network_incident_redrive_oidc_provider_parts[1] == data.aws_partition.current.partition
        && local.network_incident_redrive_oidc_provider_parts[2] == "iam"
        && local.network_incident_redrive_oidc_provider_parts[4] == data.aws_caller_identity.current.account_id
        && local.network_incident_redrive_oidc_provider_parts[5] == "oidc-provider/token.actions.githubusercontent.com",
        false,
      )
      error_message = "The GitHub OIDC provider must be token.actions.githubusercontent.com in the deployment partition and account."
    }

    precondition {
      condition     = var.network_incident_redrive_github_repository != null
      error_message = "The redrive drill requires an explicit GitHub owner/repository trust boundary."
    }

    precondition {
      condition     = var.network_incident_redrive_github_environment != null
      error_message = "The redrive drill requires one explicit protected GitHub Environment."
    }
  }
}

resource "aws_sqs_queue" "network_incident_redrive_fault_dlq" {
  count = var.enable_network_incident_redrive_drill ? 1 : 0

  name                       = "${var.network_incident_redrive_queue_name}-dlq"
  message_retention_seconds  = var.network_incident_redrive_message_retention_seconds
  sqs_managed_sse_enabled    = true
  visibility_timeout_seconds = var.network_incident_redrive_visibility_timeout_seconds
  redrive_allow_policy = jsonencode({
    redrivePermission = "byQueue"
    sourceQueueArns   = [local.network_incident_redrive_fault_queue_arn]
  })

  tags = {
    Workload = "ml-platform"
    Purpose  = "network-incident-redrive-fault-dlq"
  }

  depends_on = [terraform_data.network_incident_redrive_drill_contract]
}

resource "aws_sqs_queue" "network_incident_redrive_fault" {
  count = var.enable_network_incident_redrive_drill ? 1 : 0

  name                       = var.network_incident_redrive_queue_name
  message_retention_seconds  = var.network_incident_redrive_message_retention_seconds
  sqs_managed_sse_enabled    = true
  visibility_timeout_seconds = var.network_incident_redrive_visibility_timeout_seconds
  redrive_policy = jsonencode({
    deadLetterTargetArn = local.network_incident_redrive_fault_dlq_arn
    maxReceiveCount     = var.network_incident_redrive_max_receive_count
  })

  tags = {
    Workload = "ml-platform"
    Purpose  = "network-incident-redrive-fault-source"
  }

  depends_on = [aws_sqs_queue.network_incident_redrive_fault_dlq]
}

resource "aws_iam_role" "network_incident_redrive_canary" {
  count = var.enable_network_incident_redrive_drill ? 1 : 0

  name                 = var.network_incident_redrive_role_name
  max_session_duration = 3600
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "GitHubEnvironmentOidc"
      Effect = "Allow"
      Principal = {
        Federated = var.network_incident_redrive_github_oidc_provider_arn
      }
      Action = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          "token.actions.githubusercontent.com:sub" = local.network_incident_redrive_oidc_subject
        }
      }
    }]
  })

  tags = {
    Workload = "ml-platform"
    Purpose  = "network-incident-redrive-canary"
  }

  depends_on = [terraform_data.network_incident_redrive_drill_contract]
}

resource "aws_kms_key" "network_incident_redrive_evidence" {
  count = var.enable_network_incident_redrive_drill ? 1 : 0

  description              = "Asymmetric signing key for network incident redrive evidence"
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "ECC_NIST_P256"
  deletion_window_in_days  = 30
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AccountAdministration"
        Effect = "Allow"
        Principal = {
          AWS = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "SignAndVerifyDrillEvidence"
        Effect = "Allow"
        Principal = {
          AWS = local.network_incident_redrive_role_arn
        }
        Action = [
          "kms:DescribeKey",
          "kms:GetPublicKey",
          "kms:Sign",
          "kms:Verify",
        ]
        Resource = "*"
      },
    ]
  })

  tags = {
    Workload = "ml-platform"
    Purpose  = "network-incident-redrive-evidence-signing"
  }

  depends_on = [aws_iam_role.network_incident_redrive_canary]
}

resource "aws_iam_role_policy" "network_incident_redrive_canary" {
  count = var.enable_network_incident_redrive_drill ? 1 : 0

  name = "network-incident-redrive-canary"
  role = aws_iam_role.network_incident_redrive_canary[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ExerciseFaultSource"
        Effect = "Allow"
        Action = [
          "sqs:ChangeMessageVisibility",
          "sqs:DeleteMessage",
          "sqs:GetQueueAttributes",
          "sqs:GetQueueUrl",
          "sqs:ReceiveMessage",
          "sqs:SendMessage",
        ]
        Resource = local.network_incident_redrive_fault_queue_arn
      },
      {
        Sid    = "VerifyFaultDeadLetters"
        Effect = "Allow"
        Action = [
          "sqs:DeleteMessage",
          "sqs:GetQueueAttributes",
          "sqs:GetQueueUrl",
          "sqs:ReceiveMessage",
        ]
        Resource = local.network_incident_redrive_fault_dlq_arn
      },
      {
        Sid    = "InspectCanaryBoundary"
        Effect = "Allow"
        Action = [
          "iam:GetRole",
          "iam:GetRolePolicy",
        ]
        Resource = local.network_incident_redrive_role_arn
      },
    ]
  })
}

resource "aws_iam_role_policy" "network_incident_redrive_evidence" {
  count = var.enable_network_incident_redrive_drill ? 1 : 0

  name = "network-incident-redrive-evidence"
  role = aws_iam_role.network_incident_redrive_canary[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "SignDrillEvidence"
      Effect = "Allow"
      Action = [
        "kms:DescribeKey",
        "kms:GetPublicKey",
        "kms:Sign",
        "kms:Verify",
      ]
      Resource = aws_kms_key.network_incident_redrive_evidence[0].arn
    }]
  })
}

resource "aws_sqs_queue_policy" "network_incident_redrive_fault" {
  count = var.enable_network_incident_redrive_drill ? 2 : 0

  queue_url = count.index == 0 ? aws_sqs_queue.network_incident_redrive_fault[0].id : aws_sqs_queue.network_incident_redrive_fault_dlq[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ExactCanaryRole"
        Effect = "Allow"
        Principal = {
          AWS = local.network_incident_redrive_role_arn
        }
        Action = count.index == 0 ? [
          "sqs:ChangeMessageVisibility",
          "sqs:DeleteMessage",
          "sqs:GetQueueAttributes",
          "sqs:GetQueueUrl",
          "sqs:ReceiveMessage",
          "sqs:SendMessage",
          ] : [
          "sqs:DeleteMessage",
          "sqs:GetQueueAttributes",
          "sqs:GetQueueUrl",
          "sqs:ReceiveMessage",
        ]
        Resource = local.network_incident_redrive_queue_arns[count.index]
      },
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "sqs:*"
        Resource  = local.network_incident_redrive_queue_arns[count.index]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      },
    ]
  })
}

output "network_incident_redrive_drill" {
  value = var.enable_network_incident_redrive_drill ? {
    production_queue_arn        = var.network_incident_redrive_production_queue_arn
    fault_queue_arn             = local.network_incident_redrive_fault_queue_arn
    fault_dead_letter_queue_arn = local.network_incident_redrive_fault_dlq_arn
    redrive_canary_role_arn     = local.network_incident_redrive_role_arn
    redrive_evidence_key_arn    = aws_kms_key.network_incident_redrive_evidence[0].arn
    github_oidc_subject         = local.network_incident_redrive_oidc_subject
    github_environment_variables = {
      AWS_REGION                                = var.aws_region
      AWS_ACCOUNT_ID                            = data.aws_caller_identity.current.account_id
      AWS_REDRIVE_CANARY_ROLE_ARN               = local.network_incident_redrive_role_arn
      NETWORK_INCIDENT_REDRIVE_OIDC_SUBJECT     = local.network_incident_redrive_oidc_subject
      NETWORK_INCIDENT_QUEUE_ARN                = var.network_incident_redrive_production_queue_arn
      NETWORK_INCIDENT_FAULT_QUEUE_ARN          = local.network_incident_redrive_fault_queue_arn
      NETWORK_INCIDENT_FAULT_DLQ_ARN            = local.network_incident_redrive_fault_dlq_arn
      NETWORK_INCIDENT_REDRIVE_EVIDENCE_KEY_ARN = aws_kms_key.network_incident_redrive_evidence[0].arn
    }
  } : null
  description = "Isolated redrive route and protected GitHub Environment values; null when disabled."
}
