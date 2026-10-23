data "aws_caller_identity" "current" {}

data "aws_partition" "current" {}

locals {
  managed_network_incident_alarm_arns = [
    "arn:${data.aws_partition.current.partition}:cloudwatch:${var.aws_region}:${data.aws_caller_identity.current.account_id}:alarm:ml-platform-rejected-packets",
    "arn:${data.aws_partition.current.partition}:cloudwatch:${var.aws_region}:${data.aws_caller_identity.current.account_id}:alarm:ml-platform-flow-log-delivery-health",
  ]
  managed_network_incident_topic_arn = "arn:${data.aws_partition.current.partition}:sns:${var.aws_region}:${data.aws_caller_identity.current.account_id}:${var.managed_network_incident_topic_name}"
  network_alarm_action_arns = distinct(concat(
    var.network_alarm_actions,
    var.enable_managed_network_incident_topic ? [local.managed_network_incident_topic_arn] : [],
  ))
}

resource "aws_kms_key" "network_incidents" {
  count = var.enable_managed_network_incident_topic ? 1 : 0

  description             = "Encrypts ML platform network incident notifications"
  deletion_window_in_days = 30
  enable_key_rotation     = true

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
        Sid    = "CloudWatchAlarmEncryption"
        Effect = "Allow"
        Principal = {
          Service = "cloudwatch.amazonaws.com"
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey*",
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:SourceAccount"                      = data.aws_caller_identity.current.account_id
            "kms:EncryptionContext:aws:sns:topicArn" = local.managed_network_incident_topic_arn
          }
          ArnEquals = {
            "aws:SourceArn" = local.managed_network_incident_alarm_arns
          }
        }
      },
    ]
  })

  tags = {
    Workload = "ml-platform"
    Purpose  = "network-incident-routing"
  }
}

resource "aws_sns_topic" "network_incidents" {
  count = var.enable_managed_network_incident_topic ? 1 : 0

  name              = var.managed_network_incident_topic_name
  kms_master_key_id = aws_kms_key.network_incidents[0].arn

  tags = {
    Workload = "ml-platform"
    Purpose  = "network-incident-routing"
  }
}

resource "aws_sns_topic_policy" "network_incidents" {
  count = var.enable_managed_network_incident_topic ? 1 : 0

  arn = aws_sns_topic.network_incidents[0].arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AccountAdministration"
        Effect = "Allow"
        Principal = {
          AWS = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "SNS:*"
        Resource = local.managed_network_incident_topic_arn
      },
      {
        Sid    = "CloudWatchAlarmPublish"
        Effect = "Allow"
        Principal = {
          Service = "cloudwatch.amazonaws.com"
        }
        Action   = "SNS:Publish"
        Resource = local.managed_network_incident_topic_arn
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
          ArnEquals = {
            "aws:SourceArn" = local.managed_network_incident_alarm_arns
          }
        }
      },
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "SNS:*"
        Resource  = local.managed_network_incident_topic_arn
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      },
    ]
  })
}

output "managed_network_incident_route" {
  value = var.enable_managed_network_incident_topic ? {
    topic_arn   = local.managed_network_incident_topic_arn
    kms_key_arn = aws_kms_key.network_incidents[0].arn
  } : null
  description = "Encrypted managed alarm route; null when the opt-in is disabled."
}
