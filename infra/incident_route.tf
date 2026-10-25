data "aws_caller_identity" "current" {}

data "aws_partition" "current" {}

locals {
  managed_network_incident_queue_alarm_names = [
    "${var.managed_network_incident_topic_name}-consumer-age",
    "${var.managed_network_incident_topic_name}-consumer-dlq",
  ]
  managed_network_incident_base_alarm_names = [
    "ml-platform-rejected-packets",
    "ml-platform-flow-log-delivery-health",
  ]
  managed_network_incident_topic_arn = "arn:${data.aws_partition.current.partition}:sns:${var.aws_region}:${data.aws_caller_identity.current.account_id}:${var.managed_network_incident_topic_name}"
  managed_network_incident_queue_arn = "arn:${data.aws_partition.current.partition}:sqs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:${var.managed_network_incident_topic_name}-consumer"
  managed_network_incident_dlq_arn   = "arn:${data.aws_partition.current.partition}:sqs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:${var.managed_network_incident_topic_name}-consumer-dlq"
  managed_network_incident_queue_arns = [
    local.managed_network_incident_queue_arn,
    local.managed_network_incident_dlq_arn,
  ]
  managed_network_incident_queue_allowed_sources = [
    [local.managed_network_incident_topic_arn],
    [local.managed_network_incident_topic_arn, local.managed_network_incident_queue_arn],
  ]
  managed_network_incident_queue_enabled = (
    var.enable_managed_network_incident_queue
    && var.enable_managed_network_incident_topic
    && var.managed_network_incident_consumer_role_arn != null
  )
  managed_network_incident_queue_health_action_arns = distinct(concat(
    [local.managed_network_incident_topic_arn],
    var.managed_network_incident_queue_escalation_actions,
  ))
  managed_network_incident_alarm_names = concat(
    local.managed_network_incident_base_alarm_names,
    local.managed_network_incident_queue_enabled ? local.managed_network_incident_queue_alarm_names : [],
  )
  managed_network_incident_alarm_arns = [
    for name in local.managed_network_incident_alarm_names :
    "arn:${data.aws_partition.current.partition}:cloudwatch:${var.aws_region}:${data.aws_caller_identity.current.account_id}:alarm:${name}"
  ]
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
    Statement = concat(
      [{
        Sid    = "AccountAdministration"
        Effect = "Allow"
        Principal = {
          AWS = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
        }, {
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
      }],
      [for statement in [{
        Sid    = "SnsEncryptedQueueDelivery"
        Effect = "Allow"
        Principal = {
          Service = "sns.amazonaws.com"
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey*",
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
          ArnEquals = {
            "aws:SourceArn" = local.managed_network_incident_topic_arn
          }
        }
        }, {
        Sid    = "ConsumerQueueDecryption"
        Effect = "Allow"
        Principal = {
          AWS = var.managed_network_incident_consumer_role_arn
        }
        Action   = "kms:Decrypt"
        Resource = "*"
        Condition = {
          ArnEquals = {
            "kms:EncryptionContext:aws:sqs:arn" = local.managed_network_incident_queue_arns
          }
        }
      }] : statement if local.managed_network_incident_queue_enabled],
    )
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

resource "terraform_data" "managed_network_incident_queue_contract" {
  count = var.enable_managed_network_incident_queue ? 1 : 0

  input = {
    topic_enabled      = var.enable_managed_network_incident_topic
    consumer_role_arn  = var.managed_network_incident_consumer_role_arn
    escalation_actions = var.managed_network_incident_queue_escalation_actions
  }

  lifecycle {
    precondition {
      condition     = var.enable_managed_network_incident_topic
      error_message = "The managed incident queue requires the managed incident topic."
    }

    precondition {
      condition     = var.managed_network_incident_consumer_role_arn != null
      error_message = "The managed incident queue requires an explicit consumer role ARN."
    }

    precondition {
      condition     = length(var.managed_network_incident_topic_name) <= 67
      error_message = "The managed topic name must be at most 67 characters when deriving queue names."
    }

    precondition {
      condition     = length(var.managed_network_incident_queue_escalation_actions) > 0
      error_message = "The managed incident queue requires at least one independent queue-health escalation action."
    }

    precondition {
      condition = alltrue([
        for action in var.managed_network_incident_queue_escalation_actions :
        action != local.managed_network_incident_topic_arn
      ])
      error_message = "Queue-health escalation actions must be independent of the managed incident topic."
    }

    precondition {
      condition = alltrue([
        for action in var.managed_network_incident_queue_escalation_actions :
        split(":", action)[1] == data.aws_partition.current.partition
        && split(":", action)[3] == var.aws_region
      ])
      error_message = "Queue-health escalation actions must use the deployment partition and Region."
    }

    precondition {
      condition = alltrue([
        for action in var.managed_network_incident_queue_escalation_actions :
        split(":", action)[2] != "sns"
        || split(":", action)[4] == data.aws_caller_identity.current.account_id
      ])
      error_message = "Queue-health SNS actions must be owned by the alarm account; use a scoped Lambda relay for cross-account delivery."
    }
  }
}

resource "aws_sqs_queue" "network_incident_dlq" {
  count = local.managed_network_incident_queue_enabled ? 1 : 0

  name                              = "${var.managed_network_incident_topic_name}-consumer-dlq"
  kms_master_key_id                 = aws_kms_key.network_incidents[0].arn
  kms_data_key_reuse_period_seconds = 300
  message_retention_seconds         = 1209600
  redrive_allow_policy = jsonencode({
    redrivePermission = "byQueue"
    sourceQueueArns   = [local.managed_network_incident_queue_arn]
  })

  tags = {
    Workload = "ml-platform"
    Purpose  = "network-incident-dead-letter"
  }
}

resource "aws_sqs_queue" "network_incidents" {
  count = local.managed_network_incident_queue_enabled ? 1 : 0

  name                              = "${var.managed_network_incident_topic_name}-consumer"
  kms_master_key_id                 = aws_kms_key.network_incidents[0].arn
  kms_data_key_reuse_period_seconds = 300
  message_retention_seconds         = 345600
  visibility_timeout_seconds        = 60
  redrive_policy = jsonencode({
    deadLetterTargetArn = local.managed_network_incident_dlq_arn
    maxReceiveCount     = var.managed_network_incident_max_receive_count
  })

  tags = {
    Workload = "ml-platform"
    Purpose  = "network-incident-consumer"
  }
}

resource "aws_sqs_queue_policy" "network_incident_queues" {
  count = local.managed_network_incident_queue_enabled ? 2 : 0

  queue_url = count.index == 0 ? aws_sqs_queue.network_incidents[0].id : aws_sqs_queue.network_incident_dlq[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ExactTopicDelivery"
        Effect = "Allow"
        Principal = {
          Service = "sns.amazonaws.com"
        }
        Action   = "sqs:SendMessage"
        Resource = local.managed_network_incident_queue_arns[count.index]
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
          ArnEquals = {
            "aws:SourceArn" = local.managed_network_incident_topic_arn
          }
        }
      },
      {
        Sid    = "GovernedConsumer"
        Effect = "Allow"
        Principal = {
          AWS = var.managed_network_incident_consumer_role_arn
        }
        Action = [
          "sqs:ChangeMessageVisibility",
          "sqs:DeleteMessage",
          "sqs:GetQueueAttributes",
          "sqs:GetQueueUrl",
          "sqs:ReceiveMessage",
        ]
        Resource = local.managed_network_incident_queue_arns[count.index]
      },
      {
        Sid       = "DenyOtherConsumers"
        Effect    = "Deny"
        Principal = "*"
        Action = [
          "sqs:ChangeMessageVisibility",
          "sqs:DeleteMessage",
          "sqs:ReceiveMessage",
        ]
        Resource = local.managed_network_incident_queue_arns[count.index]
        Condition = {
          StringNotLike = {
            "aws:PrincipalArn" = var.managed_network_incident_consumer_role_arn
          }
        }
      },
      {
        Sid       = "DenyUnapprovedProducers"
        Effect    = "Deny"
        Principal = "*"
        Action    = "sqs:SendMessage"
        Resource  = local.managed_network_incident_queue_arns[count.index]
        Condition = {
          ArnNotLike = {
            "aws:SourceArn" = local.managed_network_incident_queue_allowed_sources[count.index]
          }
        }
      },
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "sqs:*"
        Resource  = local.managed_network_incident_queue_arns[count.index]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      },
    ]
  })
}

resource "aws_sns_topic_subscription" "network_incident_queue" {
  count = local.managed_network_incident_queue_enabled ? 1 : 0

  topic_arn            = aws_sns_topic.network_incidents[0].arn
  protocol             = "sqs"
  endpoint             = local.managed_network_incident_queue_arn
  raw_message_delivery = false
  redrive_policy = jsonencode({
    deadLetterTargetArn = local.managed_network_incident_dlq_arn
  })

  depends_on = [aws_sqs_queue_policy.network_incident_queues]
}

resource "aws_cloudwatch_metric_alarm" "network_incident_queue_age" {
  count = local.managed_network_incident_queue_enabled ? 1 : 0

  alarm_name          = local.managed_network_incident_queue_alarm_names[0]
  alarm_description   = "The oldest incident notification has exceeded its bounded processing age."
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  datapoints_to_alarm = 3
  metric_name         = "ApproximateAgeOfOldestMessage"
  namespace           = "AWS/SQS"
  period              = 60
  statistic           = "Maximum"
  threshold           = var.managed_network_incident_queue_age_threshold_seconds
  treat_missing_data  = "notBreaching"
  alarm_actions       = local.managed_network_incident_queue_health_action_arns
  ok_actions          = local.managed_network_incident_queue_health_action_arns

  dimensions = {
    QueueName = aws_sqs_queue.network_incidents[0].name
  }

  depends_on = [aws_sns_topic_policy.network_incidents]
}

resource "aws_cloudwatch_metric_alarm" "network_incident_dead_letters" {
  count = local.managed_network_incident_queue_enabled ? 1 : 0

  alarm_name          = local.managed_network_incident_queue_alarm_names[1]
  alarm_description   = "The incident dead-letter queue contains at least one visible message."
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  datapoints_to_alarm = 1
  metric_name         = "ApproximateNumberOfMessagesVisible"
  namespace           = "AWS/SQS"
  period              = 60
  statistic           = "Maximum"
  threshold           = 0
  treat_missing_data  = "notBreaching"
  alarm_actions       = local.managed_network_incident_queue_health_action_arns
  ok_actions          = local.managed_network_incident_queue_health_action_arns

  dimensions = {
    QueueName = aws_sqs_queue.network_incident_dlq[0].name
  }

  depends_on = [aws_sns_topic_policy.network_incidents]
}

output "managed_network_incident_route" {
  value = var.enable_managed_network_incident_topic ? {
    topic_arn             = local.managed_network_incident_topic_arn
    kms_key_arn           = aws_kms_key.network_incidents[0].arn
    queue_arn             = local.managed_network_incident_queue_enabled ? local.managed_network_incident_queue_arn : null
    dead_letter_queue_arn = local.managed_network_incident_queue_enabled ? local.managed_network_incident_dlq_arn : null
    queue_health_alarms   = local.managed_network_incident_queue_enabled ? local.managed_network_incident_queue_alarm_names : []
    queue_health_actions  = local.managed_network_incident_queue_enabled ? local.managed_network_incident_queue_health_action_arns : []
  } : null
  description = "Encrypted managed alarm route and optional durable subscriber; null when disabled."
}
