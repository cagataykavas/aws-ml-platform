variable "enable_backend_consumption_oidc_failure_alert" {
  type        = bool
  default     = false
  description = "Route failed OIDC assumptions of the backend-consumption auditor role to the managed incident topic."
}

locals {
  backend_consumption_oidc_failure_rule_name          = "ml-platform-backend-consumption-oidc-failures"
  backend_consumption_oidc_failure_rule_arn           = "arn:${data.aws_partition.current.partition}:events:${var.aws_region}:${data.aws_caller_identity.current.account_id}:rule/${local.backend_consumption_oidc_failure_rule_name}"
  backend_consumption_oidc_failure_delivery_role_name = "ml-platform-backend-consumption-oidc-alert"
  backend_consumption_oidc_failure_delivery_role_arn  = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:role/${local.backend_consumption_oidc_failure_delivery_role_name}"
}

resource "terraform_data" "backend_consumption_oidc_failure_alert_contract" {
  count = var.enable_backend_consumption_oidc_failure_alert ? 1 : 0

  input = {
    auditor_role_enabled  = var.enable_backend_consumption_auditor_role
    managed_topic_enabled = var.enable_managed_network_incident_topic
    monitored_role_arn    = local.backend_consumption_auditor_role_arn
    incident_topic_arn    = local.managed_network_incident_topic_arn
  }

  lifecycle {
    precondition {
      condition     = var.enable_backend_consumption_auditor_role
      error_message = "The OIDC failure alert requires the backend-consumption auditor role."
    }

    precondition {
      condition     = var.enable_managed_network_incident_topic
      error_message = "The OIDC failure alert requires the managed network incident topic."
    }
  }
}

resource "aws_cloudwatch_event_rule" "backend_consumption_oidc_failure" {
  count = var.enable_backend_consumption_oidc_failure_alert ? 1 : 0

  name        = local.backend_consumption_oidc_failure_rule_name
  description = "Detect failed AssumeRoleWithWebIdentity calls for the backend-consumption auditor."
  state       = "ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS"
  event_pattern = jsonencode({
    source        = ["aws.sts"]
    "detail-type" = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["sts.amazonaws.com"]
      eventName   = ["AssumeRoleWithWebIdentity"]
      requestParameters = {
        roleArn = [local.backend_consumption_auditor_role_arn]
      }
      errorCode = [{ exists = true }]
    }
  })

  tags = {
    Workload = "ml-platform"
    Signal   = "backend-consumption-oidc-failure"
  }

  depends_on = [terraform_data.backend_consumption_oidc_failure_alert_contract]
}

resource "aws_iam_role" "backend_consumption_oidc_failure_delivery" {
  count = var.enable_backend_consumption_oidc_failure_alert ? 1 : 0

  name = local.backend_consumption_oidc_failure_delivery_role_name
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "EventBridgeRuleOnly"
      Effect = "Allow"
      Principal = {
        Service = "events.amazonaws.com"
      }
      Action = "sts:AssumeRole"
      Condition = {
        StringEquals = {
          "aws:SourceAccount" = data.aws_caller_identity.current.account_id
        }
        ArnEquals = {
          "aws:SourceArn" = local.backend_consumption_oidc_failure_rule_arn
        }
      }
    }]
  })

  tags = {
    Workload = "ml-platform"
    Purpose  = "backend-consumption-oidc-failure-delivery"
  }

  depends_on = [terraform_data.backend_consumption_oidc_failure_alert_contract]
}

resource "aws_iam_role_policy" "backend_consumption_oidc_failure_delivery" {
  count = (
    var.enable_backend_consumption_oidc_failure_alert
    && var.enable_managed_network_incident_topic
  ) ? 1 : 0

  name = "publish-encrypted-oidc-failure-alert"
  role = aws_iam_role.backend_consumption_oidc_failure_delivery[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "PublishIncident"
        Effect   = "Allow"
        Action   = "sns:Publish"
        Resource = local.managed_network_incident_topic_arn
      },
      {
        Sid    = "EncryptIncident"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey*",
        ]
        Resource = aws_kms_key.network_incidents[0].arn
        Condition = {
          StringEquals = {
            "kms:EncryptionContext:aws:sns:topicArn" = local.managed_network_incident_topic_arn
            "kms:ViaService"                         = "sns.${var.aws_region}.amazonaws.com"
          }
        }
      },
    ]
  })
}

resource "aws_cloudwatch_event_target" "backend_consumption_oidc_failure" {
  count = (
    var.enable_backend_consumption_oidc_failure_alert
    && var.enable_managed_network_incident_topic
  ) ? 1 : 0

  rule      = aws_cloudwatch_event_rule.backend_consumption_oidc_failure[0].name
  target_id = "managed-incident-topic"
  arn       = local.managed_network_incident_topic_arn
  role_arn  = aws_iam_role.backend_consumption_oidc_failure_delivery[0].arn

  depends_on = [
    aws_iam_role_policy.backend_consumption_oidc_failure_delivery,
    aws_sns_topic_policy.network_incidents,
  ]
}

output "backend_consumption_oidc_failure_alert" {
  value = var.enable_backend_consumption_oidc_failure_alert ? {
    rule_arn           = local.backend_consumption_oidc_failure_rule_arn
    monitored_role_arn = local.backend_consumption_auditor_role_arn
    incident_topic_arn = local.managed_network_incident_topic_arn
    delivery_role_arn  = local.backend_consumption_oidc_failure_delivery_role_arn
  } : null
  description = "Exact failed OIDC-assumption route for the backend-consumption auditor; null when disabled."
}
