variable "aws_region" {
  type        = string
  default     = "eu-central-1"
  description = "AWS region for the reference ML platform."
}

variable "ecs_cluster_name" {
  type        = string
  description = "Existing ECS cluster name hosting the inference service."
}

variable "ecs_service_name" {
  type        = string
  description = "Existing ECS service name registered for autoscaling."
}

variable "alb_dimension" {
  type        = string
  description = "Application Load Balancer CloudWatch dimension, e.g. app/name/id."
}

variable "vpc_flow_log_retention_days" {
  type        = number
  default     = 30
  description = "CloudWatch retention for VPC Flow Logs. Must be a supported retention value."

  validation {
    condition = contains([
      1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731,
      1096, 1827, 2192, 2557, 2922, 3288, 3653,
    ], var.vpc_flow_log_retention_days)
    error_message = "vpc_flow_log_retention_days must be a supported CloudWatch Logs retention value."
  }
}

variable "rejected_packet_alarm_threshold" {
  type        = number
  default     = 100
  description = "Rejected packet count in five minutes required to breach the network alarm."

  validation {
    condition = (
      var.rejected_packet_alarm_threshold >= 1
      && floor(var.rejected_packet_alarm_threshold) == var.rejected_packet_alarm_threshold
    )
    error_message = "rejected_packet_alarm_threshold must be a positive integer."
  }
}

variable "network_alarm_actions" {
  type        = list(string)
  default     = []
  description = "SNS topic or Lambda function ARNs invoked for network-alarm ALARM and OK transitions."

  validation {
    condition = alltrue([
      for action in var.network_alarm_actions :
      (
        can(regex("^arn:aws[a-z-]*:sns:[a-z0-9-]+:[0-9]{12}:[A-Za-z0-9_-]{1,256}$", action))
        || can(regex("^arn:aws[a-z-]*:lambda:[a-z0-9-]+:[0-9]{12}:function:[A-Za-z0-9_-]{1,64}(:[A-Za-z0-9_-]{1,129})?$", action))
      )
    ])
    error_message = "network_alarm_actions entries must be SNS topic or Lambda function ARNs."
  }

  validation {
    condition     = length(var.network_alarm_actions) == length(distinct(var.network_alarm_actions))
    error_message = "network_alarm_actions entries must be unique."
  }

  validation {
    condition     = length(var.network_alarm_actions) <= 5
    error_message = "At most five external network-alarm actions are allowed by CloudWatch."
  }
}

variable "enable_managed_network_incident_topic" {
  type        = bool
  default     = false
  description = "Create a KMS-encrypted SNS topic and attach it to both network alarms."
}

variable "managed_network_incident_topic_name" {
  type        = string
  default     = "ml-platform-network-incidents"
  description = "Name of the optional managed SNS topic for network alarm state changes."

  validation {
    condition = (
      length(var.managed_network_incident_topic_name) >= 1
      && length(var.managed_network_incident_topic_name) <= 256
      && can(regex("^[A-Za-z0-9_-]+$", var.managed_network_incident_topic_name))
    )
    error_message = "managed_network_incident_topic_name must be 1-256 characters containing only letters, numbers, hyphens and underscores."
  }
}

variable "enable_managed_network_incident_queue" {
  type        = bool
  default     = false
  description = "Create a KMS-encrypted SQS subscriber and dead-letter queue for the managed topic."
}

variable "managed_network_incident_consumer_role_arn" {
  type        = string
  default     = null
  nullable    = true
  description = "IAM role allowed to consume from the managed incident queue and its dead-letter queue."

  validation {
    condition = (
      var.managed_network_incident_consumer_role_arn == null
      || can(regex("^arn:aws[a-z-]*:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]+$", var.managed_network_incident_consumer_role_arn))
    )
    error_message = "managed_network_incident_consumer_role_arn must be null or an IAM role ARN."
  }
}

variable "managed_network_incident_queue_escalation_actions" {
  type        = list(string)
  default     = []
  description = "Independent SNS topic or Lambda function ARNs invoked for queue-health ALARM and OK transitions."

  validation {
    condition = alltrue([
      for action in var.managed_network_incident_queue_escalation_actions :
      (
        can(regex("^arn:aws[a-z-]*:sns:[a-z0-9-]+:[0-9]{12}:[A-Za-z0-9_-]{1,256}$", action))
        || can(regex("^arn:aws[a-z-]*:lambda:[a-z0-9-]+:[0-9]{12}:function:[A-Za-z0-9_-]{1,64}(:[A-Za-z0-9_-]{1,129})?$", action))
      )
    ])
    error_message = "managed_network_incident_queue_escalation_actions entries must be SNS topic or Lambda function ARNs."
  }

  validation {
    condition     = length(var.managed_network_incident_queue_escalation_actions) == length(distinct(var.managed_network_incident_queue_escalation_actions))
    error_message = "managed_network_incident_queue_escalation_actions entries must be unique."
  }

  validation {
    condition     = length(var.managed_network_incident_queue_escalation_actions) <= 4
    error_message = "At most four independent queue-health actions are allowed because the managed topic consumes the fifth CloudWatch action slot."
  }
}

variable "managed_network_incident_max_receive_count" {
  type        = number
  default     = 5
  description = "Failed consumer receives before an incident message moves to the dead-letter queue."

  validation {
    condition = (
      var.managed_network_incident_max_receive_count >= 1
      && var.managed_network_incident_max_receive_count <= 1000
      && floor(var.managed_network_incident_max_receive_count) == var.managed_network_incident_max_receive_count
    )
    error_message = "managed_network_incident_max_receive_count must be an integer from 1 to 1000."
  }
}

variable "managed_network_incident_queue_age_threshold_seconds" {
  type        = number
  default     = 300
  description = "Oldest visible incident-message age that indicates a stalled consumer."

  validation {
    condition = (
      var.managed_network_incident_queue_age_threshold_seconds >= 60
      && var.managed_network_incident_queue_age_threshold_seconds <= 86400
      && floor(var.managed_network_incident_queue_age_threshold_seconds) == var.managed_network_incident_queue_age_threshold_seconds
    )
    error_message = "managed_network_incident_queue_age_threshold_seconds must be an integer from 60 to 86400."
  }
}

variable "enable_network_incident_delivery_canary" {
  type        = bool
  default     = false
  description = "Create an isolated, message-filtered SQS queue for explicit SNS delivery canaries."
}

variable "network_incident_canary_role_arn" {
  type        = string
  default     = null
  nullable    = true
  description = "IAM role allowed to publish and consume only the isolated network-incident canary path."

  validation {
    condition = (
      var.network_incident_canary_role_arn == null
      || can(regex("^arn:aws[a-z-]*:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]+$", var.network_incident_canary_role_arn))
    )
    error_message = "network_incident_canary_role_arn must be null or an IAM role ARN."
  }
}

variable "enable_network_incident_redrive_drill" {
  type        = bool
  default     = false
  description = "Provision isolated non-production SQS redrive queues and an Environment-scoped GitHub OIDC runner role."
}

variable "network_incident_redrive_production_queue_arn" {
  type        = string
  default     = null
  nullable    = true
  description = "Production queue ARN used only as a fail-closed isolation boundary; the drill role receives no access to it."

  validation {
    condition = (
      var.network_incident_redrive_production_queue_arn == null
      || can(regex("^arn:aws[a-z-]*:sqs:[a-z0-9-]+:[0-9]{12}:[A-Za-z0-9_-]{1,80}$", var.network_incident_redrive_production_queue_arn))
    )
    error_message = "network_incident_redrive_production_queue_arn must be null or a canonical SQS queue ARN."
  }
}

variable "network_incident_redrive_queue_name" {
  type        = string
  default     = "ml-platform-network-incidents-fault-injection"
  description = "Dedicated non-production source queue name; its DLQ appends -dlq."

  validation {
    condition = (
      length(var.network_incident_redrive_queue_name) >= 16
      && length(var.network_incident_redrive_queue_name) <= 76
      && can(regex("^[A-Za-z0-9_-]+-fault-injection$", var.network_incident_redrive_queue_name))
    )
    error_message = "network_incident_redrive_queue_name must end in -fault-injection, use SQS-safe characters, and leave room for the -dlq suffix."
  }
}

variable "network_incident_redrive_max_receive_count" {
  type        = number
  default     = 3
  description = "Bounded poison-message receives before the isolated message moves to the drill DLQ."

  validation {
    condition = (
      var.network_incident_redrive_max_receive_count >= 2
      && var.network_incident_redrive_max_receive_count <= 5
      && floor(var.network_incident_redrive_max_receive_count) == var.network_incident_redrive_max_receive_count
    )
    error_message = "network_incident_redrive_max_receive_count must be an integer from 2 to 5."
  }
}

variable "network_incident_redrive_message_retention_seconds" {
  type        = number
  default     = 3600
  description = "Short non-production retention backstop for source and DLQ cleanup failures."

  validation {
    condition = (
      var.network_incident_redrive_message_retention_seconds >= 900
      && var.network_incident_redrive_message_retention_seconds <= 86400
      && floor(var.network_incident_redrive_message_retention_seconds) == var.network_incident_redrive_message_retention_seconds
    )
    error_message = "network_incident_redrive_message_retention_seconds must be an integer from 900 to 86400."
  }
}

variable "network_incident_redrive_visibility_timeout_seconds" {
  type        = number
  default     = 30
  description = "Visibility timeout used by the bounded fault-injection retry loop."

  validation {
    condition = (
      var.network_incident_redrive_visibility_timeout_seconds >= 5
      && var.network_incident_redrive_visibility_timeout_seconds <= 60
      && floor(var.network_incident_redrive_visibility_timeout_seconds) == var.network_incident_redrive_visibility_timeout_seconds
    )
    error_message = "network_incident_redrive_visibility_timeout_seconds must be an integer from 5 to 60."
  }
}

variable "network_incident_redrive_github_oidc_provider_arn" {
  type        = string
  default     = null
  nullable    = true
  description = "Existing account-local GitHub Actions OIDC provider ARN; Terraform does not create the account-wide provider."

  validation {
    condition = (
      var.network_incident_redrive_github_oidc_provider_arn == null
      || can(regex("^arn:aws[a-z-]*:iam::[0-9]{12}:oidc-provider/token[.]actions[.]githubusercontent[.]com$", var.network_incident_redrive_github_oidc_provider_arn))
    )
    error_message = "network_incident_redrive_github_oidc_provider_arn must identify token.actions.githubusercontent.com."
  }
}

variable "network_incident_redrive_github_repository" {
  type        = string
  default     = null
  nullable    = true
  description = "GitHub owner/repository allowed to assume the drill role through one protected Environment."

  validation {
    condition = (
      var.network_incident_redrive_github_repository == null
      || can(regex("^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", var.network_incident_redrive_github_repository))
    )
    error_message = "network_incident_redrive_github_repository must be null or owner/repository."
  }
}

variable "network_incident_redrive_github_environment" {
  type        = string
  default     = null
  nullable    = true
  description = "Protected GitHub Environment bound into the OIDC subject claim."

  validation {
    condition = (
      var.network_incident_redrive_github_environment == null
      || can(regex("^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$", var.network_incident_redrive_github_environment))
    )
    error_message = "network_incident_redrive_github_environment must use 1-100 safe subject characters."
  }
}

variable "network_incident_redrive_role_name" {
  type        = string
  default     = "network-incident-redrive-canary"
  description = "IAM role name used only by the protected redrive workflow."

  validation {
    condition = (
      length(var.network_incident_redrive_role_name) >= 1
      && length(var.network_incident_redrive_role_name) <= 64
      && can(regex("^[A-Za-z0-9+=,.@_-]+$", var.network_incident_redrive_role_name))
    )
    error_message = "network_incident_redrive_role_name must be a valid 1-64 character IAM role name."
  }
}

variable "enable_network_incident_redrive_evidence_archive" {
  type        = bool
  default     = false
  description = "Create a private S3 Object Lock bucket for immutable signed redrive evidence."
}

variable "network_incident_redrive_evidence_archive_bucket_name" {
  type        = string
  default     = null
  nullable    = true
  description = "Globally unique S3 bucket name used only by the optional immutable evidence archive."

  validation {
    condition = (
      var.network_incident_redrive_evidence_archive_bucket_name == null
      || (
        length(var.network_incident_redrive_evidence_archive_bucket_name) >= 3
        && length(var.network_incident_redrive_evidence_archive_bucket_name) <= 63
        && can(regex("^[a-z0-9][a-z0-9.-]*[a-z0-9]$", var.network_incident_redrive_evidence_archive_bucket_name))
        && !can(regex("[.][.]|[-][.]|[.][-]", var.network_incident_redrive_evidence_archive_bucket_name))
        && !can(regex("^[0-9]+[.][0-9]+[.][0-9]+[.][0-9]+$", var.network_incident_redrive_evidence_archive_bucket_name))
      )
    )
    error_message = "network_incident_redrive_evidence_archive_bucket_name must be null or a canonical 3-63 character S3 bucket name."
  }
}

variable "network_incident_redrive_evidence_retention_days" {
  type        = number
  default     = 30
  description = "Compliance-mode Object Lock retention applied by default to every evidence version."

  validation {
    condition = (
      var.network_incident_redrive_evidence_retention_days >= 7
      && var.network_incident_redrive_evidence_retention_days <= 365
      && floor(var.network_incident_redrive_evidence_retention_days) == var.network_incident_redrive_evidence_retention_days
    )
    error_message = "network_incident_redrive_evidence_retention_days must be an integer from 7 to 365."
  }
}

variable "enable_vpc_flow_contributor_insights" {
  type        = bool
  default     = false
  description = "Enable two chargeable Contributor Insights rules for top rejected sources and destinations."
}

variable "enable_network_incident_dashboard" {
  type        = bool
  default     = false
  description = "Enable the CloudWatch network incident dashboard; requires VPC Flow Contributor Insights."
}

variable "network_incident_dashboard_name" {
  type        = string
  default     = "ml-platform-network-incidents"
  description = "CloudWatch dashboard name used for rejected-flow incident triage."

  validation {
    condition = (
      length(var.network_incident_dashboard_name) >= 1
      && length(var.network_incident_dashboard_name) <= 255
      && can(regex("^[A-Za-z0-9_-]+$", var.network_incident_dashboard_name))
    )
    error_message = "network_incident_dashboard_name must be 1-255 characters containing only letters, numbers, hyphens and underscores."
  }
}
