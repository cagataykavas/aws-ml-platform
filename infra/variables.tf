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
  description = "SNS or incident-action ARNs invoked by network alarms; empty keeps CI credential-free."

  validation {
    condition = alltrue([
      for action in var.network_alarm_actions : can(regex("^arn:aws[a-z-]*:", action))
    ])
    error_message = "network_alarm_actions entries must be AWS ARNs."
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
