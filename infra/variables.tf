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
