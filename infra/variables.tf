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
