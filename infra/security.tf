terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

provider "aws" {
  region = var.aws_region
}

variable "aws_region" {
  type    = string
  default = "eu-central-1"
}

resource "aws_s3_bucket" "artifacts" {
  bucket_prefix = "ml-artifacts-"
}

resource "aws_s3_bucket_public_access_block" "artifacts" {
  bucket                  = aws_s3_bucket.artifacts.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_kms_key" "ml" {
  description             = "KMS key for ML artifacts and secrets"
  deletion_window_in_days = 7
  enable_key_rotation     = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.ml.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_secretsmanager_secret" "database" {
  name_prefix = "ml-platform/database-"
  kms_key_id  = aws_kms_key.ml.arn
}

resource "aws_iam_role" "inference_task" {
  name_prefix = "ml-inference-task-"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "least_privilege" {
  role = aws_iam_role.inference_task.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["s3:GetObject"]
        Resource = ["${aws_s3_bucket.artifacts.arn}/*"]
      },
      {
        Effect = "Allow"
        Action = ["secretsmanager:GetSecretValue"]
        Resource = [aws_secretsmanager_secret.database.arn]
      },
      {
        Effect = "Allow"
        Action = ["kms:Decrypt"]
        Resource = [aws_kms_key.ml.arn]
      }
    ]
  })
}

output "artifact_bucket" {
  value = aws_s3_bucket.artifacts.bucket
}

output "task_role_arn" {
  value = aws_iam_role.inference_task.arn
}
