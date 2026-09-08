resource "aws_s3_bucket" "artifacts" {
  bucket_prefix = "ml-artifacts-"

  tags = {
    Workload = "ml-platform"
    Data      = "model-artifacts"
  }
}

resource "aws_s3_bucket_public_access_block" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_kms_key" "ml" {
  description             = "KMS key for ML artifacts and runtime secrets"
  deletion_window_in_days = 7
  enable_key_rotation     = true
}

resource "aws_kms_alias" "ml" {
  name          = "alias/ml-platform"
  target_key_id = aws_kms_key.ml.key_id
}

resource "aws_s3_bucket_server_side_encryption_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  rule {
    bucket_key_enabled = true

    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.ml.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_secretsmanager_secret" "database" {
  name_prefix = "ml-platform/database-"
  kms_key_id  = aws_kms_key.ml.arn

  recovery_window_in_days = 7
}

resource "aws_iam_role" "inference_task" {
  name_prefix = "ml-inference-task-"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "ecs-tasks.amazonaws.com"
      }
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
        Sid    = "ReadModelArtifacts"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:GetObjectVersion",
        ]
        Resource = ["${aws_s3_bucket.artifacts.arn}/*"]
      },
      {
        Sid      = "ListArtifactBucket"
        Effect   = "Allow"
        Action   = ["s3:ListBucket"]
        Resource = [aws_s3_bucket.artifacts.arn]
      },
      {
        Sid      = "ReadDatabaseSecret"
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = [aws_secretsmanager_secret.database.arn]
      },
      {
        Sid      = "DecryptPlatformData"
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = [aws_kms_key.ml.arn]
      },
    ]
  })
}

output "artifact_bucket" {
  value       = aws_s3_bucket.artifacts.bucket
  description = "Private, versioned, KMS-encrypted model artifact bucket."
}

output "task_role_arn" {
  value       = aws_iam_role.inference_task.arn
  description = "Least-privilege ECS task role for model and secret reads."
}
