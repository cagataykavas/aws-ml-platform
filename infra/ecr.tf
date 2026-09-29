locals {
  ecr_lifecycle_policy = {
    rules = [
      {
        rulePriority = 1
        description  = "Retain the newest 30 release images"
        selection = {
          tagStatus     = "tagged"
          tagPrefixList = ["release-"]
          countType     = "imageCountMoreThan"
          countNumber   = 30
        }
        action = {
          type = "expire"
        }
      },
      {
        rulePriority = 2
        description  = "Expire untagged build images after seven days"
        selection = {
          tagStatus   = "untagged"
          countType   = "sinceImagePushed"
          countUnit   = "days"
          countNumber = 7
        }
        action = {
          type = "expire"
        }
      },
    ]
  }
}

resource "aws_ecr_repository" "inference" {
  name                 = "ml-inference"
  image_tag_mutability = "IMMUTABLE"
  force_delete         = false

  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.ml.arn
  }

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = {
    Workload = "ml-platform"
    Purpose  = "inference-images"
  }
}

resource "aws_ecr_lifecycle_policy" "inference" {
  repository = aws_ecr_repository.inference.name
  policy     = jsonencode(local.ecr_lifecycle_policy)
}

output "inference_repository_url" {
  value       = aws_ecr_repository.inference.repository_url
  description = "KMS-encrypted ECR repository for immutable inference image tags."
}

output "inference_repository_arn" {
  value       = aws_ecr_repository.inference.arn
  description = "Repository ARN for deployment identity and policy integration."
}
