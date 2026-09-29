mock_provider "aws" {
  mock_data "aws_availability_zones" {
    defaults = {
      names = ["eu-central-1a", "eu-central-1b"]
    }
  }
}

variables {
  ecs_cluster_name = "test-cluster"
  ecs_service_name = "test-service"
  alb_dimension    = "app/test/123456"
}

run "secure_ecr_contract" {
  command = plan

  assert {
    condition     = aws_ecr_repository.inference.image_tag_mutability == "IMMUTABLE"
    error_message = "Inference image tags must be immutable."
  }

  assert {
    condition     = aws_ecr_repository.inference.image_scanning_configuration[0].scan_on_push
    error_message = "Every pushed inference image must be scanned."
  }

  assert {
    condition     = aws_ecr_repository.inference.encryption_configuration[0].encryption_type == "KMS"
    error_message = "The repository must use KMS encryption."
  }

  assert {
    condition     = aws_ecr_repository.inference.encryption_configuration[0].kms_key == aws_kms_key.ml.arn
    error_message = "The repository must use the platform-managed KMS key."
  }

  assert {
    condition     = !aws_ecr_repository.inference.force_delete
    error_message = "Terraform must not delete a non-empty inference repository implicitly."
  }

  assert {
    condition = (
      jsondecode(aws_ecr_lifecycle_policy.inference.policy).rules[0].selection.tagStatus == "tagged" &&
      jsondecode(aws_ecr_lifecycle_policy.inference.policy).rules[0].selection.tagPrefixList == ["release-"] &&
      jsondecode(aws_ecr_lifecycle_policy.inference.policy).rules[0].selection.countType == "imageCountMoreThan" &&
      jsondecode(aws_ecr_lifecycle_policy.inference.policy).rules[0].selection.countNumber == 30
    )
    error_message = "Release retention must keep the newest 30 release-* images."
  }

  assert {
    condition = (
      jsondecode(aws_ecr_lifecycle_policy.inference.policy).rules[1].selection.tagStatus == "untagged" &&
      jsondecode(aws_ecr_lifecycle_policy.inference.policy).rules[1].selection.countType == "sinceImagePushed" &&
      jsondecode(aws_ecr_lifecycle_policy.inference.policy).rules[1].selection.countUnit == "days" &&
      jsondecode(aws_ecr_lifecycle_policy.inference.policy).rules[1].selection.countNumber == 7
    )
    error_message = "Untagged build images must expire after seven days."
  }
}
