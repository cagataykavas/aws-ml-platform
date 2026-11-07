variable "enable_backend_consumption_auditor_role" {
  type        = bool
  default     = false
  description = "Provision the read-only GitHub OIDC role for retained Terraform backend-consumption audits."
}

variable "backend_consumption_archive_bucket_arn" {
  type        = string
  default     = null
  nullable    = true
  description = "ARN of the separately governed S3 Object Lock bucket containing backend-consumption receipts."

  validation {
    condition = (
      var.backend_consumption_archive_bucket_arn == null
      || can(regex("^arn:(aws|aws-us-gov|aws-cn):s3:::[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", var.backend_consumption_archive_bucket_arn))
    )
    error_message = "backend_consumption_archive_bucket_arn must be null or a bucket-only S3 ARN."
  }
}

variable "backend_consumption_auditor_github_oidc_provider_arn" {
  type        = string
  default     = null
  nullable    = true
  description = "Existing account-local GitHub Actions OIDC provider ARN used only by this auditor role."

  validation {
    condition = (
      var.backend_consumption_auditor_github_oidc_provider_arn == null
      || can(regex("^arn:aws[a-z-]*:iam::[0-9]{12}:oidc-provider/token[.]actions[.]githubusercontent[.]com$", var.backend_consumption_auditor_github_oidc_provider_arn))
    )
    error_message = "backend_consumption_auditor_github_oidc_provider_arn must identify token.actions.githubusercontent.com."
  }
}

variable "backend_consumption_auditor_github_repository" {
  type        = string
  default     = null
  nullable    = true
  description = "Exact GitHub owner/repository allowed to assume the backend-consumption auditor role."

  validation {
    condition = (
      var.backend_consumption_auditor_github_repository == null
      || can(regex("^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", var.backend_consumption_auditor_github_repository))
    )
    error_message = "backend_consumption_auditor_github_repository must be null or owner/repository."
  }
}

variable "backend_consumption_auditor_github_repository_id" {
  type        = string
  default     = null
  nullable    = true
  description = "Immutable GitHub repository ID allowed to assume the backend-consumption auditor role."

  validation {
    condition = (
      var.backend_consumption_auditor_github_repository_id == null
      || can(regex("^[1-9][0-9]{0,19}$", var.backend_consumption_auditor_github_repository_id))
    )
    error_message = "backend_consumption_auditor_github_repository_id must be null or a positive integer string."
  }
}

variable "backend_consumption_auditor_github_environment" {
  type        = string
  default     = null
  nullable    = true
  description = "Protected GitHub Environment bound into the backend-consumption auditor OIDC subject."

  validation {
    condition = (
      var.backend_consumption_auditor_github_environment == null
      || can(regex("^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$", var.backend_consumption_auditor_github_environment))
    )
    error_message = "backend_consumption_auditor_github_environment must use 1-100 safe subject characters."
  }
}

variable "backend_consumption_auditor_github_ref" {
  type        = string
  default     = null
  nullable    = true
  description = "Exact default-branch ref allowed to assume the backend-consumption auditor role."

  validation {
    condition = (
      var.backend_consumption_auditor_github_ref == null
      || try(
        can(regex("(^refs/heads/[A-Za-z0-9]$|^refs/heads/[A-Za-z0-9][A-Za-z0-9._/-]{0,199}[A-Za-z0-9_-]$)", var.backend_consumption_auditor_github_ref))
        && !strcontains(var.backend_consumption_auditor_github_ref, "..")
        && !strcontains(var.backend_consumption_auditor_github_ref, "//")
        && !strcontains(var.backend_consumption_auditor_github_ref, "/.")
        && !endswith(var.backend_consumption_auditor_github_ref, ".lock"),
        false,
      )
    )
    error_message = "backend_consumption_auditor_github_ref must be null or a canonical refs/heads/... ref."
  }
}

variable "backend_consumption_auditor_github_workflow" {
  type        = string
  default     = null
  nullable    = true
  description = "Exact GitHub Actions workflow name allowed to assume the backend-consumption auditor role."

  validation {
    condition = (
      var.backend_consumption_auditor_github_workflow == null
      || can(regex("^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$", var.backend_consumption_auditor_github_workflow))
    )
    error_message = "backend_consumption_auditor_github_workflow must use 1-100 safe claim characters."
  }
}

variable "backend_consumption_auditor_role_name" {
  type        = string
  default     = "backend-consumption-auditor"
  description = "IAM role name used only by the protected backend-consumption recovery audit."

  validation {
    condition = (
      length(var.backend_consumption_auditor_role_name) >= 1
      && length(var.backend_consumption_auditor_role_name) <= 64
      && can(regex("^[A-Za-z0-9+=,.@_-]+$", var.backend_consumption_auditor_role_name))
    )
    error_message = "backend_consumption_auditor_role_name must be a valid 1-64 character IAM role name."
  }
}

locals {
  backend_consumption_auditor_role_arn = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:role/${var.backend_consumption_auditor_role_name}"
  backend_consumption_auditor_oidc_subject = (
    var.backend_consumption_auditor_github_repository != null
    && var.backend_consumption_auditor_github_environment != null
    ? "repo:${var.backend_consumption_auditor_github_repository}:environment:${var.backend_consumption_auditor_github_environment}"
    : null
  )
  backend_consumption_auditor_oidc_provider_parts = split(
    ":",
    var.backend_consumption_auditor_github_oidc_provider_arn != null
    ? var.backend_consumption_auditor_github_oidc_provider_arn
    : "",
  )
  backend_consumption_archive_bucket_parts = split(
    ":",
    var.backend_consumption_archive_bucket_arn != null
    ? var.backend_consumption_archive_bucket_arn
    : "",
  )
  backend_consumption_archive_bucket_arn = coalesce(
    var.backend_consumption_archive_bucket_arn,
    "arn:${data.aws_partition.current.partition}:s3:::disabled-backend-consumption-archive",
  )
}

resource "terraform_data" "backend_consumption_auditor_contract" {
  count = var.enable_backend_consumption_auditor_role ? 1 : 0

  input = {
    archive_bucket_arn   = var.backend_consumption_archive_bucket_arn
    oidc_provider_arn    = var.backend_consumption_auditor_github_oidc_provider_arn
    github_repository    = var.backend_consumption_auditor_github_repository
    github_repository_id = var.backend_consumption_auditor_github_repository_id
    github_environment   = var.backend_consumption_auditor_github_environment
    github_ref           = var.backend_consumption_auditor_github_ref
    github_workflow      = var.backend_consumption_auditor_github_workflow
  }

  lifecycle {
    precondition {
      condition     = var.backend_consumption_archive_bucket_arn != null
      error_message = "The backend-consumption auditor requires an explicit archive bucket ARN."
    }

    precondition {
      condition = try(
        local.backend_consumption_archive_bucket_parts[1] == data.aws_partition.current.partition
        && local.backend_consumption_archive_bucket_parts[2] == "s3"
        && local.backend_consumption_archive_bucket_parts[5] != "",
        false,
      )
      error_message = "The backend-consumption archive bucket must use the deployment partition."
    }

    precondition {
      condition     = var.backend_consumption_auditor_github_oidc_provider_arn != null
      error_message = "The backend-consumption auditor requires the existing account-local GitHub OIDC provider ARN."
    }

    precondition {
      condition = try(
        local.backend_consumption_auditor_oidc_provider_parts[1] == data.aws_partition.current.partition
        && local.backend_consumption_auditor_oidc_provider_parts[2] == "iam"
        && local.backend_consumption_auditor_oidc_provider_parts[4] == data.aws_caller_identity.current.account_id
        && local.backend_consumption_auditor_oidc_provider_parts[5] == "oidc-provider/token.actions.githubusercontent.com",
        false,
      )
      error_message = "The auditor GitHub OIDC provider must be token.actions.githubusercontent.com in the deployment partition and account."
    }

    precondition {
      condition     = var.backend_consumption_auditor_github_repository != null
      error_message = "The backend-consumption auditor requires an explicit GitHub owner/repository trust boundary."
    }

    precondition {
      condition     = var.backend_consumption_auditor_github_repository_id != null
      error_message = "The backend-consumption auditor requires the immutable GitHub repository ID."
    }

    precondition {
      condition     = var.backend_consumption_auditor_github_environment != null
      error_message = "The backend-consumption auditor requires one explicit protected GitHub Environment."
    }

    precondition {
      condition     = var.backend_consumption_auditor_github_ref != null
      error_message = "The backend-consumption auditor requires one explicit default-branch ref."
    }

    precondition {
      condition     = var.backend_consumption_auditor_github_workflow != null
      error_message = "The backend-consumption auditor requires one explicit workflow name."
    }
  }
}

resource "aws_iam_role" "backend_consumption_auditor" {
  count = var.enable_backend_consumption_auditor_role ? 1 : 0

  name                 = var.backend_consumption_auditor_role_name
  max_session_duration = 3600
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "GitHubEnvironmentOidc"
      Effect = "Allow"
      Principal = {
        Federated = var.backend_consumption_auditor_github_oidc_provider_arn
      }
      Action = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud"           = "sts.amazonaws.com"
          "token.actions.githubusercontent.com:sub"           = local.backend_consumption_auditor_oidc_subject
          "token.actions.githubusercontent.com:repository"    = var.backend_consumption_auditor_github_repository
          "token.actions.githubusercontent.com:repository_id" = var.backend_consumption_auditor_github_repository_id
          "token.actions.githubusercontent.com:environment"   = var.backend_consumption_auditor_github_environment
          "token.actions.githubusercontent.com:ref"           = var.backend_consumption_auditor_github_ref
          "token.actions.githubusercontent.com:workflow"      = var.backend_consumption_auditor_github_workflow
        }
        StringLike = {
          "sts:RoleSessionName" = "retained-audit-?*"
        }
      }
    }]
  })

  tags = {
    Workload = "ml-platform"
    Purpose  = "backend-consumption-independent-auditor"
  }

  depends_on = [terraform_data.backend_consumption_auditor_contract]
}

resource "aws_iam_role_policy" "backend_consumption_auditor" {
  count = var.enable_backend_consumption_auditor_role ? 1 : 0

  name = "backend-consumption-read-only"
  role = aws_iam_role.backend_consumption_auditor[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "ReadRetainedBackendConsumptions"
      Effect = "Allow"
      Action = [
        "s3:GetObjectRetention",
        "s3:GetObjectVersion",
      ]
      Resource = "${local.backend_consumption_archive_bucket_arn}/terraform-backend-consumptions/v1/*"
    }]
  })
}

output "backend_consumption_auditor" {
  value = var.enable_backend_consumption_auditor_role ? {
    role_arn                  = local.backend_consumption_auditor_role_arn
    github_oidc_subject       = local.backend_consumption_auditor_oidc_subject
    github_repository_id      = var.backend_consumption_auditor_github_repository_id
    github_oidc_ref           = var.backend_consumption_auditor_github_ref
    github_oidc_workflow      = var.backend_consumption_auditor_github_workflow
    role_session_name_pattern = "retained-audit-?*"
    github_environment_variables = {
      AWS_REGION                               = var.aws_region
      AWS_ACCOUNT_ID                           = data.aws_caller_identity.current.account_id
      AWS_BACKEND_CONSUMPTION_AUDITOR_ROLE_ARN = local.backend_consumption_auditor_role_arn
      BACKEND_CONSUMPTION_AUDIT_ENABLED        = "true"
    }
  } : null
  description = "Read-only backend-consumption auditor identity and protected Environment variables; null when disabled."
}
