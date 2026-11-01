variable "enable_retained_evidence_auditor_role" {
  type        = bool
  default     = false
  description = "Provision the read-only GitHub OIDC role used by the protected retained-evidence audit."
}

variable "retained_evidence_auditor_github_oidc_provider_arn" {
  type        = string
  default     = null
  nullable    = true
  description = "Existing account-local GitHub Actions OIDC provider ARN used only by the auditor role."

  validation {
    condition = (
      var.retained_evidence_auditor_github_oidc_provider_arn == null
      || can(regex("^arn:aws[a-z-]*:iam::[0-9]{12}:oidc-provider/token[.]actions[.]githubusercontent[.]com$", var.retained_evidence_auditor_github_oidc_provider_arn))
    )
    error_message = "retained_evidence_auditor_github_oidc_provider_arn must identify token.actions.githubusercontent.com."
  }
}

variable "retained_evidence_auditor_github_repository" {
  type        = string
  default     = null
  nullable    = true
  description = "Exact GitHub owner/repository allowed to assume the retained-evidence auditor role."

  validation {
    condition = (
      var.retained_evidence_auditor_github_repository == null
      || can(regex("^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", var.retained_evidence_auditor_github_repository))
    )
    error_message = "retained_evidence_auditor_github_repository must be null or owner/repository."
  }
}

variable "retained_evidence_auditor_github_environment" {
  type        = string
  default     = null
  nullable    = true
  description = "Protected GitHub Environment bound into the auditor role's OIDC subject claim."

  validation {
    condition = (
      var.retained_evidence_auditor_github_environment == null
      || can(regex("^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$", var.retained_evidence_auditor_github_environment))
    )
    error_message = "retained_evidence_auditor_github_environment must use 1-100 safe subject characters."
  }
}

variable "retained_evidence_auditor_role_name" {
  type        = string
  default     = "retained-evidence-auditor"
  description = "IAM role name used only by the protected retained-evidence recovery audit."

  validation {
    condition = (
      length(var.retained_evidence_auditor_role_name) >= 1
      && length(var.retained_evidence_auditor_role_name) <= 64
      && can(regex("^[A-Za-z0-9+=,.@_-]+$", var.retained_evidence_auditor_role_name))
    )
    error_message = "retained_evidence_auditor_role_name must be a valid 1-64 character IAM role name."
  }
}

locals {
  retained_evidence_auditor_role_arn = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:role/${var.retained_evidence_auditor_role_name}"
  retained_evidence_auditor_oidc_subject = (
    var.retained_evidence_auditor_github_repository != null
    && var.retained_evidence_auditor_github_environment != null
    ? "repo:${var.retained_evidence_auditor_github_repository}:environment:${var.retained_evidence_auditor_github_environment}"
    : null
  )
  retained_evidence_auditor_oidc_provider_parts = split(
    ":",
    var.retained_evidence_auditor_github_oidc_provider_arn != null
    ? var.retained_evidence_auditor_github_oidc_provider_arn
    : "",
  )
}

resource "terraform_data" "retained_evidence_auditor_contract" {
  count = var.enable_retained_evidence_auditor_role ? 1 : 0

  input = {
    archive_enabled    = local.network_incident_redrive_archive_enabled
    oidc_provider_arn  = var.retained_evidence_auditor_github_oidc_provider_arn
    github_repository  = var.retained_evidence_auditor_github_repository
    github_environment = var.retained_evidence_auditor_github_environment
  }

  lifecycle {
    precondition {
      condition     = local.network_incident_redrive_archive_enabled
      error_message = "The retained-evidence auditor requires the immutable redrive evidence archive."
    }

    precondition {
      condition     = var.retained_evidence_auditor_github_oidc_provider_arn != null
      error_message = "The retained-evidence auditor requires the existing account-local GitHub OIDC provider ARN."
    }

    precondition {
      condition = try(
        local.retained_evidence_auditor_oidc_provider_parts[1] == data.aws_partition.current.partition
        && local.retained_evidence_auditor_oidc_provider_parts[2] == "iam"
        && local.retained_evidence_auditor_oidc_provider_parts[4] == data.aws_caller_identity.current.account_id
        && local.retained_evidence_auditor_oidc_provider_parts[5] == "oidc-provider/token.actions.githubusercontent.com",
        false,
      )
      error_message = "The auditor GitHub OIDC provider must be token.actions.githubusercontent.com in the deployment partition and account."
    }

    precondition {
      condition     = var.retained_evidence_auditor_github_repository != null
      error_message = "The retained-evidence auditor requires an explicit GitHub owner/repository trust boundary."
    }

    precondition {
      condition     = var.retained_evidence_auditor_github_environment != null
      error_message = "The retained-evidence auditor requires one explicit protected GitHub Environment."
    }
  }
}

resource "aws_iam_role" "retained_evidence_auditor" {
  count = var.enable_retained_evidence_auditor_role ? 1 : 0

  name                 = var.retained_evidence_auditor_role_name
  max_session_duration = 3600
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "GitHubEnvironmentOidc"
      Effect = "Allow"
      Principal = {
        Federated = var.retained_evidence_auditor_github_oidc_provider_arn
      }
      Action = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          "token.actions.githubusercontent.com:sub" = local.retained_evidence_auditor_oidc_subject
        }
      }
    }]
  })

  tags = {
    Workload = "ml-platform"
    Purpose  = "retained-evidence-independent-auditor"
  }

  depends_on = [terraform_data.retained_evidence_auditor_contract]
}

resource "aws_iam_role_policy" "retained_evidence_auditor" {
  count = var.enable_retained_evidence_auditor_role ? 1 : 0

  name = "retained-evidence-read-only"
  role = aws_iam_role.retained_evidence_auditor[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "ReadRetainedEvidenceVersions"
      Effect = "Allow"
      Action = [
        "s3:GetObjectRetention",
        "s3:GetObjectVersion",
      ]
      Resource = "${local.network_incident_redrive_archive_bucket_arn}/redrive-evidence/v1/*"
    }]
  })
}

output "retained_evidence_auditor" {
  value = var.enable_retained_evidence_auditor_role ? {
    role_arn            = local.retained_evidence_auditor_role_arn
    github_oidc_subject = local.retained_evidence_auditor_oidc_subject
    github_environment_variables = {
      AWS_REGION                             = var.aws_region
      AWS_ACCOUNT_ID                         = data.aws_caller_identity.current.account_id
      AWS_RETAINED_EVIDENCE_AUDITOR_ROLE_ARN = local.retained_evidence_auditor_role_arn
      RETAINED_EVIDENCE_AUDIT_ENABLED        = "true"
    }
  } : null
  description = "Read-only auditor identity and protected GitHub Environment variables; null when disabled."
}
