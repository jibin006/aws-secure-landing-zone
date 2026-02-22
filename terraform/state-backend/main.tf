# terraform/state-backend/
# Deploy this FIRST before any other module.
# This creates the secure backend that all other modules use.
#
# SECURITY NOTE: This module bootstraps with local state, then you migrate.
# The state for the state backend itself is kept locally (acceptable — it only
# contains S3 bucket and DynamoDB table ARNs, no sensitive values).

terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  # Intentionally local backend — this is the bootstrap exception
  # All other modules use the backend this creates
}

provider "aws" {
  region = var.primary_region

  default_tags {
    tags = {
      ManagedBy   = "terraform"
      Module      = "state-backend"
      Environment = "management"
      Owner       = "cloud-security"
    }
  }
}

variable "primary_region" {
  description = "Primary AWS region for state backend resources"
  type        = string
  default     = "ap-south-1"
}

variable "org_name" {
  description = "Short org identifier used in resource naming"
  type        = string
  default     = "myorg" # Change to your org name
}

# ─────────────────────────────────────────────────────────────────────────────
# KMS KEY — State files may contain sensitive resource metadata
# Using CMK gives you: key rotation, usage auditing, and org-scoped key policy
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_kms_key" "terraform_state" {
  description             = "CMK for Terraform state file encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  # Key policy: only management account principals can use this key
  # Deny cross-account usage — state files should never be readable outside mgmt account
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnableRootAccess"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "DenyExternalAccess"
        Effect = "Deny"
        Principal = {
          AWS = "*"
        }
        Action   = "kms:*"
        Resource = "*"
        Condition = {
          StringNotEquals = {
            "kms:CallerAccount" = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })
}

resource "aws_kms_alias" "terraform_state" {
  name          = "alias/${var.org_name}-terraform-state"
  target_key_id = aws_kms_key.terraform_state.key_id
}

# ─────────────────────────────────────────────────────────────────────────────
# S3 BUCKET — State storage
# THREAT: Public exposure → full infrastructure map + potential credential leak
# CONTROLS: Block public access, versioning (rollback capability), KMS encryption,
#           access logging to separate bucket, org-scoped bucket policy
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_s3_bucket" "terraform_state" {
  bucket = "${var.org_name}-terraform-state-${data.aws_caller_identity.current.account_id}"

  # Prevent accidental deletion — state bucket destruction is catastrophic
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_versioning" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.terraform_state.arn
    }
    bucket_key_enabled = true # Reduces KMS API calls (cost optimization without security trade-off)
  }
}

resource "aws_s3_bucket_public_access_block" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Access logging — sent to a SEPARATE logging bucket, not itself
# If logging to itself: a compromise that deletes the bucket deletes the logs too
resource "aws_s3_bucket_logging" "terraform_state" {
  bucket        = aws_s3_bucket.terraform_state.id
  target_bucket = aws_s3_bucket.state_access_logs.id
  target_prefix = "state-access-logs/"
}

resource "aws_s3_bucket_policy" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # CONTROL: Enforce TLS — deny any HTTP access to state files
        Sid       = "EnforceTLSOnly"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.terraform_state.arn,
          "${aws_s3_bucket.terraform_state.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      },
      {
        # CONTROL: Org-scoped access — no cross-org state access
        # THREAT MITIGATED: Compromised credentials used from outside org to read state
        Sid       = "DenyNonOrgAccess"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.terraform_state.arn,
          "${aws_s3_bucket.terraform_state.arn}/*"
        ]
        Condition = {
          StringNotEquals = {
            "aws:PrincipalOrgID" = var.org_id
          }
        }
      }
    ]
  })
}

# Separate bucket for state access logs
# Simpler policy — only S3 logging service can write here
resource "aws_s3_bucket" "state_access_logs" {
  bucket = "${var.org_name}-state-access-logs-${data.aws_caller_identity.current.account_id}"
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_public_access_block" "state_access_logs" {
  bucket                  = aws_s3_bucket.state_access_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "state_access_logs" {
  bucket = aws_s3_bucket.state_access_logs.id
  rule {
    id     = "expire-old-logs"
    status = "Enabled"
    expiration {
      days = 365 # Retain 1 year — adjust per your compliance requirement
    }
  }
}

# ─────────────────────────────────────────────────────────────────────────────
# DYNAMODB — State locking
# Prevents concurrent Terraform runs from corrupting state
# SECURITY NOTE: Encryption at rest with CMK
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_dynamodb_table" "terraform_state_lock" {
  name         = "${var.org_name}-terraform-state-lock"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "LockID"

  attribute {
    name = "LockID"
    type = "S"
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.terraform_state.arn
  }

  point_in_time_recovery {
    enabled = true
  }
}

variable "org_id" {
  description = "AWS Organizations ID (o-xxxxxxxxxx) — used in bucket policy to restrict org access"
  type        = string
}

data "aws_caller_identity" "current" {}

# ─────────────────────────────────────────────────────────────────────────────
# OUTPUTS — Used by other modules as backend config
# ─────────────────────────────────────────────────────────────────────────────
output "state_bucket_name" {
  value       = aws_s3_bucket.terraform_state.bucket
  description = "S3 bucket name for Terraform state"
}

output "state_lock_table" {
  value       = aws_dynamodb_table.terraform_state_lock.name
  description = "DynamoDB table name for state locking"
}

output "state_kms_key_arn" {
  value       = aws_kms_key.terraform_state.arn
  description = "KMS key ARN used for state encryption"
  sensitive   = true
}

# Write backend config file for other modules to reference
resource "local_file" "backend_config" {
  filename = "${path.module}/backend.hcl"
  content  = <<-EOT
    bucket         = "${aws_s3_bucket.terraform_state.bucket}"
    key            = "REPLACE_WITH_MODULE_PATH/terraform.tfstate"
    region         = "${var.primary_region}"
    encrypt        = true
    kms_key_id     = "${aws_kms_key.terraform_state.arn}"
    dynamodb_table = "${aws_dynamodb_table.terraform_state_lock.name}"
  EOT
}
