terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  backend "s3" {
    key = "organization/terraform.tfstate"
    # All other backend params come from backend.hcl
  }
}

provider "aws" {
  region = var.primary_region
  default_tags {
    tags = {
      ManagedBy = "terraform"
      Module    = "organization"
    }
  }
}

variable "primary_region" {
  type    = string
  default = "ap-south-1"
}

variable "org_name" {
  type    = string
  default = "myorg"
}

variable "log_archive_email" {
  description = "Unique email for log-archive account (use email+alias pattern)"
  type        = string
}

variable "security_tooling_email" {
  type = string
}

variable "shared_services_email" {
  type = string
}

variable "prod_app_email" {
  type = string
}

variable "staging_app_email" {
  type = string
}

variable "sandbox_eng_email" {
  type = string
}

# ─────────────────────────────────────────────────────────────────────────────
# AWS ORGANIZATION
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_organizations_organization" "root" {
  aws_service_access_principals = [
    "cloudtrail.amazonaws.com",       # Organization-wide CloudTrail
    "config.amazonaws.com",           # Config aggregator
    "guardduty.amazonaws.com",        # GuardDuty delegated admin
    "securityhub.amazonaws.com",      # SecurityHub aggregated findings
    "sso.amazonaws.com",              # IAM Identity Center (SSO)
    "access-analyzer.amazonaws.com",  # IAM Access Analyzer org-wide
    "account.amazonaws.com",          # Account management
  ]

  feature_set = "ALL" # Required for SCPs — do not use CONSOLIDATED_BILLING_ONLY

  enabled_policy_types = [
    "SERVICE_CONTROL_POLICY",
    "TAG_POLICY", # Enforce cost allocation tagging
  ]
}

# ─────────────────────────────────────────────────────────────────────────────
# ORGANIZATIONAL UNITS
# Design note: OUs define SCP inheritance scope.
# Workloads OU has child OUs — production gets stricter SCPs than staging.
# Suspended OU exists PRE-INCIDENT. You don't build the fire escape during fire.
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_organizations_organizational_unit" "security" {
  name      = "Security"
  parent_id = aws_organizations_organization.root.roots[0].id
}

resource "aws_organizations_organizational_unit" "infrastructure" {
  name      = "Infrastructure"
  parent_id = aws_organizations_organization.root.roots[0].id
}

resource "aws_organizations_organizational_unit" "workloads" {
  name      = "Workloads"
  parent_id = aws_organizations_organization.root.roots[0].id
}

resource "aws_organizations_organizational_unit" "production" {
  name      = "Production"
  parent_id = aws_organizations_organizational_unit.workloads.id
}

resource "aws_organizations_organizational_unit" "staging" {
  name      = "Staging"
  parent_id = aws_organizations_organizational_unit.workloads.id
}

resource "aws_organizations_organizational_unit" "sandbox" {
  name      = "Sandbox"
  parent_id = aws_organizations_organizational_unit.workloads.id
}

resource "aws_organizations_organizational_unit" "suspended" {
  # INCIDENT RESPONSE: Move compromised accounts here immediately.
  # The Suspended OU's deny-all SCP stops all actions except the IR automation role.
  # This OU must exist BEFORE you need it.
  name      = "Suspended"
  parent_id = aws_organizations_organization.root.roots[0].id
}

# ─────────────────────────────────────────────────────────────────────────────
# MEMBER ACCOUNTS
# Each account is a blast radius boundary.
# Naming convention: {env}-{function} makes accounts scannable in large orgs.
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_organizations_account" "log_archive" {
  name                       = "${var.org_name}-log-archive"
  email                      = var.log_archive_email
  parent_id                  = aws_organizations_organizational_unit.security.id
  iam_user_access_to_billing = "DENY"
  # SECURITY: Billing access from member accounts off — prevents cost-based recon
  # of account activity patterns

  lifecycle {
    # Prevent accidental account closure — requires manual intervention
    prevent_destroy = true
    # Email changes require out-of-band process
    ignore_changes = [email]
  }
}

resource "aws_organizations_account" "security_tooling" {
  name                       = "${var.org_name}-security-tooling"
  email                      = var.security_tooling_email
  parent_id                  = aws_organizations_organizational_unit.security.id
  iam_user_access_to_billing = "DENY"
  lifecycle {
    prevent_destroy = true
    ignore_changes  = [email]
  }
}

resource "aws_organizations_account" "shared_services" {
  name                       = "${var.org_name}-shared-services"
  email                      = var.shared_services_email
  parent_id                  = aws_organizations_organizational_unit.infrastructure.id
  iam_user_access_to_billing = "DENY"
  lifecycle {
    prevent_destroy = true
    ignore_changes  = [email]
  }
}

resource "aws_organizations_account" "prod_app" {
  name                       = "${var.org_name}-prod-app"
  email                      = var.prod_app_email
  parent_id                  = aws_organizations_organizational_unit.production.id
  iam_user_access_to_billing = "DENY"
  lifecycle {
    prevent_destroy = true
    ignore_changes  = [email]
  }
}

resource "aws_organizations_account" "staging_app" {
  name                       = "${var.org_name}-staging-app"
  email                      = var.staging_app_email
  parent_id                  = aws_organizations_organizational_unit.staging.id
  iam_user_access_to_billing = "DENY"
  lifecycle {
    prevent_destroy = true
    ignore_changes  = [email]
  }
}

resource "aws_organizations_account" "sandbox_eng" {
  name                       = "${var.org_name}-sandbox-eng"
  email                      = var.sandbox_eng_email
  parent_id                  = aws_organizations_organizational_unit.sandbox.id
  iam_user_access_to_billing = "DENY"
  lifecycle {
    prevent_destroy = true
    ignore_changes  = [email]
  }
}

# ─────────────────────────────────────────────────────────────────────────────
# ACCOUNT VENDING MACHINE — local module
# Accepts a request map and creates accounts with baseline config
# In production: triggered by CI/CD pipeline reading from a JSON request file
# Trade-off: Terraform-based vending is synchronous and has a 5-7 minute delay
#             per account. For high-velocity orgs, step functions + EventBridge
#             is the right architecture. This is acceptable for <50 accounts/year.
# ─────────────────────────────────────────────────────────────────────────────
variable "vended_accounts" {
  description = "Map of accounts to vend. Add an entry here and apply — no tickets required."
  type = map(object({
    email      = string
    ou         = string # "sandbox" | "staging" | "production"
    cost_center = string
    team_name  = string
  }))
  default = {}
  # Example:
  # vended_accounts = {
  #   "payments-team" = {
  #     email       = "aws+payments@yourcompany.com"
  #     ou          = "production"
  #     cost_center = "CC-1042"
  #     team_name   = "Payments"
  #   }
  # }
}

locals {
  ou_id_map = {
    sandbox    = aws_organizations_organizational_unit.sandbox.id
    staging    = aws_organizations_organizational_unit.staging.id
    production = aws_organizations_organizational_unit.production.id
  }
}

resource "aws_organizations_account" "vended" {
  for_each = var.vended_accounts

  name      = "${var.org_name}-${each.key}"
  email     = each.value.email
  parent_id = local.ou_id_map[each.value.ou]

  iam_user_access_to_billing = "DENY"

  tags = {
    CostCenter = each.value.cost_center
    TeamName   = each.value.team_name
    VendedBy   = "account-vending-machine"
  }

  lifecycle {
    prevent_destroy = true
    ignore_changes  = [email]
  }
}

# ─────────────────────────────────────────────────────────────────────────────
# OUTPUTS
# ─────────────────────────────────────────────────────────────────────────────
output "org_id" {
  value       = aws_organizations_organization.root.id
  description = "Organization ID — used in SCP conditions and bucket policies"
}

output "account_ids" {
  value = {
    log_archive      = aws_organizations_account.log_archive.id
    security_tooling = aws_organizations_account.security_tooling.id
    shared_services  = aws_organizations_account.shared_services.id
    prod_app         = aws_organizations_account.prod_app.id
    staging_app      = aws_organizations_account.staging_app.id
    sandbox_eng      = aws_organizations_account.sandbox_eng.id
  }
  description = "Account IDs by role — used downstream for cross-account trust policies"
}

output "ou_ids" {
  value = {
    security       = aws_organizations_organizational_unit.security.id
    infrastructure = aws_organizations_organizational_unit.infrastructure.id
    workloads      = aws_organizations_organizational_unit.workloads.id
    production     = aws_organizations_organizational_unit.production.id
    staging        = aws_organizations_organizational_unit.staging.id
    sandbox        = aws_organizations_organizational_unit.sandbox.id
    suspended      = aws_organizations_organizational_unit.suspended.id
  }
}
