terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  backend "s3" {
    key = "scp/terraform.tfstate"
  }
}

provider "aws" {
  region = var.primary_region
}

variable "primary_region" {
  type    = string
  default = "ap-south-1"
}

variable "allowed_regions" {
  description = "Whitelist of AWS regions workloads are permitted to run in"
  type        = list(string)
  default     = ["ap-south-1", "us-east-1"]
  # Trade-off: Adding a region requires a Terraform change + review process.
  # Operational burden is intentional — expanding blast radius should require friction.
}

variable "org_id" {
  type = string
}

variable "ou_ids" {
  description = "OU IDs from organization module output"
  type = object({
    security       = string
    infrastructure = string
    workloads      = string
    production     = string
    staging        = string
    sandbox        = string
    suspended      = string
  })
}

# ─────────────────────────────────────────────────────────────────────────────
# SCP 1: DENY ROOT ACCOUNT USAGE
#
# THREAT: Root account has unconditional access to all AWS resources and cannot
#         be restricted by SCPs or IAM policies. An attacker with root credentials
#         can create backdoor users, delete all resources, and modify billing.
#         Root credentials are prime targets in credential marketplaces.
#
# CONTROL: API calls using root credentials are blocked org-wide.
#
# BLAST RADIUS WITHOUT CONTROL: Complete account takeover with no IAM-level
#         recovery path. Root actions don't show calling identity in CloudTrail
#         the same way — they show as "Root" with no role session.
#
# TRADE-OFF: Some AWS actions REQUIRE root (e.g., closing an account, enabling
#         MFA on root, changing root email, S3 bucket policy when account is
#         locked out). Break-glass process documented in runbook.
#         These are performed out-of-band, not via Terraform.
#
# DETECTION COMPLEMENT: CloudTrail metric filter on userIdentity.type = "Root"
#         → CloudWatch alarm → PagerDuty. Any root API call is a P1 incident.
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_organizations_policy" "deny_root_usage" {
  name        = "DENY-RootAccountUsage"
  description = "Prevents root account API usage across all member accounts"
  type        = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyRootAccountUsage"
        Effect = "Deny"
        Action = "*"
        Resource = "*"
        Condition = {
          StringLike = {
            "aws:PrincipalArn" = [
              "arn:aws:iam::*:root"
            ]
          }
        }
      }
    ]
  })
}

resource "aws_organizations_policy_attachment" "deny_root_all_accounts" {
  policy_id = aws_organizations_policy.deny_root_usage.id
  target_id = var.ou_ids.workloads # Apply to all workload OUs
}

resource "aws_organizations_policy_attachment" "deny_root_security" {
  policy_id = aws_organizations_policy.deny_root_usage.id
  target_id = var.ou_ids.security
}

resource "aws_organizations_policy_attachment" "deny_root_infrastructure" {
  policy_id = aws_organizations_policy.deny_root_usage.id
  target_id = var.ou_ids.infrastructure
}

# ─────────────────────────────────────────────────────────────────────────────
# SCP 2: REGION RESTRICTION
#
# THREAT: An attacker with valid credentials spins up resources in an unmonitored
#         region (e.g., ap-northeast-3) to avoid detection. Your GuardDuty, Config,
#         and CloudTrail alerting may only cover your active regions. Resources
#         in unexpected regions are a common persistence technique.
#
# CONTROL: API calls are denied in any region not on the allowlist.
#         Global services (IAM, STS, CloudFront, Route53, Support, Billing) are
#         exempt — they have no regional concept and must be allowed.
#
# BLAST RADIUS WITHOUT CONTROL: Attacker can silently create persistence
#         (IAM users, EC2 instances, Lambda) in regions outside your detection
#         coverage. By the time you find it, they've been there for months.
#
# TRADE-OFF: Any new region requires a Terraform PR + approval. This is intentional.
#         Expanding detection coverage to a new region must precede allowing workloads.
#         The SCP enforces that sequencing.
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_organizations_policy" "region_restriction" {
  name        = "DENY-UnauthorizedRegions"
  description = "Restricts all API activity to approved regions only"
  type        = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyUnauthorizedRegions"
        Effect = "Deny"
        NotAction = [
          # Global services — no regional endpoint, cannot be restricted
          "iam:*",
          "sts:*",
          "cloudfront:*",
          "route53:*",
          "route53domains:*",
          "support:*",
          "budgets:*",
          "ce:*",           # Cost Explorer
          "account:*",      # Account management
          "organizations:*" # Org API calls are always us-east-1 internally
        ]
        Resource = "*"
        Condition = {
          StringNotEquals = {
            "aws:RequestedRegion" = var.allowed_regions
          }
        }
      }
    ]
  })
}

resource "aws_organizations_policy_attachment" "region_restriction_workloads" {
  policy_id = aws_organizations_policy.region_restriction.id
  target_id = var.ou_ids.workloads
}

resource "aws_organizations_policy_attachment" "region_restriction_security" {
  policy_id = aws_organizations_policy.region_restriction.id
  target_id = var.ou_ids.security
}

resource "aws_organizations_policy_attachment" "region_restriction_infrastructure" {
  policy_id = aws_organizations_policy.region_restriction.id
  target_id = var.ou_ids.infrastructure
}

# ─────────────────────────────────────────────────────────────────────────────
# SCP 3: DENY CLOUDTRAIL DISABLE/MODIFY
#
# THREAT: An attacker with admin access in an account disables CloudTrail as
#         their first action to blind your detection pipeline before executing
#         their primary objective (exfiltration, lateral movement, persistence).
#         This is Technique T1562.008 in MITRE ATT&CK.
#
# CONTROL: No principal in any member account can stop, delete, or modify the
#         CloudTrail configuration. Attempts fail at the API level.
#
# BLAST RADIUS WITHOUT CONTROL: Full compromise with zero forensic trail.
#         You'll know something happened (alerts will stop), but you'll have
#         no evidence of what happened or when it started.
#
# TRADE-OFF: No legitimate use case for disabling CloudTrail in any non-sandbox
#         account. Operational burden: essentially zero. This is a pure win
#         with no meaningful trade-off in production contexts.
#         Exception: testing CloudTrail configuration changes requires
#         working through the management account pipeline, not direct API calls.
#
# DETECTION COMPLEMENT: Even with this SCP, monitor for attempted disables —
#         the blocked API call itself is a high-fidelity signal that an account
#         may be compromised. A Config rule + GuardDuty finding covers this.
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_organizations_policy" "protect_cloudtrail" {
  name        = "DENY-CloudTrailModification"
  description = "Prevents disabling, deletion, or modification of CloudTrail audit logs"
  type        = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyCloudTrailModification"
        Effect = "Deny"
        Action = [
          "cloudtrail:StopLogging",
          "cloudtrail:DeleteTrail",
          "cloudtrail:UpdateTrail",
          "cloudtrail:PutEventSelectors",
          "cloudtrail:RemoveTags",
          "cloudtrail:AddTags",
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_organizations_policy_attachment" "protect_cloudtrail_workloads" {
  policy_id = aws_organizations_policy.protect_cloudtrail.id
  target_id = var.ou_ids.workloads
}

resource "aws_organizations_policy_attachment" "protect_cloudtrail_security" {
  policy_id = aws_organizations_policy.protect_cloudtrail.id
  target_id = var.ou_ids.security
}

resource "aws_organizations_policy_attachment" "protect_cloudtrail_infrastructure" {
  policy_id = aws_organizations_policy.protect_cloudtrail.id
  target_id = var.ou_ids.infrastructure
}

# ─────────────────────────────────────────────────────────────────────────────
# SCP 4: DENY LEAVING THE ORGANIZATION
#
# THREAT: An attacker with sufficient privileges removes a member account from
#         the organization. Once outside the org, SCPs no longer apply.
#         The attacker now has unrestricted access in an account that was
#         previously protected. They can re-enable root, disable CloudTrail,
#         operate in any region. The account also leaves your consolidated
#         billing — charges appear on a new billing account.
#
# CONTROL: No member account can remove itself from the organization.
#
# BLAST RADIUS WITHOUT CONTROL: Complete bypass of all org-level controls.
#         This single action escalates any account-level compromise to an
#         org-level escape.
#
# TRADE-OFF: Account removal requires management account action. This is correct
#         behavior — account lifecycle is a management plane operation.
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_organizations_policy" "deny_leave_org" {
  name        = "DENY-LeaveOrganization"
  description = "Prevents member accounts from removing themselves from the organization"
  type        = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "DenyLeaveOrganization"
        Effect   = "Deny"
        Action   = ["organizations:LeaveOrganization"]
        Resource = "*"
      }
    ]
  })
}

resource "aws_organizations_policy_attachment" "deny_leave_all_workloads" {
  policy_id = aws_organizations_policy.deny_leave_org.id
  target_id = var.ou_ids.workloads
}

resource "aws_organizations_policy_attachment" "deny_leave_security" {
  policy_id = aws_organizations_policy.deny_leave_org.id
  target_id = var.ou_ids.security
}

resource "aws_organizations_policy_attachment" "deny_leave_infrastructure" {
  policy_id = aws_organizations_policy.deny_leave_org.id
  target_id = var.ou_ids.infrastructure
}

# ─────────────────────────────────────────────────────────────────────────────
# SCP 5: DENY IAM USER CREATION IN MEMBER ACCOUNTS
#
# THREAT: Long-lived IAM user credentials are the #1 source of AWS credential
#         compromise. Keys get committed to GitHub, stored in .env files,
#         hardcoded in Lambda environment variables. An attacker who finds a
#         key has persistent access until rotation — and rotation is often
#         never done.
#
# CONTROL: No IAM users can be created in any member account.
#         All human access flows through IAM Identity Center (SSO) with
#         temporary credentials. Machine access uses IAM roles with
#         assumed role credentials (15 min - 12 hour lifetime max).
#
# BLAST RADIUS WITHOUT CONTROL: Persistent credential sprawl. Even after
#         an incident is contained, undiscovered IAM users may remain as
#         backdoors. This SCP makes backdoor-via-IAM-user impossible.
#
# TRADE-OFF: Some legacy integrations require IAM user keys (certain SaaS
#         vendors, old SDKs that don't support assume-role). These require
#         an exception process documented in the SCP exception register.
#         The friction is intentional — it surfaces technical debt.
#
# EXCEPTION PROCESS: Service accounts that genuinely need long-lived keys
#         must be created in a dedicated "legacy-integrations" account with
#         additional monitoring. Never in workload accounts.
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_organizations_policy" "deny_iam_user_creation" {
  name        = "DENY-IAMUserCreation"
  description = "Forces all access through IAM Identity Center. No long-lived IAM user keys."
  type        = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyIAMUserCreation"
        Effect = "Deny"
        Action = [
          "iam:CreateUser",
          "iam:CreateAccessKey",
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_organizations_policy_attachment" "deny_iam_users_production" {
  policy_id = aws_organizations_policy.deny_iam_user_creation.id
  target_id = var.ou_ids.production
}

resource "aws_organizations_policy_attachment" "deny_iam_users_staging" {
  policy_id = aws_organizations_policy.deny_iam_user_creation.id
  target_id = var.ou_ids.staging
}

# Note: Intentionally NOT applied to sandbox — engineers may need to test
# IAM user flows. Sandbox has no production data and separate blast radius.

# ─────────────────────────────────────────────────────────────────────────────
# SCP 6: PROTECT SECURITY TOOLING ROLES
#
# THREAT: An attacker with admin access in an account deletes or modifies the
#         GuardDuty/SecurityHub/Config service roles to blind your detection
#         pipeline. This is a pre-attack technique — disable detection, then act.
#
# CONTROL: Specific security service roles cannot be modified or deleted.
#         The role name pattern matches the roles deployed by the baseline module.
#
# TRADE-OFF: Legitimate updates to these roles (adding new permissions for new
#         AWS services) must go through the management account pipeline.
#         This is correct — security infrastructure changes are high-risk
#         and should have higher approval friction than workload changes.
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_organizations_policy" "protect_security_roles" {
  name        = "DENY-SecurityRoleModification"
  description = "Prevents modification of security tooling IAM roles (GuardDuty, Config, SecurityHub)"
  type        = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ProtectSecurityRoles"
        Effect = "Deny"
        Action = [
          "iam:AttachRolePolicy",
          "iam:DeleteRole",
          "iam:DeleteRolePermissionsBoundary",
          "iam:DeleteRolePolicy",
          "iam:DetachRolePolicy",
          "iam:PutRolePermissionsBoundary",
          "iam:PutRolePolicy",
          "iam:UpdateAssumeRolePolicy",
          "iam:UpdateRole",
        ]
        Resource = [
          "arn:aws:iam::*:role/aws-service-role/guardduty.amazonaws.com/*",
          "arn:aws:iam::*:role/aws-service-role/config.amazonaws.com/*",
          "arn:aws:iam::*:role/aws-service-role/securityhub.amazonaws.com/*",
          "arn:aws:iam::*:role/SecurityBaseline-*", # Pattern for baseline-deployed roles
        ]
      }
    ]
  })
}

resource "aws_organizations_policy_attachment" "protect_security_roles_workloads" {
  policy_id = aws_organizations_policy.protect_security_roles.id
  target_id = var.ou_ids.workloads
}

# ─────────────────────────────────────────────────────────────────────────────
# SCP 7: SUSPENDED OU — DENY ALL
# Applied to accounts moved to Suspended OU during incident response.
# Allows ONLY the incident response automation role to operate.
#
# THREAT CONTEXT: During an active incident, you need to freeze the account
#         immediately without losing forensic capability. This SCP stops
#         all further damage while allowing your IR role to collect evidence.
#
# CRITICAL OPERATIONAL NOTE: This SCP must exist BEFORE an incident.
#         The IR role ARN must be created in EVERY account as part of baseline
#         (see baseline module). You cannot assume a role that doesn't exist.
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_organizations_policy" "suspended_deny_all" {
  name        = "DENY-AllExceptIRRole"
  description = "Applied during incident response. Freezes account except for IR automation role."
  type        = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyAllExceptIRRole"
        Effect = "Deny"
        Action = "*"
        Resource = "*"
        Condition = {
          ArnNotLike = {
            "aws:PrincipalArn" = [
              "arn:aws:iam::*:role/IncidentResponse-AutomationRole",
              "arn:aws:iam::*:role/OrganizationAccountAccessRole" # Break-glass
            ]
          }
        }
      }
    ]
  })
}

resource "aws_organizations_policy_attachment" "suspended_deny_all" {
  policy_id = aws_organizations_policy.suspended_deny_all.id
  target_id = var.ou_ids.suspended
}

# ─────────────────────────────────────────────────────────────────────────────
# OUTPUTS
# ─────────────────────────────────────────────────────────────────────────────
output "scp_ids" {
  value = {
    deny_root            = aws_organizations_policy.deny_root_usage.id
    region_restriction   = aws_organizations_policy.region_restriction.id
    protect_cloudtrail   = aws_organizations_policy.protect_cloudtrail.id
    deny_leave_org       = aws_organizations_policy.deny_leave_org.id
    deny_iam_users       = aws_organizations_policy.deny_iam_user_creation.id
    protect_sec_roles    = aws_organizations_policy.protect_security_roles.id
    suspended_deny_all   = aws_organizations_policy.suspended_deny_all.id
  }
}
