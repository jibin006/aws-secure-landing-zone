terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  backend "s3" {
    key = "baseline/terraform.tfstate"
  }
}

# Deploy baseline to the primary region
provider "aws" {
  alias  = "member_account"
  region = var.primary_region

  # In production: assume role into each member account
  # assume_role {
  #   role_arn = "arn:aws:iam::${var.account_id}:role/OrganizationAccountAccessRole"
  # }
}

variable "primary_region" {
  type    = string
  default = "ap-south-1"
}

variable "log_archive_account_id" {
  description = "Account ID of the log-archive account. CloudTrail delivers logs here."
  type        = string
}

variable "org_id" {
  type = string
}

variable "org_name" {
  type    = string
  default = "myorg"
}

variable "environment" {
  description = "Account environment label: production | staging | sandbox | security | infrastructure"
  type        = string

  validation {
    condition     = contains(["production", "staging", "sandbox", "security", "infrastructure"], var.environment)
    error_message = "Environment must be one of: production, staging, sandbox, security, infrastructure"
  }
}

# ─────────────────────────────────────────────────────────────────────────────
# CLOUDTRAIL — Organization-wide audit trail
#
# SECURITY DESIGN DECISIONS:
# 1. Logs delivered to log-archive account — separate credentials required
#    to tamper with evidence. SCP on log-archive prevents deletion.
# 2. Log file validation enabled — SHA-256 hash chain detects tampering.
#    Even if an attacker modifies log content, validation will show it.
# 3. S3 data events and Lambda events enabled — without these, you're blind
#    to data plane operations (GetObject, PutObject, Invoke). Most exfiltration
#    happens at the data plane. Management events alone are insufficient.
# 4. CloudWatch Logs integration — enables real-time metric filters and alarms
#    on specific API patterns (root usage, unauthorized attempts, etc.)
#
# TRADE-OFF: Data events significantly increase CloudTrail cost in high-volume
#    S3 environments. Selector filters on specific buckets reduce cost while
#    maintaining coverage on sensitive data stores.
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_cloudwatch_log_group" "cloudtrail" {
  provider          = aws.member_account
  name              = "/aws/cloudtrail/${var.org_name}-${var.environment}"
  retention_in_days = 90 # Local retention for real-time alerting. Long-term in log-archive S3.

  tags = {
    Purpose = "CloudTrail real-time log delivery for metric filters and alarms"
  }
}

resource "aws_iam_role" "cloudtrail_to_cloudwatch" {
  provider = aws.member_account
  name     = "SecurityBaseline-CloudTrailCloudWatchRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudtrail.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "cloudtrail_to_cloudwatch" {
  provider = aws.member_account
  name     = "CloudTrailCloudWatchDelivery"
  role     = aws_iam_role.cloudtrail_to_cloudwatch.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ]
      Resource = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
    }]
  })
}

resource "aws_cloudtrail" "main" {
  provider                      = aws.member_account
  name                          = "${var.org_name}-${var.environment}-trail"
  s3_bucket_name                = "REPLACE-WITH-LOG-ARCHIVE-BUCKET-NAME"
  # In production: reference log-archive bucket via data source or variable
  # This bucket is in the log-archive account and has a bucket policy allowing
  # CloudTrail delivery from all org accounts.

  include_global_service_events = true # IAM, STS, CloudFront events
  is_multi_region_trail         = true # Catches activity in ALL regions, not just primary
  enable_log_file_validation    = true # SHA-256 hash chain — detect tampering

  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail_to_cloudwatch.arn

  event_selector {
    read_write_type                  = "All"
    include_management_events        = true

    # Data events: S3 — critical for exfiltration detection
    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::"] # All S3 buckets
      # Production optimization: replace with specific sensitive bucket ARNs
      # to reduce cost while maintaining coverage on high-value data stores
    }

    # Data events: Lambda — detect unusual invocation patterns
    data_resource {
      type   = "AWS::Lambda::Function"
      values = ["arn:aws:lambda"]
    }
  }

  tags = {
    SecurityControl = "audit-trail"
    Criticality     = "high"
  }
}

# ─────────────────────────────────────────────────────────────────────────────
# CLOUDWATCH METRIC FILTERS AND ALARMS
# These are your real-time detection layer on top of CloudTrail.
# Each filter targets a specific high-signal security event.
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_sns_topic" "security_alerts" {
  provider = aws.member_account
  name     = "security-baseline-alerts"
  # In production: subscribe this to your SIEM/PagerDuty endpoint
}

locals {
  # Map of metric filters: name → { pattern, description, threshold }
  security_metric_filters = {
    root_usage = {
      pattern     = "{ $.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \"AwsServiceEvent\" }"
      description = "Root account API usage — always a P1 security event"
      threshold   = 1
    }
    unauthorized_api = {
      pattern     = "{ ($.errorCode = \"*UnauthorizedAccess*\") || ($.errorCode = \"AccessDenied*\") }"
      description = "Unauthorized API calls — may indicate credential probing or privilege escalation attempts"
      threshold   = 10
    }
    console_no_mfa = {
      pattern     = "{ $.eventName = \"ConsoleLogin\" && $.additionalEventData.MFAUsed != \"Yes\" }"
      description = "Console login without MFA — enforce MFA via IAM Identity Center, this catches gaps"
      threshold   = 1
    }
    cloudtrail_disable_attempt = {
      pattern     = "{ ($.eventName = \"StopLogging\") || ($.eventName = \"DeleteTrail\") || ($.eventName = \"UpdateTrail\") }"
      description = "Attempted CloudTrail modification — SCP should block this; alert fires on the attempt itself"
      threshold   = 1
    }
    iam_policy_change = {
      pattern     = "{ ($.eventName=DeleteGroupPolicy) || ($.eventName=DeleteRolePolicy) || ($.eventName=DeleteUserPolicy) || ($.eventName=PutGroupPolicy) || ($.eventName=PutRolePolicy) || ($.eventName=PutUserPolicy) || ($.eventName=CreatePolicy) || ($.eventName=DeletePolicy) || ($.eventName=CreatePolicyVersion) || ($.eventName=DeletePolicyVersion) || ($.eventName=SetDefaultPolicyVersion) }"
      description = "IAM policy modifications — track all privilege changes"
      threshold   = 1
    }
    vpc_changes = {
      pattern     = "{ ($.eventName=CreateVpc) || ($.eventName=DeleteVpc) || ($.eventName=ModifyVpcAttribute) || ($.eventName=AcceptVpcPeeringConnection) || ($.eventName=CreateVpcPeeringConnection) || ($.eventName=DeleteVpcPeeringConnection) || ($.eventName=RejectVpcPeeringConnection) }"
      description = "VPC configuration changes — network boundary modifications"
      threshold   = 1
    }
    s3_bucket_public = {
      pattern     = "{ ($.eventName=PutBucketAcl) || ($.eventName=PutBucketPolicy) || ($.eventName=PutBucketCors) || ($.eventName=DeleteBucketPolicy) }"
      description = "S3 bucket policy changes — detect public exposure attempts"
      threshold   = 1
    }
  }
}

resource "aws_cloudwatch_log_metric_filter" "security" {
  provider       = aws.member_account
  for_each       = local.security_metric_filters
  name           = "SecurityBaseline-${each.key}"
  pattern        = each.value.pattern
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name

  metric_transformation {
    name      = "SecurityBaseline-${each.key}"
    namespace = "SecurityBaseline/CloudTrail"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "security" {
  provider            = aws.member_account
  for_each            = local.security_metric_filters
  alarm_name          = "SecurityBaseline-${each.key}"
  alarm_description   = each.value.description
  metric_name         = "SecurityBaseline-${each.key}"
  namespace           = "SecurityBaseline/CloudTrail"
  statistic           = "Sum"
  period              = 300 # 5-minute evaluation window
  evaluation_periods  = 1
  threshold           = each.value.threshold
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
}

# ─────────────────────────────────────────────────────────────────────────────
# GUARDDUTY
#
# SECURITY DESIGN: GuardDuty is the behavioral detection layer.
# It analyzes CloudTrail, VPC Flow Logs, and DNS logs using threat intel
# and ML models. Unlike Config rules (configuration drift), GuardDuty
# detects behavioral anomalies within permitted operations.
#
# DELEGATED ADMIN: GuardDuty admin is delegated to security-tooling account.
# Findings from all member accounts aggregate there. This means even if an
# attacker disables GuardDuty in a member account, the management/security
# account still has findings up to that point.
#
# TRADE-OFF: GuardDuty has cost based on data volume. EKS runtime monitoring
# adds agent overhead on nodes. Enable incrementally based on threat model.
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_guardduty_detector" "main" {
  provider = aws.member_account
  enable   = true

  datasources {
    s3_logs {
      enable = true # Detect S3 data plane threats (exfiltration, anomalous access)
    }
    kubernetes {
      audit_logs {
        enable = true # Detect K8s control plane threats (if using EKS)
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = true # Auto-scan EBS volumes when GuardDuty finds a threat
        }
      }
    }
  }

  tags = {
    SecurityControl = "behavioral-detection"
  }
}

# ─────────────────────────────────────────────────────────────────────────────
# AWS CONFIG
#
# SECURITY DESIGN: Config is the configuration drift detection layer.
# It records the state of AWS resources and evaluates them against rules.
# Complements GuardDuty (behavioral) and SCPs (preventive).
#
# DELIVERY: Config snapshots go to log-archive account — same as CloudTrail.
# Single audit destination simplifies compliance evidence collection.
#
# RULE EVALUATION: Use CHANGE_TRIGGERED wherever possible.
# PERIODIC evaluation (1hr/3hr/6hr/24hr) means you have a detection gap.
# A misconfiguration that exists for 5 hours 59 minutes before a 6hr eval
# is 5h59m of undetected exposure. Change-triggered evaluation fires within
# seconds of the resource change. This is the correct posture for security controls.
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_config_configuration_recorder" "main" {
  provider = aws.member_account
  name     = "SecurityBaseline-Recorder"

  role_arn = aws_iam_role.config_recorder.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_iam_role" "config_recorder" {
  provider = aws.member_account
  name     = "SecurityBaseline-ConfigRecorderRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "config.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "config_recorder" {
  provider   = aws.member_account
  role       = aws_iam_role.config_recorder.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

resource "aws_config_delivery_channel" "main" {
  provider       = aws.member_account
  name           = "SecurityBaseline-DeliveryChannel"
  s3_bucket_name = "REPLACE-WITH-LOG-ARCHIVE-CONFIG-BUCKET"
  # Deliver Config snapshots and history to log-archive account

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_configuration_recorder_status" "main" {
  provider   = aws.member_account
  name       = aws_config_configuration_recorder.main.name
  is_enabled = true
  depends_on = [aws_config_delivery_channel.main]
}

# Config Rules — Change-triggered where possible
locals {
  config_managed_rules = {
    s3_public_access = {
      name       = "s3-account-level-public-access-blocks"
      identifier = "S3_ACCOUNT_LEVEL_PUBLIC_ACCESS_BLOCKS"
      trigger    = "CONFIGURATION_CHANGE"
    }
    mfa_on_root = {
      name       = "root-account-mfa-enabled"
      identifier = "ROOT_ACCOUNT_MFA_ENABLED"
      trigger    = "PERIODIC" # Root account is a special case — no config change trigger available
    }
    cloudtrail_enabled = {
      name       = "cloudtrail-enabled"
      identifier = "CLOUD_TRAIL_ENABLED"
      trigger    = "PERIODIC"
    }
    guardduty_enabled = {
      name       = "guardduty-enabled-centralized"
      identifier = "GUARDDUTY_ENABLED_CENTRALIZED"
      trigger    = "PERIODIC"
    }
    access_keys_rotation = {
      name       = "access-keys-rotated"
      identifier = "ACCESS_KEYS_ROTATED"
      trigger    = "PERIODIC"
    }
    vpc_flow_logs = {
      name       = "vpc-flow-logs-enabled"
      identifier = "VPC_FLOW_LOGS_ENABLED"
      trigger    = "CONFIGURATION_CHANGE"
    }
    no_unrestricted_ssh = {
      name       = "restricted-ssh"
      identifier = "INCOMING_SSH_DISABLED"
      trigger    = "CONFIGURATION_CHANGE"
    }
    encrypted_volumes = {
      name       = "encrypted-volumes"
      identifier = "ENCRYPTED_VOLUMES"
      trigger    = "CONFIGURATION_CHANGE"
    }
    rds_encryption = {
      name       = "rds-storage-encrypted"
      identifier = "RDS_STORAGE_ENCRYPTED"
      trigger    = "CONFIGURATION_CHANGE"
    }
    iam_password_policy = {
      name       = "iam-password-policy"
      identifier = "IAM_PASSWORD_POLICY"
      trigger    = "PERIODIC"
    }
  }
}

resource "aws_config_config_rule" "managed" {
  provider = aws.member_account
  for_each = local.config_managed_rules
  name     = each.value.name

  source {
    owner             = "AWS"
    source_identifier = each.value.identifier
  }

  depends_on = [aws_config_configuration_recorder.main]
}

# ─────────────────────────────────────────────────────────────────────────────
# INCIDENT RESPONSE AUTOMATION ROLE
# This role MUST exist in every account BEFORE an incident occurs.
# The Suspended OU SCP allows ONLY this role to operate in quarantined accounts.
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_iam_role" "incident_response" {
  provider = aws.member_account
  name     = "IncidentResponse-AutomationRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        # Only the security-tooling account's IR automation can assume this role
        AWS = "arn:aws:iam::SECURITY-TOOLING-ACCOUNT-ID:role/IROrchestration-Role"
      }
      Action    = "sts:AssumeRole"
      Condition = {
        StringEquals = {
          "sts:ExternalId" = "ir-automation-${var.org_name}"
          # ExternalId prevents confused deputy attacks
        }
      }
    }]
  })

  tags = {
    Purpose         = "incident-response-automation"
    SecurityControl = "ir-capability"
  }
}

resource "aws_iam_role_policy" "incident_response" {
  provider = aws.member_account
  name     = "IRForensicPolicy"
  role     = aws_iam_role.incident_response.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # Read-only forensic access — collect evidence without modifying
        Sid    = "ForensicReadAccess"
        Effect = "Allow"
        Action = [
          "ec2:Describe*",
          "ec2:CreateSnapshot",     # Capture disk state for forensics
          "ec2:CreateImage",
          "s3:GetObject",
          "s3:ListBucket",
          "cloudtrail:GetTrailStatus",
          "cloudtrail:DescribeTrails",
          "logs:DescribeLogGroups",
          "logs:GetLogEvents",
          "iam:GetRole",
          "iam:ListRoles",
          "guardduty:GetFindings",
          "guardduty:ListFindings",
        ]
        Resource = "*"
      },
      {
        # Containment actions — isolate compromised resources
        Sid    = "ContainmentActions"
        Effect = "Allow"
        Action = [
          "ec2:StopInstances",
          "ec2:TerminateInstances",
          "ec2:RevokeSecurityGroupIngress",
          "ec2:RevokeSecurityGroupEgress",
          "iam:AttachRolePolicy",       # Attach deny-all policy to compromised role
          "iam:PutRolePolicy",
        ]
        Resource = "*"
      }
    ]
  })
}

# ─────────────────────────────────────────────────────────────────────────────
# SECURITY HUB — Aggregates findings from GuardDuty, Config, Inspector
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_securityhub_account" "main" {
  provider                 = aws.member_account
  enable_default_standards = true
  # Enables: AWS Foundational Security Best Practices, CIS AWS Foundations
}

resource "aws_securityhub_standards_subscription" "aws_fsbp" {
  provider      = aws.member_account
  standards_arn = "arn:aws:securityhub:${var.primary_region}::standards/aws-foundational-security-best-practices/v/1.0.0"
  depends_on    = [aws_securityhub_account.main]
}

resource "aws_securityhub_standards_subscription" "cis" {
  provider      = aws.member_account
  standards_arn = "arn:aws:securityhub:${var.primary_region}::standards/cis-aws-foundations-benchmark/v/1.4.0"
  depends_on    = [aws_securityhub_account.main]
}
