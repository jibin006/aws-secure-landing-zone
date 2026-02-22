terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  backend "s3" {
    key = "network/terraform.tfstate"
  }
}

provider "aws" {
  region = var.primary_region
}

variable "primary_region" {
  type    = string
  default = "ap-south-1"
}

variable "org_id" {
  type = string
}

variable "environment" {
  type = string
}

variable "vpc_cidr" {
  type = map(string)
  default = {
    production = "10.0.0.0/16"
    staging    = "10.1.0.0/16"
    sandbox    = "10.2.0.0/16"
  }
}

# ─────────────────────────────────────────────────────────────────────────────
# VPC + FLOW LOGS
#
# SECURITY DESIGN: Flow logs capture ALL traffic metadata (IPs, ports, bytes,
# accept/reject). This is your network-level detection surface.
#
# CRITICAL: Enable REJECT flow logs — most teams only capture ACCEPT.
# REJECT flows reveal: port scanning, lateral movement attempts, misconfigured
# security groups. A sudden spike in REJECT flows from an internal IP is an
# early indicator of compromise.
#
# FLOW LOG DESTINATION: CloudWatch Logs for real-time alerting.
# S3 in log-archive for long-term retention and SIEM ingestion.
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr[var.environment]
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name        = "${var.environment}-vpc"
    Environment = var.environment
  }
}

resource "aws_cloudwatch_log_group" "vpc_flow_logs" {
  name              = "/vpc/flow-logs/${var.environment}"
  retention_in_days = 30 # Local retention. Long-term in log-archive S3.
}

resource "aws_iam_role" "flow_logs" {
  name = "VPCFlowLogs-${var.environment}-Role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "vpc-flow-logs.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "flow_logs" {
  role = aws_iam_role.flow_logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams"
      ]
      Resource = "*"
    }]
  })
}

resource "aws_flow_log" "all_traffic" {
  vpc_id          = aws_vpc.main.id
  traffic_type    = "ALL" # Capture ACCEPT AND REJECT — do not filter to ACCEPT only
  iam_role_arn    = aws_iam_role.flow_logs.arn
  log_destination = aws_cloudwatch_log_group.vpc_flow_logs.arn

  tags = {
    SecurityControl = "network-traffic-capture"
    # DETECTION VALUE: Source for:
    # - Lateral movement detection (unexpected internal-to-internal traffic)
    # - Data exfiltration (high volume outbound to new IPs)
    # - Port scanning (high REJECT count from single source)
    # - C2 beaconing (periodic connections to external IPs)
  }
}

# ─────────────────────────────────────────────────────────────────────────────
# SUBNETS — 3-tier: public (ALB), private (app), isolated (data)
# No direct routes from isolated subnets to internet
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_subnet" "public" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(var.vpc_cidr[var.environment], 8, count.index)
  availability_zone = data.aws_availability_zones.available.names[count.index]

  map_public_ip_on_launch = false # Never auto-assign public IPs
  tags = {
    Name = "${var.environment}-public-${count.index}"
    Tier = "public"
  }
}

resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(var.vpc_cidr[var.environment], 8, count.index + 10)
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = {
    Name = "${var.environment}-private-${count.index}"
    Tier = "private"
  }
}

resource "aws_subnet" "isolated" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(var.vpc_cidr[var.environment], 8, count.index + 20)
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = {
    Name = "${var.environment}-isolated-${count.index}"
    Tier = "isolated"
    # No route table associations with IGW or NAT Gateway
    # RDS, ElastiCache, internal secrets live here
    # Traffic only possible from private subnet via security group rules
  }
}

data "aws_availability_zones" "available" {
  state = "available"
}

# ─────────────────────────────────────────────────────────────────────────────
# NAT GATEWAY
# Required for private subnet → internet egress (patches, package downloads)
# SECURITY NOTE: Capture NAT Gateway flow logs — this is your exfiltration
# detection surface. Every byte going outbound is visible here.
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_eip" "nat" {
  count  = 1
  domain = "vpc"
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
}

resource "aws_nat_gateway" "main" {
  allocation_id = aws_eip.nat[0].id
  subnet_id     = aws_subnet.public[0].id

  tags = {
    SecurityNote = "Monitor NAT Gateway flow logs for high-volume outbound or connections to new destinations"
  }

  depends_on = [aws_internet_gateway.main]
}

# ─────────────────────────────────────────────────────────────────────────────
# VPC ENDPOINTS WITH ORG-SCOPED ENDPOINT POLICIES
#
# SECURITY DESIGN: VPC endpoint policies act as a second IAM evaluation layer.
# Even if an IAM role is compromised and tries to exfiltrate to an attacker's
# S3 bucket, the endpoint policy denies it because the destination bucket
# is not owned by this organization.
#
# This is DATA EXFILTRATION PREVENTION at the network layer.
# No agent required. No additional tooling. Fails closed.
#
# CRITICAL TRADE-OFF: This breaks access to:
# - Public S3 datasets (open data, public packages)
# - Vendor S3 buckets outside your org
# - AWS-owned buckets for some service integrations
# Exception process: route those specific use cases through NAT Gateway
# (which has flow log visibility) rather than relaxing the endpoint policy.
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.primary_region}.s3"
  vpc_endpoint_type = "Gateway"

  route_table_ids = [
    aws_route_table.private.id,
    aws_route_table.isolated.id,
  ]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowOrgS3Access"
        Effect = "Allow"
        Principal = "*"
        Action = "s3:*"
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:ResourceOrgID" = var.org_id
          }
        }
      },
      {
        # AWS-owned buckets for service operations (patch updates, logging destinations)
        # Scope tightly — do not use * for resource here
        Sid    = "AllowAWSServiceBuckets"
        Effect = "Allow"
        Principal = "*"
        Action = ["s3:GetObject"]
        Resource = [
          "arn:aws:s3:::amazonlinux.${var.primary_region}/*",
          "arn:aws:s3:::amazonlinux-2-repos-${var.primary_region}/*",
          "arn:aws:s3:::patch-baseline-snapshot-${var.primary_region}/*",
        ]
      }
    ]
  })

  tags = {
    SecurityControl = "data-exfiltration-prevention"
    PolicyType      = "org-scoped-endpoint-policy"
  }
}

resource "aws_vpc_endpoint" "secretsmanager" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.primary_region}.secretsmanager"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.vpc_endpoints.id]
  private_dns_enabled = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "*" }
      Action    = "secretsmanager:GetSecretValue"
      Resource  = "arn:aws:secretsmanager:${var.primary_region}:*:secret:*"
      Condition = {
        StringEquals = {
          "aws:PrincipalOrgID" = var.org_id
        }
      }
    }]
  })
}

resource "aws_vpc_endpoint" "ssm" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.primary_region}.ssm"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.vpc_endpoints.id]
  private_dns_enabled = true
  # No SSH/RDP required — all EC2 access via SSM Session Manager through this endpoint
}

resource "aws_vpc_endpoint" "ec2messages" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.primary_region}.ec2messages"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.vpc_endpoints.id]
  private_dns_enabled = true
}

resource "aws_vpc_endpoint" "ssmmessages" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.primary_region}.ssmmessages"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.vpc_endpoints.id]
  private_dns_enabled = true
}

# ─────────────────────────────────────────────────────────────────────────────
# SECURITY GROUPS
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_security_group" "vpc_endpoints" {
  name        = "${var.environment}-vpc-endpoints"
  description = "Controls access to VPC interface endpoints. Only internal VPC traffic."
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr[var.environment]]
    description = "HTTPS from VPC CIDR only — no cross-VPC access to endpoints"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Outbound unrestricted — endpoints need to reach AWS service backends"
  }
}

# ─────────────────────────────────────────────────────────────────────────────
# ROUTE TABLES — Explicit segmentation
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }
  tags = { Name = "${var.environment}-public-rt" }
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main.id
  }
  tags = {
    Name        = "${var.environment}-private-rt"
    SecurityNote = "NAT Gateway egress — monitor flow logs for exfiltration"
  }
}

resource "aws_route_table" "isolated" {
  vpc_id = aws_vpc.main.id
  # NO default route — no internet access
  # Only VPC endpoints and VPC-local routes
  tags = {
    Name        = "${var.environment}-isolated-rt"
    SecurityNote = "No internet route — data tier is fully isolated"
  }
}

resource "aws_route_table_association" "public" {
  count          = length(aws_subnet.public)
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "private" {
  count          = length(aws_subnet.private)
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

resource "aws_route_table_association" "isolated" {
  count          = length(aws_subnet.isolated)
  subnet_id      = aws_subnet.isolated[count.index].id
  route_table_id = aws_route_table.isolated.id
}

# ─────────────────────────────────────────────────────────────────────────────
# TRANSIT GATEWAY ATTACHMENT (to shared-services TGW)
# SECURITY: Each environment gets its own TGW route table — no implicit routing
# between prod, staging, and sandbox.
# ─────────────────────────────────────────────────────────────────────────────
variable "transit_gateway_id" {
  description = "TGW ID from shared-services account. Empty string skips TGW attachment."
  type        = string
  default     = ""
}

resource "aws_ec2_transit_gateway_vpc_attachment" "main" {
  count = var.transit_gateway_id != "" ? 1 : 0

  transit_gateway_id = var.transit_gateway_id
  vpc_id             = aws_vpc.main.id
  subnet_ids         = aws_subnet.private[*].id

  # CRITICAL: Disable default route table association
  # Each environment must be explicitly associated with the correct TGW route table
  # Default ON = every attachment can reach every other attachment = full-mesh = no segmentation
  transit_gateway_default_route_table_association = false
  transit_gateway_default_route_table_propagation = false

  tags = {
    Name        = "${var.environment}-tgw-attachment"
    SecurityNote = "Explicit route table association required. No implicit cross-environment routing."
  }
}
