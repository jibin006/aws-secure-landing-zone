# Deployment Guide — Fresh AWS Account

This guide walks through deploying the landing zone from a fresh AWS account.
Estimated time: 2–3 hours for full deployment.

---

## Prerequisites

### 1. Install Required Tools

```bash
# Terraform >= 1.6
brew install terraform
terraform -version  # Should show >= 1.6.0

# AWS CLI v2
brew install awscli
aws --version
```

### 2. AWS Account Setup (One-Time Manual Steps)

These steps CANNOT be automated — they require console or root-level access:

**a) Secure the root account (do this first, before anything else)**
```
Console → Root account → Enable MFA (use hardware key or authenticator app)
Console → Root account → Remove all access keys (root should have zero API keys)
```

**b) Enable IAM Identity Center (SSO)**
```
Console → IAM Identity Center → Enable
Choose: AWS Organizations (not standalone)
```

**c) Create your initial admin user in IAM Identity Center**
```
IAM Identity Center → Users → Add user
Email: your-email@company.com
Assign to: AdministratorAccess permission set
Assign to: Management account
```

**d) Get your Organization ID**
```bash
aws organizations describe-organization --query 'Organization.Id' --output text
# Save this — you'll need it as var.org_id throughout
```

### 3. Configure AWS CLI

```bash
# Configure SSO profile — DO NOT use root credentials or long-lived IAM user keys
aws configure sso
# SSO start URL: https://your-instance.awsapps.com/start
# SSO region: ap-south-1
# Account ID: your management account ID
# Role name: AdministratorAccess
# Profile name: landing-zone-mgmt

# Test authentication
aws sts get-caller-identity --profile landing-zone-mgmt
```

---

## Deployment Steps

### Step 1: Bootstrap State Backend

```bash
cd terraform/state-backend

# Create terraform.tfvars
cat > terraform.tfvars <<EOF
org_name       = "yourorg"          # Replace with your org short name
primary_region = "ap-south-1"
org_id         = "o-xxxxxxxxxxxx"   # Your organization ID
EOF

# Deploy (this uses local state — acceptable one-time bootstrap exception)
AWS_PROFILE=landing-zone-mgmt terraform init
AWS_PROFILE=landing-zone-mgmt terraform plan
AWS_PROFILE=landing-zone-mgmt terraform apply

# Note the outputs
terraform output state_bucket_name
terraform output state_lock_table

# Update backend.hcl key for organization module
sed -i 's/REPLACE_WITH_MODULE_PATH/organization/' backend.hcl
```

### Step 2: Create Organization Structure

```bash
cd ../organization

# Create terraform.tfvars
# IMPORTANT: AWS account creation requires unique email per account
# Use email+alias pattern: you+log-archive@gmail.com works fine
cat > terraform.tfvars <<EOF
org_name               = "yourorg"
primary_region         = "ap-south-1"
log_archive_email      = "you+log-archive@yourcompany.com"
security_tooling_email = "you+security-tooling@yourcompany.com"
shared_services_email  = "you+shared-services@yourcompany.com"
prod_app_email         = "you+prod-app@yourcompany.com"
staging_app_email      = "you+staging-app@yourcompany.com"
sandbox_eng_email      = "you+sandbox-eng@yourcompany.com"
EOF

# Copy backend config and update key
cp ../state-backend/backend.hcl .
sed -i 's/organization\/terraform.tfstate/organization\/terraform.tfstate/' backend.hcl

AWS_PROFILE=landing-zone-mgmt terraform init -backend-config=backend.hcl
AWS_PROFILE=landing-zone-mgmt terraform plan
AWS_PROFILE=landing-zone-mgmt terraform apply

# IMPORTANT: AWS account creation takes 2-5 minutes per account
# Total for 6 accounts: ~15-20 minutes
# Do not interrupt apply

# Save outputs
terraform output -json > ../outputs-organization.json
```

### Step 3: Apply SCPs

```bash
cd ../scp

# Get OU IDs from organization output
OU_IDS=$(cat ../outputs-organization.json | jq '.ou_ids.value')
ORG_ID=$(cat ../outputs-organization.json | jq -r '.org_id.value')

cat > terraform.tfvars <<EOF
primary_region  = "ap-south-1"
org_id          = "$ORG_ID"

# Paste OU IDs from organization output
ou_ids = {
  security       = "ou-xxxx-xxxxxxxx"   # Replace with actual values from output
  infrastructure = "ou-xxxx-xxxxxxxx"
  workloads      = "ou-xxxx-xxxxxxxx"
  production     = "ou-xxxx-xxxxxxxx"
  staging        = "ou-xxxx-xxxxxxxx"
  sandbox        = "ou-xxxx-xxxxxxxx"
  suspended      = "ou-xxxx-xxxxxxxx"
}
EOF

cp ../state-backend/backend.hcl .
sed -i 's/REPLACE_WITH_MODULE_PATH/scp/' backend.hcl

AWS_PROFILE=landing-zone-mgmt terraform init -backend-config=backend.hcl
AWS_PROFILE=landing-zone-mgmt terraform plan

# CAREFULLY REVIEW THE PLAN
# SCPs take effect immediately. A wrong SCP can lock you out of accounts.
# Verify the region allowlist includes your working region before applying.

AWS_PROFILE=landing-zone-mgmt terraform apply
```

**⚠️ SCP Deployment Warning:**  
SCPs apply immediately. Before applying the `DENY-IAMUserCreation` SCP, ensure you have working SSO access configured. If you're relying on IAM users for access, you'll lock yourself out of the affected OUs.

### Step 4: Deploy Baseline to Each Account

For each member account, assume role and deploy baseline:

```bash
cd ../baseline

# First, add member account profiles to ~/.aws/config
# AWS Organizations creates OrganizationAccountAccessRole in each account

cat >> ~/.aws/config <<EOF
[profile log-archive]
role_arn = arn:aws:iam::LOG_ARCHIVE_ACCOUNT_ID:role/OrganizationAccountAccessRole
source_profile = landing-zone-mgmt
region = ap-south-1

[profile security-tooling]  
role_arn = arn:aws:iam::SECURITY_TOOLING_ACCOUNT_ID:role/OrganizationAccountAccessRole
source_profile = landing-zone-mgmt
region = ap-south-1

[profile prod-app]
role_arn = arn:aws:iam::PROD_APP_ACCOUNT_ID:role/OrganizationAccountAccessRole
source_profile = landing-zone-mgmt
region = ap-south-1
EOF

# Deploy to each account (repeat for each)
cp ../state-backend/backend.hcl .
sed -i 's/REPLACE_WITH_MODULE_PATH/baseline\/prod-app/' backend.hcl

cat > terraform.tfvars <<EOF
primary_region         = "ap-south-1"
environment            = "production"
org_id                 = "o-xxxxxxxxxxxx"
org_name               = "yourorg"
log_archive_account_id = "123456789012"  # log-archive account ID
EOF

AWS_PROFILE=prod-app terraform init -backend-config=backend.hcl
AWS_PROFILE=prod-app terraform plan
AWS_PROFILE=prod-app terraform apply
```

### Step 5: Deploy Network

```bash
cd ../network

# Deploy one VPC per environment account
# Run once per environment, switching AWS_PROFILE

cat > terraform.tfvars <<EOF
primary_region = "ap-south-1"
environment    = "production"
org_id         = "o-xxxxxxxxxxxx"
EOF

cp ../state-backend/backend.hcl .
sed -i 's/REPLACE_WITH_MODULE_PATH/network\/production/' backend.hcl

AWS_PROFILE=prod-app terraform init -backend-config=backend.hcl
AWS_PROFILE=prod-app terraform apply
```

---

## Verification Checklist

After deployment, verify each control is working:

```bash
# 1. Verify CloudTrail is running in all accounts
aws cloudtrail describe-trails --profile prod-app --include-shadow-trails false

# 2. Verify GuardDuty is enabled
aws guardduty list-detectors --profile prod-app

# 3. Verify Config recorder is running
aws configservice describe-configuration-recorder-status --profile prod-app

# 4. Verify SecurityHub is enabled
aws securityhub describe-hub --profile prod-app

# 5. Test SCP: try to stop CloudTrail (should fail with AccessDenied)
aws cloudtrail stop-logging \
  --name $(aws cloudtrail describe-trails --profile prod-app --query 'trailList[0].Name' --output text) \
  --profile prod-app
# Expected: "An error occurred (AccessDeniedException)"

# 6. Test SCP: try to create IAM user in production (should fail)
aws iam create-user --user-name test-scp-user --profile prod-app
# Expected: "An error occurred (AccessDeniedException)"

# 7. Test SCP: try to use an unauthorized region
aws ec2 describe-instances --region eu-west-1 --profile prod-app
# Expected: "An error occurred (AccessDeniedException)"
```

---

## Common Issues and Fixes

**Issue:** `terraform apply` fails with `ACCOUNT_NUMBER_LIMIT_EXCEEDED`  
**Fix:** AWS free tier accounts have a limit of 10 accounts. Request a limit increase via Support Console before deploying.

**Issue:** SCP applied but not blocking expected actions  
**Fix:** Check that the account is in the correct OU. SCPs apply to the OU hierarchy. Accounts directly under Root are only covered by Root-level SCPs.

**Issue:** Config rule shows `INSUFFICIENT_DATA` for all resources  
**Fix:** Config recorder takes 10–15 minutes to do its initial sweep. Wait and refresh.

**Issue:** CloudTrail delivery to log-archive S3 fails  
**Fix:** The log-archive S3 bucket needs a bucket policy allowing CloudTrail delivery from all org accounts. This is managed in the baseline module — ensure the log-archive account baseline was deployed first.
