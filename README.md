
aws-secure-landing-zone/
├── README.md
├── iam/
│   ├── oidc/
│   ├── cross-account/
│   └── vending-machine/
├── docs/
│   └── iam-ai-workload-analysis.md
└── .github/
    └── workflows/


# AWS Secure Landing Zone — Production-Grade Multi-Account Architecture

> **Portfolio Project** | Cloud Security Engineering | Jibin Benny  
> Built to demonstrate security architecture depth, not configuration familiarity.

---

## Architecture Philosophy

This landing zone is designed around one question at every decision point:

> **If account X is fully compromised, what is the maximum blast radius, and what is the detection latency?**

Every SCP, every account boundary, every logging decision traces back to that question.

---

## Account Structure

```
Root (Management Account) — NO workloads run here
├── Security OU
│   ├── log-archive          ← Immutable audit trail. Separate credentials. Harder to destroy than to commit the attack.
│   └── security-tooling     ← GuardDuty delegated admin, SecurityHub aggregator, Config aggregator
├── Infrastructure OU
│   └── shared-services      ← Transit Gateway, Route53 Resolver, shared AMI library
├── Workloads OU
│   ├── Production OU
│   │   └── prod-app         ← Production workloads. Strictest SCPs.
│   ├── Staging OU
│   │   └── staging-app      ← Pre-prod. Moderate SCPs.
│   └── Sandbox OU
│       └── sandbox-eng      ← Engineer experimentation. Region-restricted. No prod data.
└── Suspended OU             ← Quarantine zone. Deny-all SCP. Used during incident response.
```

---

## Blast Radius Analysis

### Scenario 1: Sandbox Account Compromised
- **What the attacker can reach:** Only resources within `sandbox-eng`. No VPC peering to production or staging (TGW route tables are segmented). No cross-account IAM role trust from sandbox to workload accounts.
- **What they cannot reach:** Production data, staging databases, CloudTrail in log-archive account, any Security OU resources.
- **Detection latency:** GuardDuty finding within ~5 minutes of anomalous API calls. CloudTrail events in log-archive within 5–15 minutes (delivery SLA).
- **Residual risk:** An attacker can burn the sandbox account, incur cost, or use it as a pivot point for phishing (spoofing internal-looking domains). Blast radius is contained; reputational risk is not zero.

### Scenario 2: Production Workload Account Compromised
- **What the attacker can reach:** Resources within `prod-app`. IAM roles with cross-account trust to `shared-services` for specific actions (read-only).
- **What they cannot reach:** Cannot modify SCPs (only management account can). Cannot disable CloudTrail (SCP deny). Cannot access log-archive (separate account, separate credentials, deny policy on log bucket).
- **Detection latency:** GuardDuty + SecurityHub correlation within 5 minutes. Cross-account role assumption logged in both accounts' CloudTrail.
- **Residual risk:** Data exfiltration within the account before detection. VPC endpoint policy limits S3 exfiltration to org-owned buckets. Not all exfiltration paths are closed (e.g., direct HTTPS to attacker infra via NAT Gateway). Detection engineering pipeline covers this.

### Scenario 3: Management Account Compromised — Worst Case
- **What the attacker can reach:** Everything. Can detach SCPs, modify org structure, access consolidated billing.
- **What limits the damage:** Management account has no workloads, no long-lived credentials in use, access only via SSO with MFA. Break-glass access is the only credential path (documented in `docs/break-glass-runbook.md`). CloudTrail from management account flows to log-archive — but if attacker has management account access they can eventually reach log-archive too.
- **Detection latency:** Any API call from management account outside normal SSO patterns triggers a high-priority GuardDuty finding. PagerDuty escalation within 2 minutes.
- **Residual risk:** This is an existential event. The architecture minimizes likelihood through access restriction, not just detection. Management account compromise = full incident response activation.

---

## Control Design Decisions

### Why SCPs Are Not Enough (and what fills the gap)

| Layer | Instrument | What it covers | What it misses |
|---|---|---|---|
| Preventive | SCP | Blocks IAM-controlled actions | Behavior within allowed actions |
| Detective | AWS Config | Configuration drift | Behavioral anomalies |
| Behavioral | GuardDuty | Threat intelligence + ML anomaly | Known-good-but-malicious patterns |
| Correlation | SecurityHub | Cross-service signal aggregation | Context-aware investigation |

All four layers are deployed. None is optional.

### Account Vending — No Tickets Required
New product teams get a secure AWS account in <2 hours via the account vending pipeline in `terraform/organization/account_vending.tf`. The pipeline:
1. Accepts a JSON request (team name, OU target, cost center tag)
2. Creates the account via AWS Organizations
3. Applies baseline Terraform module (CloudTrail, Config, GuardDuty, SecurityHub)
4. Assigns permission sets via IAM Identity Center
5. Sends Slack notification to the team with account ID and SSO login URL

No human in the security team approves this. The controls are baked into the baseline — security-by-default, not security-by-review.

---

## How to Deploy

### Prerequisites
```bash
# Terraform >= 1.6
terraform -version

# AWS CLI with management account credentials
aws sts get-caller-identity

# You must be in the management account with OrganizationsFullAccess
```

### Step 1: Bootstrap State Backend
```bash
cd terraform/state-backend
terraform init
terraform apply
# This creates the S3 + DynamoDB backend used by all other modules
```

### Step 2: Create Organization Structure
```bash
cd terraform/organization
terraform init -backend-config=../state-backend/backend.hcl
terraform apply
```

### Step 3: Apply SCPs
```bash
cd terraform/scp
terraform init -backend-config=../state-backend/backend.hcl
terraform apply
```

### Step 4: Deploy Baseline to All Accounts
```bash
cd terraform/baseline
terraform init -backend-config=../state-backend/backend.hcl
terraform apply
```

### Step 5: Deploy Network Layer
```bash
cd terraform/network
terraform init -backend-config=../state-backend/backend.hcl
terraform apply
```

---

## Security Notes on This Repository

- **No credentials in code.** Provider authentication uses AWS SSO / OIDC.
- **State backend** uses S3 (KMS encrypted) + DynamoDB locking. See `terraform/state-backend/`.
- **All secrets** referenced via AWS Secrets Manager data sources — never in state values.
- **Module pinning** — all external modules pinned to specific git commit SHAs, not version tags.

---

## Portfolio Evidence Map

| Concept | Where it's demonstrated |
|---|---|
| Blast radius design | This README + `docs/blast-radius-design.md` |
| SCP composition | `terraform/scp/` — each control documented |
| Preventive vs detective trade-offs | `docs/control-design.md` |
| State file security | `terraform/state-backend/` |
| Account vending automation | `terraform/organization/account_vending.tf` |
| Incident postmortem | `docs/postmortem-state-exposure.md` |
| Threat model | `docs/threat-model.md` |
