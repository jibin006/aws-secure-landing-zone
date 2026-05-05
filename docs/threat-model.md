# Threat Model — AWS Secure Landing Zone

**Author:** Jibin Benny  
**Version:** 1.0  
**Scope:** Multi-account AWS Organization landing zone

---

## Methodology

Using STRIDE + MITRE ATT&CK Cloud matrix. For each threat:
- Attack path described step by step
- What architectural control stops or detects it
- Residual risk after controls are applied
- Detection latency

---

## Attack Path 1: Credential Compromise → Account Takeover

**Threat Actor:** External attacker who obtained an AWS access key from a GitHub commit or CI/CD log.

**Step-by-step:**
1. Attacker finds `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` in a public GitHub repo
2. Runs `aws sts get-caller-identity` — confirms credentials are valid
3. Calls `aws iam list-attached-role-policies` to enumerate privileges
4. Attempts to create a new IAM user with admin access for persistence
5. Tries to disable CloudTrail to blind detection
6. Exfiltrates data from S3 buckets

**Controls and their effectiveness:**

| Step | Control | Outcome |
|---|---|---|
| Step 4 | SCP: DENY-IAMUserCreation on production/staging | API call fails — no backdoor user created |
| Step 5 | SCP: DENY-CloudTrailModification | API call fails — audit trail preserved |
| Step 6 | S3 VPC Endpoint Policy (org-scoped) | Only accessible if calling from inside VPC via endpoint. External calls may succeed if S3 bucket is internet-accessible — **this is the residual risk** |
| All steps | CloudTrail metric filter: unauthorized API | Alert fires within 5 minutes |
| All steps | GuardDuty: UnauthorizedAccess:IAMUser findings | Finding within 2–5 minutes |

**Residual Risk:** S3 buckets that are accessible from the internet (public buckets, or buckets with broad bucket policies) can still be accessed with the compromised credentials from outside the VPC, bypassing the endpoint policy. Mitigation: S3 Block Public Access enabled at account level + Config rule enforcement.

**Detection Latency:** 2–5 minutes (GuardDuty near-real-time). CloudWatch alarm: <5 minutes.

---

## Attack Path 2: Insider Threat — Developer Abuses Sandbox Access

**Threat Actor:** Malicious or negligent internal developer with sandbox account access.

**Step-by-step:**
1. Developer has legitimate SSO access to sandbox-eng account
2. Attempts to access production data by assuming cross-account role
3. Attempts to create IAM user with long-lived credentials for persistence
4. Attempts to access resources in staging or production VPCs via network

**Controls and their effectiveness:**

| Step | Control | Outcome |
|---|---|---|
| Step 2 | No cross-account trust from sandbox to production IAM roles | `AssumeRole` call fails — no trust relationship exists |
| Step 3 | SCP: DENY-IAMUserCreation on production/staging (**not on sandbox**) | Can create IAM users in sandbox. This is a documented exception. |
| Step 4 | TGW route table segmentation | No routes between sandbox VPC and production/staging VPC |
| All | CloudTrail + GuardDuty | All API calls logged. Lateral movement attempts generate findings. |

**Residual Risk:** Developer can create IAM users and access keys within the sandbox account. This is accepted risk — sandbox has no production data, and the blast radius is contained to the sandbox account.  
**Gap to address:** Sandbox should still have alerting on IAM user creation even if not blocked. Config rule + SNS notification to security team.

**Detection Latency:** Cross-account role assumption attempts: logged immediately in CloudTrail. GuardDuty finding: 2–5 minutes.

---

## Attack Path 3: Supply Chain — Malicious Terraform Module

**Threat Actor:** Compromised public Terraform module executes attacker-controlled code during `terraform apply`.

**Step-by-step:**
1. Developer adds a public Terraform module pinned to a version tag (not a commit SHA)
2. Module author's account is compromised; attacker pushes malicious code to the version tag
3. On next `terraform plan/apply`, the malicious module executes with the CI/CD role's privileges
4. Malicious code creates a backdoor IAM role with trust to an external account
5. Malicious code exfiltrates Terraform state via HTTP to attacker's server

**Controls and their effectiveness:**

| Step | Control | Outcome |
|---|---|---|
| Step 2 | **Module pinning to commit SHA, not version tags** | Malicious update doesn't affect pinned SHA — **this is the primary control** |
| Step 4 | CloudTrail logs IAM role creation | Detected in CloudTrail, triggers IAM change alarm |
| Step 5 | VPC endpoint policy (org-scoped S3) | Exfil to external S3 blocked. HTTP exfil to arbitrary server via NAT Gateway is **not blocked** |
| Step 5 | NAT Gateway flow logs | HTTP exfil visible as outbound connection to new IP |

**Residual Risk:** If module is pinned to version tag instead of SHA, this attack succeeds. Operational control (code review process for module changes) is the backstop. Process controls fail; technical controls (SHA pinning) are more reliable.  
**Gap to address:** Automated check in CI/CD pipeline: reject any `terraform plan` that references a module source without a commit SHA. OPA/Conftest policy.

**Detection Latency for backdoor role creation:** CloudWatch alarm: <5 minutes. By then, malicious code has already run. Prevention (SHA pinning) is the correct control, not detection.

---

## Attack Path 4: Management Account Compromise

**Threat Actor:** Highly sophisticated attacker (nation-state level) who compromised a security engineer's workstation and extracted SSO session tokens.

**Step-by-step:**
1. Attacker extracts cached SSO credentials from engineer's workstation
2. Uses credentials to access the management account via SSO
3. Modifies SCPs to remove protections
4. Moves accounts out of protected OUs or removes org controls
5. Establishes persistence across all member accounts

**Controls and their effectiveness:**

| Step | Control | Outcome |
|---|---|---|
| Step 1 | MFA on SSO (IAM Identity Center) with hardware key | Attacker needs physical hardware key — significantly raises attack cost |
| Step 1 | Session duration limits (1-4 hours max) | Stolen session token expires quickly |
| Step 3–5 | CloudTrail on management account → log-archive | All actions logged before attacker can tamper |
| Step 3–5 | CloudWatch alarm: any management account API | P1 alert fires within 5 minutes |

**Residual Risk:** This is the existential threat. If the attacker has valid session credentials with MFA already satisfied, and the session hasn't expired, they have unrestricted access. Technical controls slow them down but don't stop them. The primary mitigations are: (1) access restriction — very few people have management account access, (2) session duration limits, (3) fast detection + response.

**Detection Latency:** <5 minutes from first API call. Response time determines blast radius. This is why you practice incident response drills — the playbook must be reflexive, not recalled under pressure.

---

## Control Coverage Matrix

| MITRE Technique | Technique ID | SCP | Config | GuardDuty | CloudTrail Alarm |
|---|---|---|---|---|---|
| Disable Cloud Logs | T1562.008 | ✅ Blocks | ✅ Detects | ✅ Detects | ✅ Alarms |
| Create Account | T1136.003 | ✅ Blocks IAM users | - | ✅ Detects | ✅ Alarms |
| Valid Accounts | T1078 | - | - | ✅ Detects anomalies | ✅ Alarms |
| Unused Regions | T1535 | ✅ Blocks | ✅ Detects | - | - |
| Exfiltration to Cloud | T1537 | ✅ Endpoint policy | - | ✅ Detects | ✅ Alarms |
| Account Manipulation | T1098 | ✅ Protects roles | ✅ Detects | ✅ Detects | ✅ Alarms |
