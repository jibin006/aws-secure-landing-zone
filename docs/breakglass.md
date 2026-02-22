# Break-Glass Runbook — Management Account Emergency Access

**Classification:** Restricted  
**Use when:** Normal SSO access is unavailable AND a security incident requires management account access  
**Authorization required:** 2 of 3 designated security leads must approve (documented in access management system)

---

## When to Use This Runbook

- SSO identity provider is unavailable (IdP outage)
- Active incident requiring management account access when SSO is compromised
- Account lockout due to misconfigured SCP that blocks SSO service

**Do NOT use for:** Routine operations, convenience, avoiding the normal SSO process.

---

## Break-Glass Procedure

### Step 1: Authorization
Contact 2 of 3 designated approvers. Document in incident ticket:
- Reason for break-glass access
- Approver names and timestamps
- Expected duration of access

### Step 2: Retrieve Break-Glass Credentials
Break-glass credentials are stored in:
- AWS Secrets Manager: `arn:aws:secretsmanager:ap-south-1:MGMT_ACCOUNT_ID:secret:break-glass/mgmt-admin`
- Access requires: Hardware MFA token + knowledge of Secrets Manager ARN
- Credentials are rotated automatically every 90 days

### Step 3: Access the Management Account
```bash
# Use break-glass profile — configured with long-lived credentials stored offline
aws sts get-caller-identity --profile break-glass-mgmt

# Immediately enable CloudTrail alert suppression exception
# (The alert will fire — this is intentional. Notify on-call before proceeding.)
```

### Step 4: Notify Security Team
**Before any action**, send notification to #security-incidents Slack channel:
```
Break-glass access invoked for management account
Incident: [TICKET-NUMBER]
Approvers: [Names]
Start time: [Timestamp]
Expected duration: [Duration]
Reason: [Brief description]
```

### Step 5: Minimum Necessary Actions
Perform only the actions required to resolve the incident. Document every command executed.

### Step 6: Revoke Access
```bash
# Immediately after completing the required actions:
# 1. Log out of the break-glass session
# 2. Rotate the break-glass credentials
aws secretsmanager rotate-secret \
  --secret-id break-glass/mgmt-admin \
  --profile break-glass-mgmt
```

### Step 7: Post-Incident Documentation
Within 24 hours, file a detailed report:
- Every API call made during break-glass session (pull from CloudTrail)
- Duration of access
- Actions taken and their justification
- Any findings from the session

---

## CloudTrail Alert During Break-Glass

When break-glass access is used, the CloudWatch alarm `SecurityBaseline-root_usage` or an equivalent management account alarm **will fire**. This is expected and correct behavior.

**Do not suppress the alarm.** The alarm firing is the audit trail that this access occurred. The on-call engineer receiving the alert should:
1. Check Slack for the break-glass notification (sent in Step 4)
2. Confirm the incident ticket exists
3. Monitor CloudTrail for the duration of the session
4. Document the alarm as "expected — break-glass in use" in the alert triage system

---

## Contacts

| Role | Name | Contact |
|---|---|---|
| Security Lead 1 | [Name] | [Contact] |
| Security Lead 2 | [Name] | [Contact] |
| Security Lead 3 | [Name] | [Contact] |
| On-call Security | PagerDuty | #security-oncall |
