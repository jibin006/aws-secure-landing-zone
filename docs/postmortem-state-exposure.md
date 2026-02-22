# Postmortem: Terraform State Backend S3 Bucket Public Exposure

**Severity:** P1 — Critical  
**Duration:** 6 hours (14:00 – 20:00 IST)  
**Status:** Resolved  
**Author:** Jibin Benny  

---

## Summary

A Terraform S3 state backend bucket was inadvertently made publicly readable for approximately 6 hours due to a misconfigured `aws_s3_bucket_acl` resource applied to the wrong bucket. The error was introduced during a refactoring of the storage module and was not caught in code review. The exposure was detected by an AWS Config rule at 20:00 when the rule completed its periodic evaluation cycle. No confirmed external access to the state file was identified, however, due to the sensitivity of state file contents, full incident response procedures were executed.

---

## Timeline

| Time | Event |
|---|---|
| 13:45 | Developer begins refactoring S3 module in `storage/` |
| 14:00 | `terraform apply` executed locally. `acl = "public-read"` applied to state backend bucket instead of intended static assets bucket. Both buckets exist in same account with similar naming. |
| 14:02 | Change takes effect. State backend bucket becomes publicly readable. |
| 14:00–20:00 | **Exposure window.** State file containing infrastructure metadata publicly accessible via direct S3 URL. |
| 20:00 | AWS Config rule `s3-bucket-public-read-prohibited` completes periodic evaluation cycle. Fires non-compliant finding. SNS → email alert received by on-call engineer. |
| 20:08 | On-call engineer acknowledges alert. Begins investigation. |
| 20:12 | `aws s3api get-bucket-policy` and `aws s3api get-bucket-acl` confirm public read ACL on state bucket. CloudTrail queried to identify when the ACL was set and by which principal. |
| 20:15 | **Containment:** `aws s3api put-bucket-acl --bucket [name] --acl private` executed. Block Public Access re-enabled. |
| 20:18 | S3 server access logs pulled for the 6-hour exposure window. Analysis begins for external access. |
| 20:45 | S3 access logs show 3 GET requests from external IPs during exposure window. IPs queried against threat intelligence. No known-malicious IPs identified. All requests returned 403 (state file was not at root — path requires knowledge of key structure). |
| 21:00 | State file contents analyzed. Contains: VPC IDs, subnet IDs, security group IDs, IAM role ARNs. No plaintext credentials, passwords, or private keys in state outputs. |
| 21:30 | Rotation decision: No credentials to rotate (state contained no sensitive values). Resource IDs do not constitute credentials — attacker knowledge of a VPC ID does not grant access. |
| 22:00 | Incident closed. Postmortem initiated. |

---

## Root Cause Analysis

**Immediate cause:** Developer used a copy-paste pattern from an existing resource block and applied `acl = "public-read"` to the wrong S3 bucket resource. Terraform has two S3 resources with similar names in the same workspace.

**Contributing cause 1 — Detection latency:** AWS Config rule was configured for `PERIODIC` evaluation (6-hour cycle). A `CONFIGURATION_CHANGE` triggered rule would have fired within 60 seconds of the ACL change. This 6-hour detection gap is the most significant finding. The difference between 60-second detection and 6-hour detection is the difference between "we noticed immediately and fixed it" and "we had a 6-hour exposure window."

**Contributing cause 2 — Bucket naming:** The state backend bucket and the static assets bucket had similar names (`myorg-terraform-state-123456` vs `myorg-static-assets-123456`). Sufficiently distinct naming reduces the likelihood of this error.

**Contributing cause 3 — No pre-apply policy check:** The Terraform plan was not scanned by a policy-as-code tool (OPA/Conftest) before apply. A Conftest policy blocking `acl = "public-read"` or `acl = "public-read-write"` on any bucket in the management account would have caught this at plan time.

**Contributing cause 4 — No S3 Block Public Access at account level:** AWS provides an account-level S3 Block Public Access setting that overrides all bucket-level ACLs. This was not enabled on the management account. Had it been enabled, the ACL change would have been ignored entirely — the bucket would have remained private regardless of the resource configuration.

---

## Impact Assessment

**What was exposed:** Terraform state file containing infrastructure metadata (resource IDs, ARNs, network configuration). No credentials, passwords, database connection strings, or private keys.

**Who accessed it:** S3 server access logs show 3 GET requests from external IPs. All returned 403 (path was not guessed). No confirmed data exfiltration.

**Business impact:** No data breach. No service disruption. Reputational risk if this became public: moderate (infrastructure metadata of a state backend is sensitive but not critical-credential-level sensitive).

**Regulatory impact:** None identified. State file did not contain PII or regulated data.

---

## What Went Well

- S3 server access logs were enabled and available for forensic analysis. Without them, we would have had no visibility into whether the state file was accessed.
- The state file was designed with security in mind — no sensitive output values, no credential resources managed by Terraform. The blast radius of exposure was limited by good state hygiene.
- On-call response was fast once the alert fired — 7 minutes from alert to containment is acceptable.
- The incident response process was followed correctly. Evidence was preserved before remediation.

---

## What Went Wrong

- AWS Config rule was set to PERIODIC evaluation instead of CONFIGURATION_CHANGE. This is the highest-priority finding.
- No S3 Block Public Access at the account level — this is a free, zero-overhead control that would have made this incident impossible.
- No policy-as-code pre-apply checks in the Terraform workflow.
- Similar bucket naming made the mistake easy to make.
- No automated check in CI/CD that detects when the state backend bucket policy changes.

---

## Action Items

| Action | Owner | Priority | Due Date | Status |
|---|---|---|---|---|
| Change Config rule `s3-bucket-public-read-prohibited` to CONFIGURATION_CHANGE trigger | Cloud Security | P0 | Immediately | ✅ Done |
| Enable S3 Block Public Access at account level for all accounts | Cloud Security | P0 | Immediately | ✅ Done |
| Add Conftest policy blocking `public-read` ACLs on S3 resources | Platform Eng | P1 | 1 week | In Progress |
| Rename state backend bucket to distinguish clearly from workload buckets | Platform Eng | P2 | 2 weeks | Planned |
| Add CloudWatch alarm on state backend bucket policy/ACL changes | Cloud Security | P1 | 3 days | ✅ Done |
| Add Terraform workspace-level S3 resource inventory check in CI | Platform Eng | P2 | 2 weeks | Planned |
| Audit all Config rules for PERIODIC vs CHANGE_TRIGGERED evaluation | Cloud Security | P1 | 1 week | In Progress |

---

## Lessons Learned

**On detection:** PERIODIC Config rule evaluation creates a detection SLA that is incompatible with fast-moving threats. For any security control, ask: "What is the detection latency?" If the answer is "up to 6 hours," that's not a security control — that's an audit report. Security controls that matter operate in seconds to minutes.

**On prevention vs detection:** Account-level S3 Block Public Access is a free, zero-operational-burden preventive control. We chose not to enable it by default and relied on a detective control. The detective control failed to detect in time. The lesson: preventive controls should always be evaluated first. If a preventive control has no significant trade-off, it should be enabled by default. This one didn't.

**On state hygiene:** The limited blast radius of this incident was a direct result of good Terraform practices — no credentials in state, no sensitive outputs. Had we been managing database passwords or API keys directly in Terraform resources, this would have been a credential rotation incident across dozens of services. Terraform state hygiene is a security control, not just a best practice.

**On the attacker's perspective:** An attacker who accessed this state file got: VPC CIDRs, subnet IDs, security group IDs, IAM role ARNs. What can they do with that? They can skip the reconnaissance phase of an attack. They know exactly how the network is structured and which IAM roles exist. The blast radius wasn't zero — it was "we handed the attacker a blueprint they'd normally have to spend hours building." That's worth taking seriously even when no credentials were exposed.
