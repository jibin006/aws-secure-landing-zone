**What this build solves:** IAM vending machines eliminate the gap between role creation 
and boundary enforcement — developers can create roles without being able to escalate 
privileges beyond the boundary cap.

**The decision I made:** Permission boundaries enforced at creation time via Lambda vending 
machine, with an explicit deny on boundary removal in the boundary policy itself.

**What I explicitly rejected:** Manual boundary attachment after role creation — the window 
between creation and boundary application is an exploitable gap.

**The trade-off I accepted:** All developer roles are capped at the boundary regardless of 
job requirements — boundary exceptions require a vending machine code change, not 
self-service.

**The Anthropic clause:** For LLM training pipelines, the same boundary pattern applies but 
the boundary must explicitly deny access to model artifact storage for roles not tagged 
workload=training — a compromised CI identity with broad S3 access can overwrite model 
weights.



## Architecture

[ASCII or diagram — every component, trust boundary, data flow]

Management Account
  └── IAM Vending Machine Lambda (role: vending-machine-executor)
       ├── Creates roles with permission boundary enforced
       └── Tags every created role: CreatedBy=iam-vending-machine

Workload Accounts
  └── Created roles (bounded by developer-boundary policy)
       ├── Can perform: S3, Lambda, CloudWatch operations
       └── Cannot perform: IAM boundary removal, privilege escalation

CI/CD Pipeline (GitHub Actions)
  └── OIDC Federation → AWS Role (scoped to repo:branch)
       └── No static credentials at any point in chain

## Security Decisions (Detailed)

Decision 1: OIDC over rotated access keys
- OIDC eliminates the credential class entirely for CI/CD
- Rotated keys reduce the window but do not eliminate the exposure surface
- Rejected: Secrets Manager with rotation — still a credential that exists at rest

Decision 2: Boundary denial embedded in the boundary policy itself
- Self-referential deny on iam:DeleteRolePermissionsBoundary
- This means even a role with AdministratorAccess attached cannot remove its own boundary
- Rejected: SCP-only enforcement — SCPs are account-wide and do not survive role movement

## What Broke During Development

Entry 1: OIDC sub condition removal
- What broke: Any GitHub Actions workflow in any repo could assume the role
- Root cause: aud condition verifies the token source (GitHub), sub condition scopes it to a 
  specific repo and branch. Without sub, all GitHub tokens pass.
- Fix: Restored sub condition with exact repo:branch format
- Monitoring: EventBridge on iam:UpdateAssumeRolePolicy for this specific role

Entry 2: Cross-account trust without external ID  
- What broke: Any service in Account A can assume the role in Account B
- Root cause: Trust policy trusts the account, not a specific principal. Confused deputy 
  means any service operating within that account — including compromised ones — can assume 
  the role.
- Fix: Added external ID condition to trust policy
- Monitoring: CloudTrail on sts:AssumeRole calls without expected external ID

Entry 3: Vending machine Lambda over-permissioned initially
- What broke: Lambda had iam:* which includes iam:CreatePolicyVersion — it could escalate 
  its own privileges
- Root cause: Copy-pasted broad IAM permissions during initial setup without scoping
- Fix: Scoped to iam:CreateRole, iam:TagRole, iam:PutRolePermissionsBoundary only
- Monitoring: CloudTrail on any IAM action by the vending machine Lambda beyond these three

## What I Would Do Differently at Scale

At 50 accounts and 5,000 roles:
- The current Lambda invocation model does not scale — need an SQS queue in front
- Permission boundary versioning becomes a problem — updating the boundary policy affects 
  all existing roles simultaneously
- The external ID for cross-account assumption needs to be account-pair-specific, not shared

## Attack Paths Tested

Attack 1: OIDC without sub condition
- What succeeded: Any repo's workflow assumed the role
- What caught it: Manual verification (no automated detection yet)
- Residual risk: Trust policy drift — EventBridge monitoring added

Attack 2: Boundary removal attempt
- What succeeded: Nothing — boundary removal was denied
- What caught it: IAM policy evaluation
- Residual risk: Boundary policy itself could be modified by an admin — SCP needed

Attack 3: PassRole escalation via cross-account role
- What succeeded: Full escalation path documented (PassRole + RunInstances = EC2 with role)
- What caught it: Nothing — this was the intentional gap
- Fix applied: Removed PassRole from Account A principal
- Residual risk: Other principals in Account A may still have PassRole — needs periodic audit
