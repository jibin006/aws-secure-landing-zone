Q1.A — Blast radius if OIDC trust allows any branch on a Vertex AI training pipeline

If the sub condition is missing and the training pipeline uses OIDC to authenticate to GCP/AWS, any CI/CD workflow can now:

Read training data from the model artifact bucket

Write model artifacts (overwriting legitimate model weights)

Trigger training jobs with modified parameters

Access the training service account's credentials

The blast radius is not just credential theft. The blast radius includes model integrity. A tampered model trained on injected data can exfiltrate information through its outputs.

Q1.B — Minimum permission set for a model serving endpoint

Think through this:

What does a serving endpoint need to read? The model artifact from storage. That is storage.objects.get on the specific bucket/object path.

What does it need to write? Prediction logs. That is bigquery.tabledata.insertAll on the specific logging table.

What does it explicitly not need? IAM permissions. Service account management. Access to other model buckets. Access to training infrastructure.

Write the principle: the serving identity and the training identity are separate. The serving identity cannot overwrite model weights. The training identity cannot serve predictions. They share nothing.



**The problem:**

**"You discover that an S3 bucket containing Terraform state files has had its bucket policy changed to allow public read access. The change happened 6 hours ago. You do not know who made the change or why."**

The risk here is full environment compromise without detection because the Terraform state file exposes sensitive data and the complete infrastructure graph in a single artifact.
The attacker can extract specific values like RDS passwords, IAM role ARNs and trust relationships, KMS key IDs, VPC CIDRs, and security group mappings, giving them a precise blueprint to target resources directly.
Detection fails because the attacker downloads and analyzes the state file locally — not a single AWS CloudTrail event is generated until they begin exploitation.
The blast radius includes every account and environment referenced in the state, and if a shared backend with multiple workspaces is used, a single exposed S3 bucket can collapse isolation across dev, staging, and production simultaneously.
Fixing the bucket only stops further exposure, but the incident persists because all secrets, trust relationships, and infrastructure mappings in the state must be assumed compromised and already in the attacker’s possession.

First 10 Minutes (This is where you need precision)
1) Immediate containment (FIRST action)

I would immediately remove public access by:

Blocking public access at bucket level
Reverting the bucket policy

👉 Stop further exposure before investigation

2) Assume compromise

I would treat the state file as compromised and assume any sensitive data inside it is exposed.

3) Identify what was exposed

Not tools—thinking:

Does state contain:

access keys?

secrets?

RDS passwords?

IAM role ARNs?

👉 This defines severity

4) Check access patterns

I would check if the bucket was accessed anonymously during the exposure window.

Key signal:

Was data actually accessed or just exposed?
5) Identify source of change

I would determine who or what changed the bucket policy:

human user

CI/CD pipeline

compromised credential

6) Credential rotation (if needed)

If secrets are found in state:

rotate credentials immediately

invalidate tokens

reissue access

7) State integrity check

Verify Terraform state has not been altered or replaced


**The question:**

**"OIDC is not available in this environment. The GitHub OIDC endpoint is blocked by corporate proxy. You have 15 minutes. Walk me through exactly how you authenticate the CI/CD pipeline to AWS with zero static credentials."**



Initial Answer (before interruption)

The risk here is introducing a reusable credential into the CI/CD pipeline. Any static or semi-static credential—even if rotated—can be exfiltrated from the pipeline environment, logs, or intermediate systems and reused outside the intended execution context.

Given OIDC is not available, my goal is:

Eliminate reusable credentials and enforce short-lived, context-bound authentication


What I would do
I would authenticate the pipeline using ephemeral credentials generated at runtime, not pre-stored
The pipeline would request access dynamically from AWS using a trusted intermediary
That intermediary would:
Validate the pipeline identity (job, repo, environment)
Issue short-lived credentials via STS
Scope them strictly to that job

So the flow becomes:

Pipeline → trusted broker → AWS STS → temporary credentials → job executes

Key properties:


No credentials stored in GitHub

No reuse possible

Credentials expire automatically

Access tied to execution context

⏱️ Interruption — Pushback

“Why not just rotate the access keys every 24 hours?”

Response (under pressure)

Acknowledge

Rotation reduces the exposure window — that is correct.

Adapt

But it does not eliminate the credential class. A 24-hour window where credentials exist means any system that touches those credentials—CI/CD environment variables, logs, secret distribution layers—is now a viable exfiltration point. Once leaked, those credentials are valid from anywhere, completely breaking the intended trust boundary.

Trade-off

If I must operate without OIDC, I would move to a model where credentials are generated just-in-time and expire quickly—using a brokered STS flow backed by a secure system that issues credentials per job. The trade-off I accept is increased system complexity and dependency on that broker’s availability, instead of relying on static key rotation which is simpler but fundamentally less secure.
