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

The Risk

The risk here is that Terraform state files may contain sensitive data such as access keys, IAM role ARNs, database credentials, and infrastructure configuration. Public read access means this data could have been exposed to anyone on the internet for the past 6 hours, enabling attackers to gain unauthorized access and potentially escalate privileges.

The Blast Radius

The blast radius includes any infrastructure managed by that Terraform state. If credentials or role references are exposed, an attacker could:

Assume roles
Access cloud resources
Modify infrastructure indirectly
Pivot into other services

Additionally, even without credentials, the state file reveals the full architecture, which increases the attack surface.

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
