Q1.A — Blast radius if OIDC trust allows any branch on a Vertex AI training pipeline

Write this out. If the sub condition is missing and the training pipeline uses OIDC to authenticate to GCP/AWS, any CI/CD workflow can now:

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
