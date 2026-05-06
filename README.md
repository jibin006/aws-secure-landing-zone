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
