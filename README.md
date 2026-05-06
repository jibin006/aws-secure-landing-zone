
## OIDC Federation

1) The Risk I Was Solving

The core risk was that CI/CD pipelines relied on long-lived AWS access keys stored in GitHub secrets. These keys are reusable, can be exfiltrated, and are not strongly bound to workload identity. If compromised, they allow attackers to access AWS from anywhere with the same privilege, and rotation doesn’t eliminate the exposure window.

2) What I Built

I replaced secret-based authentication with identity-based federation using OIDC. Instead of storing credentials, I configured AWS to trust GitHub as an identity provider and created a role with a strict trust policy that validates signed OIDC tokens. Access is granted only if the token matches specific claims like repository, branch, and audience, and AWS issues short-lived credentials via STS.

3) What Broke

Initially, without strict conditions like the sub claim, the trust policy was too broad, meaning any GitHub workflow could attempt to assume the role. I also validated that workflows from non-authorized branches failed, confirming that access control was enforced at the identity layer rather than through secrets.

4) What I Fixed

I tightened the trust policy to enforce least privilege at the identity level—restricting access to a specific repository and branch. This ensured that only intended workloads could assume the role, eliminating the possibility of token misuse from other contexts.

5) The Trade-off I Accepted

I accepted increased dependency on GitHub’s security and availability, since AWS now trusts GitHub-issued tokens. Additionally, the setup is more complex than static keys and requires careful policy design. However, this trade-off is justified because it removes long-lived credentials and enforces short-lived, identity-bound access with significantly reduced blast radius.
