# Carefloor Release Authority

Candidate-independent approval and promotion authority for BrainVI Carefloor.
The approval workflow verifies the caller attestation, every evidence digest, a
merged source PR, independent code review, and the actual workflow-dispatch actor
before signing an exact-run receipt. Promotion revalidates that receipt and the
staged deployment, then rolls the canonical alias back if convergence or receipt
persistence fails.

Both workflows currently use GitHub-hosted `ubuntu-latest` runners. Private-repo
minutes are therefore billable after the organization allowance. Moving them to
a dedicated self-hosted release runner removes GitHub minute charges, but also
requires replacing the current `--deny-self-hosted-runners` provenance policy
with an OIDC-bound, ephemeral runner trust policy; do not change only the label.
