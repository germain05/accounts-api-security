# Assumptions

The brief is deliberately generic. Where it left a gap I made a choice rather than
hedging, and every choice is here so a reviewer can substitute their own and see
what changes. Nothing below is load-bearing for the security reasoning — if an
assumption is wrong, the control moves, the argument does not.

## Identifiers

| thing | value used | note |
|---|---|---|
| GitHub org / repo | `example-bank/accounts-api` | deliberately neutral. Every OIDC condition, CODEOWNERS entry and cosign identity uses it consistently, so a global find-and-replace re-points the whole submission at a real org. |
| prod AWS account | `123456789012` | EKS, RDS, Secrets Manager, KMS, CloudTrail |
| build AWS account | `210987654321` | ECR only. Separate on purpose: compromising the build path yields an image, not a cluster. |
| log-archive account | `444455556666` | CloudTrail destination, Object Lock. Separate so a compromised prod principal cannot delete its own trail. |
| non-prod account | `555555555555` | referenced by waiver `SEC-2102` |
| region | `ap-south-1` | Mumbai. Chosen because the brief said so, and because it makes RBI data localisation a live obligation rather than a hypothetical one. |
| EKS cluster | `banking-shared-ap-south-1`, ~12 other services | the shared-tenancy premise drives the whole audit/enforce rollout design |
| KYC provider | `kyc.example-kyc.com`, HTTPS, one endpoint | the single permitted egress destination |
| event stream | MSK (`kafka-cluster:*` IAM actions), TLS listener 9094 | the brief says "a message stream"; MSK keeps it in the AWS IAM idiom. Kinesis or SQS would change three ARNs and nothing else. |
| ARNs, VPC endpoint ids, CIDRs, KMS key ids | placeholders, consistent across files | marked where they appear |

## Platform

* **EKS ≥ 1.27, containerd runtime.** This matters once: it is why the
  `/var/run/docker.sock` mount in the broken manifest is ranked third rather than
  first — on a containerd node that path does not exist. Said explicitly in
  `docs/04-findings.md` rather than quietly assumed.
* **IRSA is in use** (not EKS Pod Identity). Both work; IRSA is the wider install
  base. The trust-policy shape differs, the least-privilege argument does not.
* **Istio is installed**, or another mesh with an egress gateway. If not, the L7
  half of the egress control is unavailable and the honest position is that the
  NetworkPolicy alone cannot express an FQDN — stated in `docs/05-egress.md`.
* **Secrets Store CSI driver installed cluster-wide.** The section 6 delivery path
  depends on it; where it is not available, External Secrets Operator is the
  fallback and the manifest includes both, with the trade-off written down.
* **Kyverno, not Gatekeeper**, with the admission webhook at `failurePolicy: Fail`
  and 3 replicas. The availability consequence of that choice is argued in
  `docs/05-admission-rollout.md`.
* **Branch protection on `main`**: required CODEOWNERS review, required
  `security-gates / gate` status check, no force-push, no self-approval. This is a
  repository *setting*, not a file, so it cannot be proven from the repo — the
  CODEOWNERS file and the single `gate` job are the parts that live in Git.
* **GitHub Environment `production`** exists with required reviewers. Without it,
  the `:environment:production` claim is never minted and the deploy role cannot
  be assumed at all — the control fails closed.

## Scope boundaries — things I did not treat as mine

* The **application source** of `accounts-api`. The brief says to assume it exists
  and is broadly competent. `app/` is a minimal stand-in that exists for two
  reasons only: so the pipeline has something real to build, sign and attest, and
  so the "distroless, no shell, single binary" premise that the Falco rules depend
  on is a fact in this repo rather than an assertion.
* The **edge**: CloudFront, WAF rules, ALB listener configuration, rate limiting.
  Named in `docs/05-egress.md` as the control that would catch the authenticated
  bulk-read path I cannot otherwise see, and left out of scope.
* The **other twelve services** on the cluster. Their manifests are the reason the
  rollout is staged; I do not get to change them, which is the entire argument for
  audit mode.
* **Organisational controls**: hardware-backed commit signing, two-person review
  policy, the access-review process itself. Named in `DECISIONS.md` §6 because they
  are the real answer to blast-radius scenario (b), not because they are unimportant.

## What was actually executed, and what was not

**Executed, output committed in `test-output/`:** `kyverno test` (46 assertions
across 7 fixtures), `conftest verify` (33 unit tests), `conftest test` against the
shipped Terraform and all three fixtures, `terraform fmt -check` and
`terraform validate` against `terraform/`, the IAM policy-document schema check,
the waiver checker including real cosign signature verification, and a real
gitleaks scan of this repository's full history whose single finding was processed
through the waiver path end to end.

**Executed on GitHub if you push this repo:** `build-release.yml` builds the image,
generates the SBOM, keyless-signs it, attests the SBOM and verifies both — against
GHCR, with no AWS account and no secrets. That is a real green run, not a diagram.

**Not executed, and marked as such wherever it is claimed:** anything requiring an
AWS account. **No `terraform apply`**, no EKS cluster, no CloudTrail, no Secrets
Manager, no ECR, no Kyverno running in a real cluster.

`terraform init -backend=false` and `terraform validate` *were* run and both pass
(captured in `test-output/terraform-validate.txt`). `init` needs one network call
to the provider registry, which is the reason `conftest --parser hcl2` and not
`validate` is the **blocking** IaC gate: the merge decision should not depend on a
registry being reachable. They also answer different questions — `validate` checks
syntax and provider schema, `conftest` checks whether the database is public — so
both run and neither substitutes for the other.

One consequence worth stating plainly: because nothing was applied, the
**Kyverno signature-verification policy has never verified a real signature**, and
the ECR tag-immutability setting has never been exercised. Both are authored as
they would ship and both are honestly flagged — `verify-image-signature` carries
no assertion in the offline suite rather than a fabricated passing one, and the
GHCR downgrade is named in `DECISIONS.md`.
