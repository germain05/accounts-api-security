# Traceability — every artefact back to a named threat

`T1`–`T5` are defined in [`THREAT-MODEL.md`](THREAT-MODEL.md).

| artefact | threat | what it does |
|---|---|---|
| `iam/github-oidc-trust-policy.json` | T1 | pins `sub` to one repo, one branch, one environment; denies fork/PR/tag-triggered assumption |
| `.github/workflows/build-release.yml` — SHA-pinned actions, `permissions` least-privilege | T1 | removes the tag-mutation and compromised-action path into the deploy role |
| `.github/workflows/build-release.yml` — cosign sign + verify | T4 | binds the artefact to the workflow identity that produced it |
| `.github/workflows/build-release.yml` — syft SBOM as attestation | T4 | inventory travels with the artefact, survives the 90-day log retention |
| `terraform/ecr.tf` — `image_tag_mutability = IMMUTABLE`, registry policy | T4 | a pushed tag cannot be re-pointed |
| `policy/kyverno/policies/require-image-digest.yaml` | T4 | no `:latest`, no floating tags admitted |
| `policy/kyverno/policies/verify-image-signature.yaml` | T4 | unsigned or foreign-built images rejected at admission |
| `.github/workflows/security-gates.yml` — Trivy SCA | T4 | known-vulnerable dependencies blocked at the defined threshold |
| `.github/workflows/security-gates.yml` — Semgrep SAST | T2 | injection/deserialisation classes that give the attacker step 1 |
| `.github/workflows/security-gates.yml` — Gitleaks **full history** | T1, T3 | a leaked long-lived AWS key or DB password is the cheapest path to both |
| `.github/workflows/security-gates.yml` — conftest/Checkov IaC | T3 | public DB, unencrypted storage, open SG blocked pre-merge |
| `waivers/waivers.yaml` + `scripts/waiver_check.py` | (meta) | keeps the gates above alive; an unwaivable gate is a disabled gate |
| `docs/03-break-glass.md` | (meta) | the one bypass, time-boxed and audited, so nobody invents an unaudited one |
| `remediate/workload-fixed.yaml` | T2 | removes docker.sock, hostNetwork, root, RBAC wildcards |
| `policy/kyverno/policies/*` (11 policies) | T2, T4 | structural prevention of the same manifest being reintroduced |
| `policy/kyverno/policies/restrict-privileged-rolebindings.yaml` | T2 | closes the second-order bypass the RBAC fix creates: binding to the `cluster-admin` ClusterRole needs no wildcard of your own |
| `policy/kyverno/policies/restrict-ephemeral-containers.yaml` | T2 | closes the `kubectl debug` bypass: an ephemeral container is in neither `containers[]` nor `initContainers[]` and arrives via the `pods/ephemeralcontainers` subresource, so every other policy here was blind to it. Found in review, not in the brief |
| `policy/kyverno/policies/mutate-safe-defaults.yaml` | T2 (rollout) | defaults the baseline in for the other twelve teams so the promotion of `require-restricted-securitycontext` to Enforce is a no-op rather than an incident. Mutation is not enforcement — the policy says so in its own comments |
| `policy/kyverno/tests/resources/compliant-initcontainer.yaml` | T2 (regression) | a *compliant* initContainer that must be ADMITTED. Added after review found the rule denying it — the JMESPath `false \|\| true` trap. Negative fixtures cannot catch a false positive |
| `scripts/check_iam_policies.py` | T1, T2 (meta) | asserts every document in `iam/` is one AWS would actually accept. A policy that fails to apply reviews as a control and is not one |
| `policy/kyverno/tests/resources/bypass-workload.yaml` | T2, T4 | proves the rules resist someone who has read the rule names, not just the broken manifest |
| `policy/fixtures/terraform/evasion/` | T3 | proves the IaC rules survive `var`-driven values, `dynamic` blocks, IPv6 and Aurora — the shapes that defeat a naive rule set |
| `iam/external-secrets-policy.json` | T2 | keeps the secrets operator's breadth out of the workload's identity |
| `policy/rego/terraform.rego` | T3 | structural prevention of the same RDS/CloudTrail/SG being reintroduced |
| `iam/pod-identity-policy.json` | T2 | replaces `NotAction: *` with three scoped statements |
| `k8s/networkpolicy-egress.yaml` + `k8s/istio-egress.yaml` | T5, T2 | default-deny egress, one permitted KYC FQDN |
| `runtime/falco-rules.yaml` | T2, T5 | detects the credential-read and the unexpected-egress steps |
| `runtime/runbook-accounts-api.md` | T2, T5 | gives the detection an owner and a first 15 minutes |
| `k8s/externalsecret.yaml` | T3 | no plaintext credential in Git or in a committed manifest |
| `docs/06-secrets-rotation.md` | T3 | bounds the useful life of a stolen credential; emergency path measured in minutes |
| `docs/06-log-redaction.md` | T5 | the leak that needs no exploit |
| `terraform/cloudtrail.tf` | (evidence for all) | the only reason any of the above is provable after the fact |
| `ASSUMPTIONS.md` | (all) | states what would have to be different for any of the above to be wrong |
| `docs/07-operating-model.md` | (all) | the controls above decay without ownership, cadence and measurement; this is what keeps them true in month twelve |

**Built without a matching threat, deliberately:** `.github/dependabot.yml` (hygiene, keeps the T4 gate's false-positive load low rather than mitigating a threat directly) and `terraform/kms.tf` CMKs (the confidentiality threat they address — AWS operator access to disk — is not in my top five; they are here because a bank's examiner asks for key custody, which is a regulatory obligation rather than a threat. Stated as such in `DECISIONS.md` §5).
