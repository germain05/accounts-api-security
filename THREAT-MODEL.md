# Threat model — `accounts-api`

Scope: the container, its pipeline, the identities it assumes, the data it holds. Every control in sections 2–6 carries a `T#` tag back to this page; the full map is [`TRACEABILITY.md`](TRACEABILITY.md).

```text
    INTERNET (untrusted)                      GITHUB (untrusted control plane)
  customers   KYC provider   attacker            source + Actions runners
      │ B1 TLS    ▲ B4          ╎ B4 exfil          │ B5  OIDC AssumeRole, no static keys
      ▼           │             ╎                   ├────────────────────┐
┌─ AWS PROD 123456789012 · ap-south-1 ───────────┐   │  ┌─ AWS BUILD 210987654321 ─┐
│  CloudFront + WAF ──► ALB ──B2──┐              │   └─►│  ECR  accounts-api        │
│  ┌─ shared EKS · 12 other teams' services ───┐ │      └────────┬──────────────────┘
│  │   ns/accounts: accounts-api ×3  ◄──B8──►  │ │◄─ B6 digest + ┘ cosign verify
│  │   ▲ MSK events   │ B3        │ B7  ns/*   │ │
│  └───────────────── │ ───────── │ ───────────┘ │
│      RDS postgres ◄─┘           └─► Secrets Manager + KMS
│      name,email,phone,IBAN,balance,last4    CloudTrail / GuardDuty
└────────────────────────────────────────────────┘
```

**B1** internet→edge · **B2** edge→workload, plaintext inside the VPC · **B3** workload→data, credential from Secrets Manager · **B4** workload→internet, only `kyc.example-kyc.com:443` is legitimate · **B5** GitHub→AWS, federated OIDC · **B6** registry→cluster, digest + signature · **B7** pod→AWS APIs, IRSA · **B8** namespace→namespace, RBAC + NetworkPolicy + shared node kernel.

## Top five, ranked by probability × reach

| # | threat | entry | reaches | control here |
|---|---|---|---|---|
| **T1** | **CI/CD identity abuse** — poisoned Action, `pull_request_target`, or maintainer takeover assumes the deploy role | B5 | ECR push and `kubectl apply` in prod. Beats every runtime control because it *is* the deploy path | `sub` pinned to `:environment:production` **and** `job_workflow_ref`; `aud` asserted; actions SHA-pinned; `permissions: {}`; no `pull_request_target` |
| **T2** | **Pod identity over-permission → lateral movement** — RCE/SSRF here or in any co-tenant, then use of its AWS role and RBAC | B2→B7/B8 | IAM `NotAction` on `*` ≈ account takeover; RBAC `*` on `secrets`; docker.sock = node root = every other team's pods | least-privilege pod policy; namespaced RBAC, no wildcards, no API token mounted; Kyverno on hostPath, host namespaces, root, escalation, debug containers |
| **T3** | **Direct database exposure** — public RDS, `0.0.0.0/0:5432`, unencrypted, static password | B3, bypassing B1–B2 | the whole dataset with no application exploit; scanners find this in hours | fixed Terraform, and Rego rules that fail the plan on recurrence — tested against an evasion fixture |
| **T4** | **Unsigned or mutable artefact** — `:latest`, no signature, no SBOM | B6 | registry write changes what runs in prod without touching Git → immediately T2 | tag immutability; deploy by digest; keyless cosign bound to the workflow identity; SBOM attestation; Kyverno `verifyImages` |
| **T5** | **PII leaking via logs and egress** — the service logs request context and may egress anywhere | B4 + logs | bulk IBAN and PII, no exploit needed. Under RBI localisation, a residency incident too | allowlist log serialiser + Fluent Bit redaction, residual leaks named; default-deny egress + Istio gateway pinning the one KYC FQDN |

**Accepted, not controlled.** *KYC provider breach* — we control what we send, not their security; compensating: field minimisation and a contractual notification SLA, noted not built. *Insider with cluster-admin* — detective only: CloudTrail and EKS audit to a separate log-archive account under an SCP denying `s3:DeleteObject`, plus CODEOWNERS review. Prevention needs break-glass-only admin with session recording; deprioritised.

## The threat I think is overrated here

**Container escape via a kernel 0-day.** On managed EKS it is the *second* step of a chain whose first step is RCE — and RCE already yields the pod's AWS identity and the database credential, which is the entire dataset. Escape adds the other teams' workloads; it does not add *this* service's data. So the budget goes to scoping the identity and the egress, which devalue both steps, not to gVisor/Kata, which addresses only the second and costs a cluster-wide migration across twelve teams. **I would rather make RCE worth little than make escape hard.** Accepted consequence: a co-tenant's escape reaches my node — cheaply mitigated, since the fixed manifest drops `hostPath`, `hostNetwork` and root, and the Falco rule fires on escape primitives rather than the exploit.
