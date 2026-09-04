# Section 5 — admission policy, and the rollout problem

A cluster shared with a dozen other teams is a rollout problem as much as a policy
problem. The policy that is technically correct and breaks four other teams on a
Tuesday gets the admission controller uninstalled, and then the correct policy
protects nothing. So every policy carries its day-one mode and its promotion
criteria **in its own annotations**, next to the rule, not in a wiki page nobody
opens.

## Day-one posture

| policy | day one | scope | what triggers promotion |
|---|---|---|---|
| `disallow-host-namespaces` | **Enforce** | cluster (minus 5 infra namespaces) | already promoted. 14-day dry-run found 2 violations, both in `kube-system`. This one is non-negotiable because it is load-bearing for every NetworkPolicy in the cluster. |
| `disallow-hostpath` | **Enforce** | cluster (minus infra) | already promoted. Same dry-run: violations only in CSI/CNI daemonsets, excluded by **namespace** rather than by path — a path allowlist is a bypass waiting to be found. |
| `restrict-rbac-wildcards` | **Enforce** | cluster (minus named operator ClusterRoles) | already promoted. 4 violations, all Helm-installed operator ClusterRoles, each excluded by name — and each name is a line somebody had to write and review. |
| `restrict-privileged-rolebindings` | **Enforce** | cluster (minus infra + one named break-glass binding) | already promoted, and it ships *with* `restrict-rbac-wildcards` rather than after it. Reason: the wildcard policy audits the Role and says nothing about the RoleBinding, so a tenant who cannot write `verbs: ["*"]` can still bind their ServiceAccount to the `cluster-admin` ClusterRole that Kubernetes ships. Landing the first policy without the second would have published the bypass. |
| `restrict-registries` | **Enforce** | cluster | already promoted. The allowlist was derived from a 30-day inventory of every image reference actually running, so it was empirically complete *before* it was enforced. That order — enumerate reality, then enforce the enumeration — is the pattern for every promotion below. |
| `require-restricted-securitycontext` | **Audit** cluster-wide, **Enforce** in `ns/accounts` | | 14 consecutive days of zero PolicyReport failures + acknowledgement from each of the 12 service owners + the two known offenders (a legacy JVM in `ns/payments` needing `CAP_NET_BIND_SERVICE`, a vendor OTel collector running as root) migrated or holding a namespace-scoped exception PR. Target 4 weeks. |
| `require-image-digest` | **Audit** cluster-wide, **Enforce** in `ns/accounts` | | every team's CD tooling must resolve tags at build time rather than apply time. Argo image-updater and Flux do; hand-rolled `kubectl` pipelines mostly do not. Evidence: 14 days zero failures **per namespace**, promoted namespace by namespace. |
| `verify-image-signature` | **Audit** cluster-wide, **Enforce** in `ns/accounts` | | 30 days of Audit showing 100% of admitted images in a namespace carry a verifiable signature. Promoted one namespace at a time — a single cluster-wide flip would break twelve teams at once, and the resulting incident review would end with the policy removed, which is a worse outcome than an unsigned image. |
| `disallow-secrets-as-env` | **Audit** cluster-wide, **Enforce** in `ns/accounts` | | longest runway: `envFrom: secretRef` is in 14 of ~40 workloads and fixing it is an *application* change (read a file, re-read on change), not a manifest change. Needs the CSI driver installed cluster-wide and a published migration recipe first. Estimated two quarters. |
| `restrict-ephemeral-containers` | **Enforce** | cluster (minus infra) | already enforced, with no audit period, and it is the one row here where that is the *conservative* choice. The policy can only fire on `kubectl debug` — an interactive action with a human at a terminal reading the rejection. It cannot fail somebody's deploy at 3am, which is the entire reason the rows below get a grace period. |
| `mutate-safe-defaults` | **Enforce (mutate)** | cluster (minus infra; requests rule also skips `ns/accounts`) | not a gate and never promoted to one. It is the instrument that makes the four Audit rows promotable — see "Why a mutate policy" below. |
| `require-resource-limits` | **Audit** | cluster | deliberately not promoted early. This is a tenancy control, not a security control, and I am not spending enforcement credibility on it. A per-namespace `LimitRange` with defaults is the better fix and makes the policy nearly redundant. |

**The pattern.** I enforce in `ns/accounts` — the namespace I own — on day one for
every policy, including the ones that are cluster-wide Audit. That is not just
tidiness: it is the evidence I take to the other twelve teams. "We have run this
in enforce for six weeks on the service that holds the customer ledger, here is
the incident count (zero) and here is the migration diff" is an argument. "Policy
says so" is not, and platform teams that lead with the second one get their
webhooks removed.

**What counts as evidence to promote**, generally: a Kyverno `PolicyReport` with
zero failures for the stated window, across the namespaces in scope, *with*
representative deploy traffic in that window — a quiet fortnight over the December
freeze is not evidence. I check the second condition by counting admission
requests in the same period, not just failures.

## Failure mode I designed around

Kyverno's webhook is in the admission path. If it is unavailable and
`failurePolicy: Fail`, nothing deploys cluster-wide, including the fix for
whatever broke Kyverno. If it is `Ignore`, an attacker who can crash the webhook
has disabled every policy here.

I ship `failurePolicy: Fail` for the `Enforce` policies with the webhook running 3
replicas across zones and a PodDisruptionBudget, and I accept the availability
risk — because `Ignore` turns "the admission controller is down" into a silent
security event, and the whole point of section 5 is to not have silent security
events. The compensating control for the availability side is that
`disallow-host-namespaces` and friends are also checked in CI (`conftest` against
the rendered manifests), so the common case — a bad manifest — is caught before it
ever reaches the cluster, and the webhook is the backstop rather than the only gate.

## Running the tests

```
kyverno test policy/kyverno/tests          # 46 assertions, seven fixtures
./scripts/run-policy-tests.sh              # the above plus conftest + waivers
```

Captured output is in [`../test-output/`](../test-output).

`verify-image-signature` is **not** in the `kyverno test` suite. The CLI cannot
verify a Sigstore signature without registry and Rekor access, and a fixture that
asserts `pass` for it would be a lie in a file whose entire job is to be
trustworthy. It is exercised by `./scripts/run-policy-tests.sh --integration`,
which needs a kind cluster and network.

## Three blind spots I went looking for, and closed

Writing the policies was the easy half. These are the three places where the rule set
*looked* complete and was not, both found by trying to defeat it rather than by
reading it — which is why `bypass-workload.yaml` exists as a first-class fixture.

* **`initContainers`.** Kyverno's autogen rewrites `spec.containers` for
  controllers, so a rule written against `containers` reads correctly and never
  looks at `initContainers`. A privileged init step that drops a setuid binary into
  a shared `emptyDir` and exits is admitted, and it has finished its work before
  the main container starts. Closed by `init-containers-restricted`, with the
  bypass fixture carrying exactly that shape.
* **`RoleBinding`.** Covered above; the short version is that the wildcard lives in
  a ClusterRole Kubernetes ships, so a policy that only inspects Roles can be
  satisfied without giving up any privilege at all.
* **`ephemeralContainers`.** The one I missed first time round and found by
  re-reading my own rule set asking "what is a container that is in neither list".
  `kubectl debug -n accounts <pod> --image=alpine --target=api --profile=sysadmin`
  does not create a Pod — it UPDATEs the `pods/ephemeralcontainers` subresource of
  a pod that was admitted days ago and is never re-evaluated. The new container
  lands in `spec.ephemeralContainers`, a third list that no rule here inspected,
  and with `--target` it joins the target's process namespace: it can read
  `/proc/1/environ` and the DB credential mounted at `/var/run/secrets/db`. Every
  control in section 4a was intact and the attacker had a root shell beside the
  workload. Closed by `restrict-ephemeral-containers`, which matches both `Pod`
  and `Pod/ephemeralcontainers`.

All three are now assertions in the suite, so they cannot silently regress.

### A fourth thing, which was a bug rather than a blind spot

`init-containers-restricted` was **rejecting compliant initContainers**. The rule
asked whether privilege escalation was allowed as:

```
{{ element.securityContext.allowPrivilegeEscalation || `true` }} == true
```

JMESPath treats `false` as a falsy value, so an explicit
`allowPrivilegeEscalation: false` — exactly what the policy demands — evaluated to
`true` and was denied. The `|| \`true\`` was there to catch the *absent* case and
silently caught the compliant case too.

This is worth more than the two blind spots above, because of who it hurts. A hole
lets a bad workload through; a false positive fires on the team that did what you
asked. On a cluster shared with twelve other teams, a handful of those is all it
takes for the platform team to be asked to remove the admission controller — and
then the correct policy protects nothing. It is the failure mode `DECISIONS.md` §2
is written around, and my own rule set had it.

Two changes came out of it. The condition now uses `to_string()`, which does not
route through truthiness (`absent -> "null"`, `false -> "false"`, `true -> "true"`).
And `compliant-initcontainer.yaml` is a permanent positive fixture: the suite had
a broken manifest and a fixed one and a bypass attempt, all of which the rule
handled correctly, and **no negative fixture can catch a false positive**. Only a
compliant fixture that must be ADMITTED can.

## Why a mutate policy, when mutation is not enforcement

The rollout table above has four policies sitting in Audit with a promotion date.
The honest risk with that plan is that it is a plan to stay in Audit forever: audit
mode produces a report nobody is paged for, so on day 15 the violation count is not
zero, the promotion slips, and a year later the policy is still advisory.

`mutate-safe-defaults` is what breaks that. For most workloads the missing fields
are missing because nobody thought about them, not because the workload needs the
permission. Defaulting those in does three things: it shrinks the audit-mode
violation list to the workloads that *genuinely* conflict — a list short enough to
hold a conversation about; it makes the eventual flip to Enforce a no-op for
everyone already being mutated; and it fixes workloads rather than reporting them.

**What it deliberately does not do.** Every rule steps aside for an explicitly-set
value. A team that writes `allowPrivilegeEscalation: true` keeps it, and
`require-restricted-securitycontext` rejects them for it. Silently reversing a
stated intent would produce a workload that does not do what its manifest says,
which is a worse outcome than a rejection and much harder to debug. So mutation
buys the rollout; validation is still the control, and the Audit rows above still
have to be promoted. `kyverno-test.yaml` asserts both halves — the unhardened pod
is mutated (with the patched output pinned exactly), and the deliberately
privileged one is skipped.

The `pod-policies.kyverno.io/autogen-controllers: none` annotation matters here:
mutating the Deployment rather than the Pod writes the change into the object Argo
or Helm owns, and the next sync diffs against it forever. Mutating the Pod leaves
the controller's spec untouched.

