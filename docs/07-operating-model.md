# Operating the controls — ownership, cadence, and how I would know they are working

Controls decay. The interesting question a year after this submission is not
whether the policies were correct on day one; it is whether anyone still trusts
them. This page is the part that decides that, and it is the part most take-home
submissions leave out.

## Who owns what

| artefact | owner | consulted | what "owning it" means |
|---|---|---|---|
| `policy/` (Kyverno + Rego + Semgrep) | Security Engineering | service teams | writes the rules, and owns the pain when a rule is wrong |
| `waivers/APPROVERS.yaml` | Security leads | risk committee | the only file that decides who may make an exception |
| `waivers/waivers.yaml` | service team requests, security approves | — | two names on every exception, enforced by CODEOWNERS *and* by the checker |
| `.github/workflows/` | Security Engineering | platform | the gate definitions; changing what blocks is a security review |
| `terraform/`, `k8s/` | Platform + service team | security | the resources themselves |
| `runtime/` rules and runbook | Security Engineering (on-call) | service team | the on-call who is woken owns the rule that wakes them — this is the rule that keeps detections honest |
| break-glass follow-up issues | Security on-call | service team | 72-hour SLA, blocks the next normal release |

The rule behind the table: **whoever is woken by a control owns it.** A detection
routed to a team that cannot change the rule becomes a rule nobody tunes and
everybody mutes.

## The four numbers I would put on a dashboard

Not "number of vulnerabilities". These four, because each one changes a decision:

1. **Waiver-to-fix ratio, per gate, per month.** Of the findings that blocked a
   merge, how many were resolved by fixing versus by waiving? Target under 1:4. If
   waivers outnumber fixes, the *threshold* is wrong, not the engineers — and the
   response is to change the gate, not to lecture. This is the single most
   informative number here.
2. **Median time from waiver creation to closure**, and the count of waivers
   renewed more than once. A waiver on its third renewal is not a waiver; it is a
   policy decision that has not been made. Those get escalated to the risk
   committee, by name, quarterly.
3. **Gate latency: median PR-to-green.** A security gate is also a tax on delivery.
   If it moves past ~10 minutes, teams start batching changes, batches are harder
   to review, and the review control degrades — a security cost, paid indirectly.
   This is why promoting SAST to blocking has a latency condition attached.
4. **Audit-mode violation count per policy, per namespace, with deploy volume
   alongside.** This is the promotion evidence in `docs/05-admission-rollout.md`.
   Violations alone are not enough: zero violations during a change freeze is not
   evidence of anything, so the deploy count is on the same chart.

Deliberately *not* on the dashboard: total open findings. It only ever goes up, it
is dominated by the unfixable backlog, and nobody has ever made a decision with it.

## Cadence

| when | what | who |
|---|---|---|
| every PR | the blocking gates | automated |
| nightly | full-history secret scan; re-scan of every *running* digest against the current CVE feed, because an image that was clean at build time is not clean forever | automated |
| weekly | new-finding triage; waivers expiring in the next 7 days | security on-call, 30 min |
| monthly | the four numbers above; audit-mode violation trend; promote or explain why not | security lead + platform |
| quarterly | approver-list review; access review on the log-archive account and the log groups; **rehearsal of the emergency credential rotation and one break-glass dry run** | security lead |
| per incident | runbook executed, then the runbook itself edited within 48h while it is fresh | responder |

The quarterly rehearsal is the one I would protect hardest if the calendar got
crowded. Rotation and break-glass are the two procedures that only ever run under
pressure, and an untested procedure is a document, not a control.

## How a policy changes

1. Rule change lands as a PR with a **failing fixture first** — the test that
   proves the rule catches the thing, added before the rule. Otherwise the rule
   ships already-passing and nobody knows whether it does anything.
2. Ship in `Audit`, cluster-wide, and in `Enforce` for `ns/accounts` only.
3. Watch the PolicyReport for the stated window with representative deploy volume.
4. Promote in a PR that a security lead reviews, quoting the violation count.
5. Every policy carries its mode and its promotion criteria in its own annotations,
   so the answer to "why is this only auditing?" is in the file, not in someone's
   memory.

## Failure modes I am watching for

* **Gate distrust.** Symptom: rising waiver-to-fix ratio, or engineers asking for
  break-glass on non-incidents. Response: cut the ruleset, not the gate.
* **Waiver sprawl.** Symptom: more than ~15 live waivers, or repeat renewals.
  Response: the ones being renewed are policy decisions; make them.
* **Detection rot.** Symptom: a Falco rule that has fired zero times in six months
  is either perfect or broken, and there is no way to tell from the outside.
  Response: quarterly synthetic trigger — deliberately read the credential file
  from a debug container in staging and confirm the page arrives. A detection that
  has never been proven to fire is a hypothesis.
* **Policy drift from reality.** Symptom: the exclusion list in a policy growing.
  Each exclusion is a line somebody had to write; when the list grows faster than
  the ruleset, the policy no longer describes the cluster.
