# Waivers — lifecycle

A gate with no waiver path gets disabled within a month. This is the waiver path.

## Shape

* **In-repo.** `waivers/waivers.yaml`. A waiver is a pull request, so it gets code review, CODEOWNERS enforcement, and a permanent, blame-able history. No web UI, no ticket-system side channel, no `# nosec` comment scattered through the source.
* **Signed.** The approver signs the *canonical body* of the waiver (`scripts/sign_waiver.py`), not the YAML text. The signature covers `expires`, `scope` and `severity`, so those cannot be edited after approval. `waivers/fixtures/tampered.yaml` is a committed proof: extending `expires` by two days invalidates it and fails the gate.
* **Expiring.** Every waiver has a hard `expires`, capped by severity: **CRITICAL 14d · HIGH 30d · MEDIUM 90d · LOW 180d.** There is no "permanent" option.
* **Fails closed on lapse.** This is the part that matters. `.trivyignore`, `.gitleaks.toml`, `.semgrepignore` and `policy/rego/data.waivers.json` are `.gitignore`'d and *generated* from active waivers at pipeline time. So an expired waiver does two things at once: the `waiver-integrity` job fails the build with a named error, **and** the finding stops being suppressed. There is no state in which an expired waiver quietly keeps working.

## Who approves

`waivers/APPROVERS.yaml`, itself CODEOWNERS-gated to `@example-bank/security-leads`.

| severity | approver | also required |
|---|---|---|
| LOW / MEDIUM | Security Engineering lead | — |
| HIGH | Security Engineering lead | linked SEC ticket with a remediation date |
| CRITICAL | Head of Platform Security | — |
| any, `class: accepted-risk` | an approver with `may_accept_risk: true` | risk-committee minute referenced in the ticket |

`requested_by == approved_by` is a hard failure. The `identity` in `APPROVERS.yaml` is the email in the approver's Sigstore certificate, so "approved by" is a cryptographic claim, not a string anyone can type.

## What cannot be waived

* **A real secret.** `tool: gitleaks` waivers are only accepted with `class: false-positive` and a commit-independent `pattern`. A live credential in history is rotated; it is not accepted.
* **The waiver gate itself.** `waiver-integrity` has no waiver path. It is the only gate in the pipeline that does not, on purpose.
* **Anything, silently.** Suppression exists only where a signed, unexpired waiver exists.

## When one expires

1. `waiver-integrity` fails on the next PR *and* the next push to main, with the waiver id, the days lapsed and the ticket in the error.
2. The nightly run fails too, so a repo with no PR traffic still surfaces it — a lapsed waiver does not wait for someone to open a PR.
3. Seven days before expiry the gate emits a `::warning::` on every run (and, in the real rollout, opens a GitHub issue against the ticket). By design there is no auto-renew: the whole value is that somebody has to look again.
4. Two ways out: fix the finding and delete the waiver, or open a renewal PR — which is a fresh two-person approval and a fresh signature, not a rubber stamp on the old one.

## False-positive load, and what I would tune first

Estimated for this repo shape, from what these tools do on a Go service with Terraform and Kubernetes YAML:

| gate | expected FP rate | first thing I tune |
|---|---|---|
| gitleaks (full history) | **highest** — test fixtures, example IBANs, base64 blobs, old `.env.example` files | scope-based allowlist for `app/testdata/`, then raise the entropy floor for generic rules. This is first because a noisy secret gate is the fastest way to teach a team to skim CI output. |
| semgrep `p/owasp-top-ten` | medium — sanitiser-unaware taint on Go template paths | delete the rules that fire on our idioms rather than blanket-ignoring paths; a path ignore hides the true positives too. This is why SAST ships in WARN mode. |
| trivy SCA | low, but high *volume* of unactionable CRITICALs in base-image OS packages | `--ignore-unfixed` on the blocking scan (already set) plus a distroless base, which deletes most of the OS layer rather than ignoring it. |
| conftest IaC | very low — the rules are ours and assertion-shaped | nothing; if this one is noisy the rule is wrong and gets fixed, not waived. |

A pipeline nobody trusts is a pipeline nobody reads. The order above is deliberately "loudest first", not "highest severity first".
