# Submission guide — what to put in each field

Everything the assessment form asks for, in the order the form asks for it. Each
row gives you the exact file to attach and, where the field is a text box rather
than an upload, the file to open and paste from.

**Two copies of every deliverable are provided:**

| folder | use it when |
|---|---|
| [`files/`](files) | the field accepts the native format — `.md`, `.yaml`, `.json`, `.tf`, `.txt` |
| [`pdf/`](pdf) | the uploader only offers **PDF, DOC, DOCX, XLSX, PNG, JPG, WebP** (several fields on this form do). Same content, typeset, with the trust-boundary diagram rendered rather than shown as source. |

Both are generated from the repository by `scripts/build-submission.py`, so neither
can drift from what is committed. Re-run it after any change:

```bash
python3 scripts/build-submission.py
```

> **Rule of thumb:** try the native file first. If the picker greys it out, upload
> the identically-named PDF. Never retype anything — every field below has a file.

---

## Section 1 — Part 1: Build

| # | Field on the form | What to submit |
|---|---|---|
| 1.1 | **Git repository (link or archive)** · REQUIRED | The GitHub URL from [`PUSH-TO-GITHUB.md`](PUSH-TO-GITHUB.md). **Test it in an incognito window before you submit** — the form explicitly requires that it opens without signing in. |
| 1.2 | **README.md covering how a reviewer would run your policy tests** · Markdown · REQUIRED | `files/01-2-README.md` (or `pdf/01-2-README.pdf`) |

---

## Section 2 — Threat Model

| # | Field | What to submit |
|---|---|---|
| 2.1 | **Threat model document** (one page max) · Markdown | `files/02-1-threat-model.md` — trust-boundary diagram, ranked top-5 with entry point and reach, control or acceptance per threat, and the overrated threat. The traceability matrix is appended because the brief asks that sections 2–6 trace back to a named threat. |

**Use the PDF here if you can.** `pdf/02-1-threat-model.pdf` has the trust-boundary
diagram rendered as a picture; the Markdown shows it as Mermaid source unless the
reviewer's viewer draws Mermaid (GitHub does).

---

## Section 3 — Build and Release Integrity

| # | Field | What to submit |
|---|---|---|
| 3.1 | **GitHub Actions pipeline config** (SBOM attestation, signing, OIDC, immutable tags) · YAML · REQUIRED | `files/03-1-build-release-pipeline.yaml` |
| 3.2 | **IAM OIDC trust policy with scoped `sub` claim** · JSON · REQUIRED | `files/03-2-iam-oidc-trust-policy.json` |

If there is any free-text or "notes" box in this section, use
`files/03-3-build-integrity-notes.md`. It carries the four things the brief asks
to be stated in one line each — where the trust root lives, how tag mutation is
prevented, what the OIDC scoping denies — plus **what the signature does and does
not prove**, which the brief calls out specifically.

---

## Section 4 — Pipeline Gates and the Waiver Path

| # | Field | What to submit |
|---|---|---|
| 4.1 | **Pipeline gate configuration** (SCA, SAST, secrets over full history, IaC, with thresholds) · YAML · REQUIRED | `files/04-1-security-gates.yaml` |
| 4.2 | **Waiver mechanism implementation or specification** · REQUIRED | `files/04-2-waiver-mechanism.md` — spec, live waiver file, approver authority matrix, the full checker implementation, both negative fixtures, and captured proof the gate fails closed. Use `pdf/04-2-waiver-mechanism.pdf` if the picker rejects `.md`. |
| 4.3 | **Break-glass procedure with audit trail description** · Markdown · REQUIRED (Write **or** Upload) | Upload `files/04-3-break-glass.md`, or open it and paste the whole file into the text box. |

If there is a notes box, `files/04-4-gates-rationale.md` covers the per-tool
rationale, the full-history mechanism, the threshold reasoning, and the expected
false-positive load with what gets tuned first.

> This is the section the brief says it reads hardest. Worth mentioning in any
> free-text box: the waivers are **cosign-signed over a canonical body**, so
> `expires` cannot be extended after approval — and there is a committed fixture
> that proves a two-day edit breaks the signature.

---

## Section 5 — Review and Remediate

| # | Field | What to submit |
|---|---|---|
| 5.1 | **Fixed workload manifest** (Deployment + RBAC) · YAML · REQUIRED | `files/05-1-workload-fixed.yaml` |
| 5.2 | **Policy-as-code preventing recurrence, with test fixtures** · YAML · REQUIRED | `files/05-2-kyverno-policy-and-fixtures.yaml` — nine policies plus the test definition and all three fixtures in one file |
| 5.3 | **Fixed Terraform configuration** · HCL · REQUIRED | `files/05-3-terraform-fixed.tf` |
| 5.4 | **Policy-as-code (IaC scanning rules) with test fixtures** · REQUIRED | `files/05-4-iac-policy-and-fixtures.md` — the Rego, its 33 unit tests, all three fixtures, and the captured pass/fail output |
| 5.5 | **Rewritten IAM policy + one-line statement of what it denies** | `files/05-5-pod-identity-policy.json`. The one-line statement is the last line of `files/05-6-findings.md`; it is quoted in full below so you can paste it straight into the field. |

**Paste-ready for 5.5** — the one-line statement:

> Everything except reading one named secret's `AWSCURRENT` version through the
> Secrets Manager VPC endpoint and reading/writing two named Kafka topics — in
> particular it now denies all IAM and STS (so no persistence and no role
> chaining), all CloudTrail mutation (so the evidence survives), every AWS region
> except `ap-south-1` (so exfiltration into an attacker's region fails and RBI
> data localisation holds), and any use of the credential from outside our VPC
> endpoints (so a stolen token is inert on the attacker's own machine).

The ranked defect analysis for all three artefacts — ranked by **exploitability in
this environment**, which is what the brief asks for — is
`files/05-6-findings.md`. Attach it to any notes box in this section; it is the
part that shows the reasoning rather than the fix.

---

## Section 6 — Admission and Runtime

| # | Field | What to submit |
|---|---|---|
| 6.1 | **Admission policy files with audit/enforce designation and promotion criteria** · YAML · REQUIRED | `files/06-1-admission-policies.yaml` — every policy carries `day-one-mode` and `promotion-criteria` / `promotion-evidence` in its own annotations |
| 6.2 | **Policy test fixtures showing bad manifest rejected** (kyverno test / conftest output) · REQUIRED | `files/06-2-policy-test-output.txt` |
| 6.3 | **Custom runtime detection rule** with alert payload, routing, on-call owner, 3-step runbook · REQUIRED | `files/06-3-runtime-detection-and-runbook.md` |
| 6.4 | **Egress control configuration** + documented limitations | `files/06-4-egress-control.yaml`, and `files/06-6-egress-limitations.md` for the limitations half. If only one upload is allowed, attach the YAML and paste the limitations into any notes box. |

`files/06-5-admission-rollout.md` is the rollout write-up — the audit/enforce table,
what triggers each promotion, and what counts as evidence. Attach it if there is
room; it is the answer to "a shared cluster is a rollout problem as much as a
policy problem".

---

## Section 7 — Secrets and Data Protection

| # | Field | What to submit |
|---|---|---|
| 7.1 | **Secrets delivery configuration**, no plaintext in repo, mapped to Secrets Manager · YAML · REQUIRED | `files/07-1-secrets-delivery.yaml` (the IRSA policy for the secrets operator is `files/07-4-external-secrets-iam-policy.json` if there is a second slot) |
| 7.2 | **Rotation mechanism**: interval, emergency procedure, target times per credential · Markdown · REQUIRED (Write **or** Upload, 50 000 char limit) | `files/07-2-rotation.md` — about 8 400 characters, well inside the limit. Upload it, or open and paste the whole file. |
| 7.3 | **Log redaction specification**: what is redacted, at which layer, what it still leaks · Markdown · REQUIRED | `files/07-3-log-redaction.md` |

---

## Section 8 — Part 2: Decisions and Trade-offs

| # | Field | What to submit |
|---|---|---|
| 8.1 | **Decisions and trade-offs document** (1–2 pages) · Markdown · REQUIRED | `files/08-1-decisions.md` — covers all six required parts: biggest decisions incl. one deliberate non-enforcement, enforcement posture with the promotion sequence, two blast-radius scenarios worked fully, the detection gap, a six-row regulatory table, and what was cut |

`files/08-2-assumptions-and-operating-model.md` is optional supporting material:
the assumptions filled in where the brief was generic, and how the controls stay
alive past month one. Attach it if the form allows an extra file; skip it if not —
nothing required depends on it.

---

## Before you press submit

- [ ] The repository URL opens in an **incognito window** with no sign-in.
- [ ] `./scripts/run-policy-tests.sh` passes on a fresh clone — eleven checks, three of which pass by failing.
- [ ] The Actions tab shows a green `build-release` run (the image really was built, signed, attested and verified).
- [ ] Every REQUIRED field above has a file attached.
- [ ] The two "Write or Upload" fields (4.3, 7.2, and 8.1 if it offers a text box) either have the file attached **or** the full text pasted — not a summary.
- [ ] If any picker rejected a `.yaml` / `.tf` / `.json`, the matching PDF went up instead.

## One thing worth saying in a free-text box if you get one

The suite is **designed to go red on 2026-09-27**, when waiver `SEC-2041` expires.
That is the mechanism working, not a bug: an expired waiver fails the build *and*
stops suppressing the finding, because the ignore files are generated from
unexpired waivers rather than committed. A reviewer running it later can pin the
date with `WAIVER_TODAY=2026-09-04 ./scripts/run-policy-tests.sh`. It is called out
in the README, but it reads better as a deliberate choice than as a surprise.
