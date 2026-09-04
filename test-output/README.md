# Captured test output

Committed so a reviewer can see the result without installing anything, and so a
regression is visible in a diff. Regenerate with `./scripts/run-policy-tests.sh`.

Three of these files contain **failures on purpose** — they are the negative
fixtures, and the suite asserts that the command exits non-zero:

| file | what it shows |
|---|---|
| `kyverno-test.txt` | 35 assertions across the broken, bypass-attempt and remediated manifests |
| `conftest-verify.txt` | 23 Rego unit tests for the Terraform rules |
| `conftest-bad-fixture.txt` | **11 deliberate failures** — the production Terraform being rejected |
| `conftest-good-fixture.txt` | the same three resources, remediated, passing |
| `conftest-terraform.txt` | the shipped `terraform/` passing |
| `waiver-check.txt` | the live waiver file: schema, approver authority, lifetime cap, expiry, signature |
| `waiver-check-invalid.txt` | **9 deliberate failures** — expired, self-approved, over-cap, unauthorised approver, a real secret being waived, and the "just make it go away" waiver |
| `waiver-check-tampered.txt` | **1 deliberate failure** — `expires` edited by two days after approval; only the signature catches it |
| `waiver-generate.txt` | derived ignore files, built from active waivers only |
| `gitleaks-waiver-worked-example.txt` | the whole waiver mechanism end to end against this repo: a real gitleaks false positive → signed waiver `SEC-2118` → derived allowlist → clean scan, with the commands to reproduce |

Run date: 2026-09-04. See the note in the top-level README about `SEC-2041`
expiring on 2026-09-27 and why that makes the suite go red.
