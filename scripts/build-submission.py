#!/usr/bin/env python3
"""Build the submission pack: one file per form field, plus a PDF of each.

The assessment form asks for ~19 separate uploads, several of which correspond to
more than one file in this repository (all the Kyverno policies, for example, or
the waiver mechanism's script + data + approver list). This script assembles each
one into a single, self-contained, clearly-labelled artefact so the form can be
filled in without hunting through the tree — and regenerates them from the repo,
so the pack can never drift from what is committed.

  python3 scripts/build-submission.py            # files + PDFs
  python3 scripts/build-submission.py --no-pdf   # files only

Output: submission/files/ and submission/pdf/
"""
from __future__ import annotations

import argparse
import html
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT_FILES = ROOT / "submission" / "files"
OUT_PDF = ROOT / "submission" / "pdf"

CHROME_CANDIDATES = ["chromium", "chromium-browser", "google-chrome", "google-chrome-stable"]
# Playwright-managed Chromium, if that is the only one on the box.
CHROME_GLOBS = ["/opt/pw-browsers/chromium-*/chrome-linux/chrome",
                "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                "/Applications/Chromium.app/Contents/MacOS/Chromium"]

# Each entry: (output filename, [source paths], header note)
# A single source is copied verbatim. Several sources are concatenated with a
# banner naming each original path, so a reviewer can always find the real file.
BUNDLES: list[tuple[str, list[str], str]] = [
    # ---- Section 1: Part 1 — Build ---------------------------------------
    ("01-2-README.md", ["README.md"],
     "Section 1 deliverable: README covering how a reviewer runs the policy tests."),

    # ---- Section 2: Threat model -----------------------------------------
    ("02-1-threat-model.md", ["THREAT-MODEL.md", "TRACEABILITY.md"],
     "Section 2 deliverable: one-page threat model. TRACEABILITY.md is appended "
     "because the brief asks that everything in sections 2-6 trace back to a named "
     "threat, and that mapping is the evidence for it."),

    # ---- Section 3: Build and release integrity --------------------------
    ("03-1-build-release-pipeline.yaml", [".github/workflows/build-release.yml"],
     "Section 3 deliverable: the pipeline implementing SBOM attestation, image "
     "signing, OIDC auth and immutable tags."),
    ("03-2-iam-oidc-trust-policy.json", ["iam/github-oidc-trust-policy.json"],
     "Section 3 deliverable: IAM OIDC trust policy with the sub claim scoped as it "
     "would ship. The build-account variant is iam/github-oidc-trust-policy-build.json."),
    ("03-3-build-integrity-notes.md", ["docs/02-build-integrity.md"],
     "Supporting write-up for section 3: where the trust root lives, how tag "
     "mutation is prevented, what the OIDC scoping denies, and what the signature "
     "does and does not prove."),

    # ---- Section 4: Pipeline gates and the waiver path -------------------
    ("04-1-security-gates.yaml", [".github/workflows/security-gates.yml"],
     "Section 4 deliverable: SCA, SAST, full-history secret scanning and IaC "
     "scanning with the severity thresholds that block a merge."),
    ("04-2-waiver-mechanism.md",
     ["waivers/README.md", "waivers/waivers.yaml", "waivers/APPROVERS.yaml",
      "scripts/waiver_check.py", "waivers/fixtures/invalid-waivers.yaml",
      "waivers/fixtures/tampered.yaml", "test-output/waiver-check.txt",
      "test-output/waiver-check-invalid.txt", "test-output/waiver-check-tampered.txt"],
     "Section 4 deliverable: the waiver mechanism — in-repo, cosign-signed over a "
     "canonical body, severity-capped expiry, and fail-closed on lapse. Includes the "
     "specification, the live waiver file, the approver authority matrix, the full "
     "implementation, the negative fixtures, and captured proof that the gate fails "
     "closed on both an expired waiver and a post-approval edit."),
    ("04-3-break-glass.md", ["docs/03-break-glass.md"],
     "Section 4 deliverable: break-glass procedure and the audit trail it leaves."),
    ("04-4-gates-rationale.md", ["docs/03-gates-and-waivers.md"],
     "Supporting write-up for section 4: tool choices, the full-history mechanism, "
     "the threshold reasoning, and the expected false-positive load."),

    # ---- Section 5: Review and remediate ---------------------------------
    ("05-1-workload-fixed.yaml", ["remediate/workload-fixed.yaml"],
     "Section 5 deliverable: the remediated Deployment and RBAC. Defects and their "
     "exploitability ranking are in 05-6-findings.md."),
    ("05-2-kyverno-policy-and-fixtures.yaml",
     ["policy/kyverno/policies/disallow-host-namespaces.yaml",
      "policy/kyverno/policies/disallow-hostpath.yaml",
      "policy/kyverno/policies/require-restricted-securitycontext.yaml",
      "policy/kyverno/policies/restrict-rbac-wildcards.yaml",
      "policy/kyverno/policies/restrict-privileged-rolebindings.yaml",
      "policy/kyverno/policies/require-image-digest.yaml",
      "policy/kyverno/policies/restrict-registries.yaml",
      "policy/kyverno/policies/disallow-secrets-as-env.yaml",
      "policy/kyverno/policies/require-resource-limits.yaml",
      "policy/kyverno/tests/kyverno-test.yaml",
      "policy/kyverno/tests/resources/bad-workload.yaml",
      "policy/kyverno/tests/resources/bypass-workload.yaml"],
     "Section 5 deliverable: policy-as-code preventing recurrence of the workload "
     "defects, with the test fixtures. bad-workload.yaml is the production manifest "
     "verbatim (fails before the fix); the remediated manifest in 05-1 passes after. "
     "bypass-workload.yaml is a third fixture: a plausible attempt to satisfy the "
     "policy names without changing the behaviour."),
    ("05-3-terraform-fixed.tf",
     ["terraform/rds.tf", "terraform/security_groups.tf", "terraform/cloudtrail.tf",
      "terraform/kms.tf", "terraform/ecr.tf", "terraform/variables.tf",
      "terraform/versions.tf"],
     "Section 5 deliverable: the remediated Terraform. Defects and their "
     "exploitability ranking are in 05-6-findings.md."),
    ("05-4-iac-policy-and-fixtures.md",
     ["policy/rego/terraform.rego", "policy/rego/terraform_test.rego",
      "policy/fixtures/terraform/bad/main.tf",
      "policy/fixtures/terraform/evasion/main.tf",
      "policy/fixtures/terraform/good/main.tf",
      "test-output/conftest-verify.txt", "test-output/conftest-bad-fixture.txt",
      "test-output/conftest-evasion-fixture.txt", "test-output/conftest-good-fixture.txt"],
     "Section 5 deliverable: IaC policy-as-code with test fixtures. 33 unit tests, "
     "the production-today configuration rejected by 11 rules, an evasion fixture "
     "(variable-driven values, dynamic blocks, IPv6, Aurora) rejected by 7 more, and "
     "the remediated version passing. Captured output included."),
    ("05-5-pod-identity-policy.json", ["iam/pod-identity-policy.json"],
     "Section 5 deliverable: the least-privilege pod identity policy. The original "
     "is iam/pod-identity-policy-original.json; the one-line statement of what this "
     "denies that the original allowed is at the end of 05-6-findings.md."),
    ("05-6-findings.md", ["docs/04-findings.md"],
     "Section 5 supporting write-up: every defect in the three artefacts, ranked by "
     "exploitability in this environment rather than by scanner severity, with the "
     "fix and the policy that prevents recurrence."),

    # ---- Section 6: Admission and runtime ---------------------------------
    ("06-1-admission-policies.yaml",
     ["policy/kyverno/policies/disallow-host-namespaces.yaml",
      "policy/kyverno/policies/disallow-hostpath.yaml",
      "policy/kyverno/policies/require-restricted-securitycontext.yaml",
      "policy/kyverno/policies/restrict-rbac-wildcards.yaml",
      "policy/kyverno/policies/restrict-privileged-rolebindings.yaml",
      "policy/kyverno/policies/require-image-digest.yaml",
      "policy/kyverno/policies/verify-image-signature.yaml",
      "policy/kyverno/policies/restrict-registries.yaml",
      "policy/kyverno/policies/disallow-secrets-as-env.yaml",
      "policy/kyverno/policies/require-resource-limits.yaml"],
     "Section 6 deliverable: the admission baseline. Every policy carries its "
     "day-one mode and its promotion criteria in its own annotations "
     "(example-bank.io/day-one-mode, /promotion-criteria, /promotion-evidence) — the "
     "rollout posture is next to the rule, not in a wiki. The summary table is in "
     "06-5-admission-rollout.md."),
    ("06-2-policy-test-output.txt",
     ["test-output/kyverno-test.txt", "test-output/conftest-bad-fixture.txt",
      "test-output/conftest-evasion-fixture.txt", "test-output/waiver-check-invalid.txt"],
     "Section 6 deliverable: captured test output showing the bad manifest rejected. "
     "39 kyverno assertions across three fixtures, plus the Terraform and waiver "
     "negative fixtures failing as designed."),
    ("06-3-runtime-detection-and-runbook.md",
     ["runtime/falco-rules.yaml", "runtime/runbook-accounts-api.md"],
     "Section 6 deliverable: a custom runtime detection rule written for this "
     "workload, with the alert payload, where it lands, who is woken, and the first "
     "three steps of the responder's runbook."),
    ("06-4-egress-control.yaml",
     ["k8s/networkpolicy-egress.yaml", "k8s/istio-egress.yaml",
      "k8s/networkpolicy-quarantine.yaml"],
     "Section 6 deliverable: the egress control — default-deny at L3/L4 plus an "
     "FQDN- and CA-pinned egress gateway at L7. Documented limitations are in "
     "06-6-egress-limitations.md."),
    ("06-5-admission-rollout.md", ["docs/05-admission-rollout.md"],
     "Section 6 supporting write-up: audit/enforce designation per policy, what "
     "triggers promotion, and what counts as evidence that a gate is ready."),
    ("06-6-egress-limitations.md", ["docs/05-egress.md"],
     "Section 6 supporting write-up: which layer the egress control sits at, the "
     "layers rejected and why, and seven named things it still fails to stop."),

    # ---- Section 7: Secrets and data protection ---------------------------
    ("07-1-secrets-delivery.yaml",
     ["k8s/externalsecret.yaml", "iam/external-secrets-policy.json"],
     "Section 7 deliverable: the secrets delivery configuration. No plaintext "
     "credential in the repo or in any committed manifest; mapped to AWS Secrets "
     "Manager via the Secrets Store CSI driver, with External Secrets Operator shown "
     "as the alternative and the trade-off stated."),
    ("07-2-rotation.md", ["docs/06-secrets-rotation.md"],
     "Section 7 deliverable: rotation mechanism, interval, emergency procedure, and "
     "target rotation time per credential."),
    ("07-3-log-redaction.md", ["docs/06-log-redaction.md"],
     "Section 7 deliverable: what is redacted, at which layer, and what the "
     "redaction still leaks."),

    # ---- Section 8: Part 2 — Decisions ------------------------------------
    ("08-1-decisions.md", ["DECISIONS.md"],
     "Section 8 deliverable: biggest decisions, enforcement posture, two blast-radius "
     "scenarios worked fully, the detection gap, the regulatory table, and what was cut."),
    ("08-2-assumptions-and-operating-model.md",
     ["ASSUMPTIONS.md", "docs/07-operating-model.md"],
     "Optional supporting material: the assumptions filled in where the brief was "
     "generic, and how the controls stay alive after month one."),
]

LANG = {".yaml": "yaml", ".yml": "yaml", ".json": "json", ".tf": "hcl",
        ".rego": "rego", ".py": "python", ".conf": "ini", ".txt": "text",
        ".sh": "bash", ".md": "markdown"}


def comment_banner(path: str, ext: str) -> str:
    line = "=" * 74
    if ext in {".yaml", ".yml", ".py", ".sh", ".conf"}:
        return f"# {line}\n# SOURCE: {path}\n# {line}\n"
    if ext in {".tf", ".rego"}:
        return f"// {line}\n// SOURCE: {path}\n// {line}\n"
    if ext == ".txt":
        return f"{line}\nSOURCE: {path}\n{line}\n"
    return f"\n---\n\n## SOURCE: `{path}`\n\n"


def build_file(name: str, sources: list[str], note: str) -> Path:
    out = OUT_FILES / name
    ext = out.suffix
    parts: list[str] = []

    if ext == ".md":
        parts.append(f"<!-- {name} -->\n\n> **{note}**\n>\n"
                     f"> Assembled by `scripts/build-submission.py` from the repository. "
                     f"Source paths are given above each section.\n")
    elif ext == ".json":
        pass  # must stay valid JSON — no banner
    else:
        c = "//" if ext in {".tf", ".rego"} else "#"
        wrapped = "\n".join(f"{c} {ln}" for ln in _wrap(note, 76))
        parts.append(f"{c} {name}\n{c}\n{wrapped}\n{c}\n"
                     f"{c} Assembled by scripts/build-submission.py from the repository.\n")

    for src in sources:
        text = (ROOT / src).read_text()
        if ext == ".md" and Path(src).suffix != ".md":
            lang = LANG.get(Path(src).suffix, "")
            parts.append(f"\n---\n\n## `{src}`\n\n```{lang}\n{text.rstrip()}\n```\n")
        elif ext == ".md":
            parts.append(f"\n---\n\n## `{src}`\n\n{text.rstrip()}\n")
        elif ext == ".json" and len(sources) == 1:
            parts.append(text)
        else:
            parts.append(comment_banner(src, ext) + text.rstrip() + "\n")

    out.write_text("\n".join(parts).rstrip() + "\n")
    return out


def _wrap(s: str, width: int) -> list[str]:
    words, lines, cur = s.split(), [], ""
    for w in words:
        if len(cur) + len(w) + 1 > width:
            lines.append(cur)
            cur = w
        else:
            cur = f"{cur} {w}".strip()
    if cur:
        lines.append(cur)
    return lines


CSS = """
@page { size: A4; margin: 16mm 14mm 18mm 14mm; }
body { font: 10.5pt/1.5 -apple-system, "Segoe UI", Helvetica, Arial, sans-serif;
       color: #14181f; margin: 0; }
h1 { font-size: 19pt; margin: 0 0 4pt; letter-spacing: -0.2pt; }
h2 { font-size: 13.5pt; margin: 18pt 0 6pt; padding-bottom: 3pt;
     border-bottom: 1px solid #d7dce3; }
h3 { font-size: 11.5pt; margin: 13pt 0 4pt; }
h2, h3, h4 { page-break-after: avoid; }
p, li { orphans: 3; widows: 3; }
code { font-family: "SF Mono", "JetBrains Mono", Menlo, Consolas, monospace;
       font-size: 9pt; background: #f2f4f7; padding: 1px 4px; border-radius: 3px; }
pre { background: #f7f9fb; border: 1px solid #dde3ea; border-left: 3px solid #7b8794;
      border-radius: 4px; padding: 8pt 10pt; overflow-wrap: break-word;
      white-space: pre-wrap; font-size: 8.2pt; line-height: 1.42; }
pre code { background: none; padding: 0; font-size: inherit; }
table { border-collapse: collapse; width: 100%; margin: 8pt 0; font-size: 9pt; }
th, td { border: 1px solid #d7dce3; padding: 4pt 6pt; text-align: left;
         vertical-align: top; }
th { background: #eef1f5; font-weight: 600; }
blockquote { margin: 8pt 0; padding: 6pt 10pt; background: #f4f7fb;
             border-left: 3px solid #4a6fa5; font-size: 9.5pt; }
blockquote p { margin: 0 0 4pt; }
.doc-head { border-bottom: 2px solid #14181f; padding-bottom: 6pt; margin-bottom: 12pt; }
.diagram { margin: 10pt 0 14pt; text-align: center; page-break-inside: avoid; }
.diagram svg { max-width: 100%; height: auto; }
.doc-head .sub { color: #5b6472; font-size: 9pt; margin-top: 3pt; }
a { color: #1f4e8c; text-decoration: none; }
"""


def to_html(path: Path, title: str) -> str:
    ext = path.suffix
    if ext == ".md":
        import markdown
        import re as _re

        src = path.read_text()

        # A Mermaid fence is a picture on GitHub and a wall of source in a PDF.
        # Swap it for the pre-rendered SVG (scripts/render-diagrams.sh), and drop
        # the duplicate <img> that THREAT-MODEL.md carries as its own fallback.
        svg = ROOT / "docs" / "img" / "trust-boundaries.svg"
        if svg.exists():
            src = _re.sub(r"!\[[^\]]*\]\((?:\.\./)*docs/img/trust-boundaries\.svg\)\n?", "", src)
            src = _re.sub(r"```mermaid\n.*?```",
                          "@@DIAGRAM@@", src, flags=_re.S)

        body = markdown.markdown(
            src,
            extensions=["tables", "fenced_code", "toc", "sane_lists", "attr_list"],
        )
        if svg.exists() and "@@DIAGRAM@@" in body:
            inline = svg.read_text()
            inline = _re.sub(r"^<\?xml[^>]*\?>\s*", "", inline)
            body = body.replace("<p>@@DIAGRAM@@</p>",
                                f"<div class='diagram'>{inline}</div>")
            body = body.replace("@@DIAGRAM@@", "")
    else:
        body = ("<pre><code>"
                + html.escape(path.read_text())
                + "</code></pre>")
    return (f"<!doctype html><html><head><meta charset='utf-8'>"
            f"<title>{html.escape(title)}</title><style>{CSS}</style></head><body>"
            f"<div class='doc-head'><h1>{html.escape(title)}</h1>"
            f"<div class='sub'>accounts-api security assessment &middot; "
            f"generated from the repository, not hand-edited</div></div>"
            f"{body}</body></html>")


def find_chrome() -> str | None:
    for c in CHROME_CANDIDATES:
        if shutil.which(c):
            return c
    import glob
    for pattern in CHROME_GLOBS:
        for hit in sorted(glob.glob(pattern), reverse=True):
            if Path(hit).exists():
                return hit
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-pdf", action="store_true")
    args = ap.parse_args()

    for d in (OUT_FILES, OUT_PDF):
        d.mkdir(parents=True, exist_ok=True)

    built = []
    for name, sources, note in BUNDLES:
        missing = [s for s in sources if not (ROOT / s).exists()]
        if missing:
            print(f"::error:: {name}: missing source(s) {missing}")
            return 1
        built.append((build_file(name, sources, note), note))
    print(f"wrote {len(built)} file(s) to submission/files/")

    if args.no_pdf:
        return 0

    chrome = find_chrome()
    if chrome is None:
        print("no chromium found — skipping PDFs (rerun without --no-pdf where one exists)")
        return 0

    tmp = ROOT / ".submission-html"
    tmp.mkdir(exist_ok=True)
    ok = 0
    for path, _ in built:
        title = path.stem
        h = tmp / f"{title}.html"
        h.write_text(to_html(path, title))
        pdf = OUT_PDF / f"{title}.pdf"
        proc = subprocess.run(
            [chrome, "--headless", "--disable-gpu", "--no-sandbox",
             "--no-pdf-header-footer", f"--print-to-pdf={pdf}", f"file://{h}"],
            capture_output=True, text=True, timeout=180,
        )
        if pdf.exists():
            ok += 1
        else:
            print(f"::warning:: PDF failed for {title}: {proc.stderr.strip()[-200:]}")
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"wrote {ok}/{len(built)} PDF(s) to submission/pdf/")
    return 0 if ok == len(built) else 1


if __name__ == "__main__":
    sys.exit(main())
