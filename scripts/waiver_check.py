#!/usr/bin/env python3
"""Waiver gatekeeper for the accounts-api security gates.

Two subcommands, both used by .github/workflows/security-gates.yml:

  check     validate every waiver: schema, approver authority, lifetime cap for
            the severity, signature over the canonical body, and expiry.
            Exits non-zero on ANY expired or malformed waiver, which is what
            makes a lapsed waiver fail the build rather than quietly persist.

  generate  emit the per-tool ignore files (.trivyignore, .gitleaks.toml,
            .semgrepignore, policy/rego/data.waivers.json) from the ACTIVE
            waivers only. Those files are .gitignore'd and never committed, so
            the only way to suppress a finding in this repo is a waiver entry
            that passed `check` in the same pipeline run.

Usage:
  python3 scripts/waiver_check.py check [--verify-signatures] [--file PATH] [--today YYYY-MM-DD]
  python3 scripts/waiver_check.py generate [--file PATH]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import date, datetime, timedelta
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_WAIVERS = ROOT / "waivers" / "waivers.yaml"
APPROVERS_FILE = ROOT / "waivers" / "APPROVERS.yaml"
SIG_DIR = ROOT / "waivers" / "signatures"

REQUIRED = {
    "id", "tool", "finding", "scope", "severity", "class",
    "reason", "compensating_control", "ticket",
    "requested_by", "approved_by", "created", "expires",
}

TOOLS = {"trivy", "semgrep", "gitleaks", "conftest", "checkov", "kyverno"}

# Maximum life of a waiver, by the severity of the thing being waived.
# The point of the cap is that the *renewal conversation* happens on a cadence
# proportional to the risk, not that 14 days is a magic number.
MAX_LIFETIME_DAYS = {"CRITICAL": 14, "HIGH": 30, "MEDIUM": 90, "LOW": 180}

# Why a waiver exists. `false-positive` and `not-exploitable` are analytical
# claims that can be re-tested; `accepted-risk` is a business decision and needs
# a higher approver. See waivers/README.md.
CLASSES = {"false-positive", "not-exploitable", "fix-in-flight", "accepted-risk"}

WARN_WINDOW_DAYS = 7
TICKET_RE = re.compile(r"^SEC-\d{3,6}$")

# Sigstore identity that signed the waiver body. Keyless; the approver runs
#   cosign sign-blob --bundle waivers/signatures/<id>.bundle <canonical.json>
# and authenticates with their corporate GitHub account.
COSIGN_ISSUER = "https://github.com/login/oauth"


class Findings:
    def __init__(self) -> None:
        self.errors: list[str] = []
        self.warnings: list[str] = []

    def err(self, msg: str) -> None:
        self.errors.append(msg)

    def warn(self, msg: str) -> None:
        self.warnings.append(msg)


def _as_date(value) -> date | None:
    if isinstance(value, date) and not isinstance(value, datetime):
        return value
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, str):
        try:
            return date.fromisoformat(value)
        except ValueError:
            return None
    return None


def canonical_body(waiver: dict) -> bytes:
    """Byte-exact payload the approver signed.

    Signature covers everything except the signature block itself, so an
    unsigned field cannot be edited after approval — in particular `expires`,
    `scope` and `severity`, which are the three an attacker or an impatient
    engineer would want to change.
    """
    body = {k: v for k, v in waiver.items() if k not in {"signature", "_notes"}}
    for k, v in body.items():
        if isinstance(v, (date, datetime)):
            body[k] = v.isoformat()
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


def load_approvers() -> dict:
    if not APPROVERS_FILE.exists():
        return {}
    return yaml.safe_load(APPROVERS_FILE.read_text()) or {}


def approver_authorised(approvers: dict, identity: str, severity: str, klass: str) -> str | None:
    """Return an error string, or None if the approval is in order."""
    people = {p["identity"]: p for p in approvers.get("approvers", [])}
    person = people.get(identity)
    if person is None:
        return f"approved_by '{identity}' is not in waivers/APPROVERS.yaml"
    authority = set(person.get("may_approve", []))
    if severity not in authority:
        return (f"approved_by '{identity}' may approve {sorted(authority)} — "
                f"not {severity}")
    if klass == "accepted-risk" and not person.get("may_accept_risk", False):
        return (f"class 'accepted-risk' needs a risk-accepting approver; "
                f"'{identity}' is not one")
    return None


def verify_signature(waiver: dict, approvers: dict, f: Findings) -> None:
    """Verify the approver's detached signature over `canonical_body(waiver)`.

    Two modes, because the production mode is not runnable by an offline reviewer:

      keyless (production)  waivers/signatures/<id>.bundle, verified against the
                            approver's Sigstore identity and the GitHub OIDC issuer.
                            No standing private key exists anywhere.

      keyed (this repo)     waivers/signatures/<id>.sig + waivers/keys/<approver>.pub,
                            verified with `cosign verify-blob --key`. Used here ONLY
                            so `make verify` works with no network and no browser
                            login; the private keys were generated, used once and
                            destroyed, and are not in this repository.

    Keyed mode is chosen automatically when a .sig exists. In the real rollout the
    keyed path would be removed, since a standing key is exactly the thing keyless
    signing exists to avoid.
    """
    wid = waiver["id"]
    if shutil.which("cosign") is None:
        f.err(f"{wid}: cosign not on PATH — cannot verify signature "
              f"(this is an error, not a skip: an unverifiable waiver is not a waiver)")
        return

    sig = SIG_DIR / f"{wid}.sig"
    bundle = SIG_DIR / f"{wid}.bundle"
    pubkey = ROOT / "waivers" / "keys" / f"{waiver['approved_by']}.pub"

    if sig.exists():
        if not pubkey.exists():
            f.err(f"{wid}: signed by {waiver['approved_by']} but no public key at "
                  f"{pubkey.relative_to(ROOT)}")
            return
        # --insecure-ignore-tlog: the offline keyed demo does not publish to Rekor,
        # because a transparency-log entry is only meaningful with a Fulcio
        # certificate binding it to a human identity. The production keyless path
        # below does use the log, and does not pass this flag.
        cmd = ["cosign", "verify-blob", "--key", str(pubkey),
               "--signature", str(sig), "--insecure-ignore-tlog=true"]
    elif bundle.exists():
        cmd = ["cosign", "verify-blob", "--bundle", str(bundle),
               "--certificate-identity", waiver["approved_by"],
               "--certificate-oidc-issuer", COSIGN_ISSUER]
    else:
        f.err(f"{wid}: no signature — expected waivers/signatures/{wid}.sig "
              f"or {wid}.bundle")
        return

    payload = ROOT / f".waiver-{wid}.canonical.json"
    payload.write_bytes(canonical_body(waiver))
    try:
        proc = subprocess.run(cmd + [str(payload)], capture_output=True,
                              text=True, timeout=60)
        if proc.returncode != 0:
            tail = (proc.stderr or proc.stdout).strip().splitlines()[-1:] or [""]
            f.err(f"{wid}: signature does NOT verify for approver "
                  f"{waiver['approved_by']} — {tail[0]}")
    except subprocess.TimeoutExpired:
        f.err(f"{wid}: cosign verify-blob timed out")
    finally:
        payload.unlink(missing_ok=True)


def check(waivers: list[dict], today: date, verify_sigs: bool) -> int:
    approvers = load_approvers()
    f = Findings()
    seen: set[str] = set()

    for i, w in enumerate(waivers):
        wid = w.get("id", f"<index {i}>")
        missing = REQUIRED - set(w)
        if missing:
            f.err(f"{wid}: missing required field(s) {sorted(missing)}")
            continue
        if wid in seen:
            f.err(f"{wid}: duplicate waiver id")
        seen.add(wid)

        if w["tool"] not in TOOLS:
            f.err(f"{wid}: unknown tool '{w['tool']}' (expected one of {sorted(TOOLS)})")
        if w["severity"] not in MAX_LIFETIME_DAYS:
            f.err(f"{wid}: severity must be one of {sorted(MAX_LIFETIME_DAYS)}")
        if w["class"] not in CLASSES:
            f.err(f"{wid}: class must be one of {sorted(CLASSES)}")
        if not TICKET_RE.match(str(w["ticket"])):
            f.err(f"{wid}: ticket must be SEC-nnn (a waiver with no tracking issue "
                  f"is a decision nobody revisits)")
        if len(str(w.get("reason", ""))) < 40:
            f.err(f"{wid}: reason is too short to be a reason")
        if not str(w.get("compensating_control", "")).strip():
            f.err(f"{wid}: compensating_control is mandatory — 'we accept it' is not a control")

        # Secret findings are not risk-acceptable. A real credential in history is
        # rotated, never waived; the only legitimate gitleaks waiver is a proven
        # false positive with a commit-independent pattern.
        if w["tool"] == "gitleaks":
            if w["class"] != "false-positive":
                f.err(f"{wid}: gitleaks findings may only be waived as 'false-positive'. "
                      f"A real secret is rotated, not waived.")
            if not w.get("pattern"):
                f.err(f"{wid}: gitleaks waivers need `pattern` (a commit-independent "
                      f"regex). Fingerprints embed the commit hash and evaporate on rebase.")

        created, expires = _as_date(w["created"]), _as_date(w["expires"])
        if created is None or expires is None:
            f.err(f"{wid}: created/expires must be YYYY-MM-DD dates")
            continue
        if expires <= created:
            f.err(f"{wid}: expires must be after created")

        cap = MAX_LIFETIME_DAYS.get(w["severity"])
        if cap and (expires - created).days > cap:
            f.err(f"{wid}: lifetime {(expires - created).days}d exceeds the "
                  f"{cap}d cap for {w['severity']}")

        if w["requested_by"] == w["approved_by"]:
            f.err(f"{wid}: self-approval — requested_by and approved_by must differ")

        problem = approver_authorised(approvers, w["approved_by"], w["severity"], w["class"])
        if problem:
            f.err(f"{wid}: {problem}")

        if expires < today:
            f.err(f"{wid}: EXPIRED on {expires} ({(today - expires).days}d ago). "
                  f"The finding is live again. Fix it, or open a renewal PR against "
                  f"{w['ticket']} for a fresh two-person approval.")
        elif expires - timedelta(days=WARN_WINDOW_DAYS) <= today:
            f.warn(f"{wid}: expires {expires} (in {(expires - today).days}d) — "
                   f"renewal or fix needed this week, ticket {w['ticket']}")

        if verify_sigs:
            verify_signature(w, approvers, f)

    for m in f.warnings:
        print(f"::warning::{m}")
    for m in f.errors:
        print(f"::error::{m}")

    if f.errors:
        print(f"\nFAIL: {len(f.errors)} waiver problem(s); {len(waivers)} waiver(s) examined.")
        return 1
    print(f"OK: {len(waivers)} waiver(s) valid, signed and unexpired "
          f"({len(f.warnings)} expiring within {WARN_WINDOW_DAYS}d).")
    return 0


def generate(waivers: list[dict], today: date) -> int:
    # Fail closed on anything this function cannot prove is still in date.
    # `check` runs before `generate` in the pipeline and would already have
    # rejected these, but `generate` is what actually writes the suppression
    # files — so it does not get to assume its caller was careful. A waiver whose
    # `expires` will not parse is treated as expired, not as active, and the run
    # fails rather than silently emitting a suppression with no end date.
    unparseable = [str(w.get("id", "<no id>")) for w in waivers
                   if _as_date(w.get("expires")) is None]
    if unparseable:
        for wid in unparseable:
            print(f"::error::{wid}: `expires` is missing or not a YYYY-MM-DD date — "
                  f"refusing to derive a suppression file from it")
        print(f"\nFAIL: {len(unparseable)} waiver(s) with an unusable expiry; "
              f"nothing generated.")
        return 1

    active = [w for w in waivers if _as_date(w["expires"]) >= today]

    trivy = [f"{w['finding']}  # {w['ticket']} {w['approved_by']} exp {w['expires']}"
             for w in active if w["tool"] == "trivy"]
    (ROOT / ".trivyignore").write_text("\n".join(trivy) + ("\n" if trivy else ""))

    patterns = [w["pattern"] for w in active if w["tool"] == "gitleaks"]
    regexes = ",\n    ".join(f"'''{p}'''" for p in patterns)
    (ROOT / ".gitleaks.toml").write_text(
        "# GENERATED by scripts/waiver_check.py — do not edit, do not commit.\n"
        "[extend]\nuseDefault = true\n\n"
        "[allowlist]\n"
        'description = "Derived from waivers/waivers.yaml (CODEOWNERS + cosign gated)"\n'
        'regexTarget = "line"\n'
        + (f"regexes = [\n    {regexes}\n]\n" if patterns else "regexes = []\n")
    )

    semgrep_paths = sorted({w["scope"] for w in active if w["tool"] == "semgrep"})
    (ROOT / ".semgrepignore").write_text("\n".join(semgrep_paths) + ("\n" if semgrep_paths else ""))

    rego = {"waived": [{"rule": w["finding"], "resource": w["scope"], "expires": str(w["expires"])}
                       for w in active if w["tool"] in {"conftest", "checkov"}]}
    out = ROOT / "policy" / "rego" / "data.waivers.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(rego, indent=2) + "\n")

    print(f"generated ignore files from {len(active)}/{len(waivers)} active waiver(s); "
          f"{len(waivers) - len(active)} expired waiver(s) deliberately NOT suppressed")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["check", "generate"])
    ap.add_argument("--file", default=str(DEFAULT_WAIVERS))
    ap.add_argument("--verify-signatures", action="store_true",
                    help="require and verify a cosign bundle per waiver")
    ap.add_argument("--today", default=os.environ.get("WAIVER_TODAY"),
                    help="override today's date (test fixtures only)")
    args = ap.parse_args()

    today = date.fromisoformat(args.today) if args.today else date.today()
    path = Path(args.file)
    if not path.exists():
        print(f"::error::waiver file {path} not found")
        return 1
    doc = yaml.safe_load(path.read_text()) or {}
    waivers = doc.get("waivers") or []

    if args.command == "check":
        return check(waivers, today, args.verify_signatures)
    return generate(waivers, today)


if __name__ == "__main__":
    sys.exit(main())
