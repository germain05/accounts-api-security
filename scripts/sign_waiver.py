#!/usr/bin/env python3
"""Emit the canonical, signable body of a waiver.

An approver never signs the YAML file — YAML has too many byte-identical
spellings for the same document, so a signature over the raw text would break on
a reformat and could be laundered by one. They sign the canonical JSON produced
here, which is exactly what scripts/waiver_check.py recomputes at verify time.

  # 1. produce the payload
  python3 scripts/sign_waiver.py SEC-2041-trivy-CVE-2024-45337 -o /tmp/w.json

  # 2a. production: keyless, approver authenticates with their corporate GitHub
  cosign sign-blob --yes --bundle waivers/signatures/<id>.bundle /tmp/w.json

  # 2b. offline demo in this repo: keyed
  cosign sign-blob --yes --key <approver>.key --output-signature waivers/signatures/<id>.sig /tmp/w.json

Editing any field afterwards — most importantly `expires`, `scope` or
`severity` — invalidates the signature and fails the waiver-integrity gate.
"""
import argparse
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from waiver_check import DEFAULT_WAIVERS, canonical_body  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("waiver_id")
    ap.add_argument("-o", "--out", default="-")
    ap.add_argument("--file", default=str(DEFAULT_WAIVERS))
    a = ap.parse_args()

    doc = yaml.safe_load(Path(a.file).read_text()) or {}
    for w in doc.get("waivers", []):
        if w.get("id") == a.waiver_id:
            body = canonical_body(w)
            if a.out == "-":
                sys.stdout.buffer.write(body + b"\n")
            else:
                Path(a.out).write_bytes(body)
                print(f"wrote {len(body)} bytes to {a.out}", file=sys.stderr)
            return 0
    print(f"no waiver with id {a.waiver_id}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
