#!/usr/bin/env python3
"""Assert every policy document in iam/ is one AWS would actually accept.

This exists because of a defect found in review: the policies here carried a
top-level `_comment` key holding their rationale. That is a common convention and
it does not work — an IAM policy document accepts only `Version`, `Id` and
`Statement` at the top level, and `iam:CreatePolicy` /
`iam:UpdateAssumeRolePolicy` reject the whole document with
`MalformedPolicyDocument`. Every one of these files would have failed to apply.

A policy that cannot be applied is worse than no policy: it reviews as a control
and is not one. The rationale now lives in iam/README.md and this check keeps the
JSON appliable.

Checks, per file:
  * parses as JSON
  * top-level keys are a subset of {Version, Id, Statement}
  * Version is the policy-language date, not today's date
  * every statement has Effect in {Allow, Deny} and only schema-legal keys
  * a trust policy (has Principal) uses sts:AssumeRole* actions
  * no `StringLike` on a GitHub OIDC `sub` claim — the wildcard that makes the
    scoping decorative (see iam/README.md)
"""
import json
import sys
from pathlib import Path

TOP = {"Version", "Id", "Statement"}
STMT = {"Sid", "Effect", "Principal", "NotPrincipal", "Action", "NotAction",
        "Resource", "NotResource", "Condition"}
IAM_DIR = Path(__file__).resolve().parent.parent / "iam"


def check(path: Path) -> list[str]:
    errs: list[str] = []
    try:
        doc = json.loads(path.read_text())
    except json.JSONDecodeError as e:
        return [f"{path.name}: not valid JSON — {e}"]

    extra = set(doc) - TOP
    if extra:
        errs.append(f"{path.name}: top-level key(s) {sorted(extra)} — AWS rejects "
                    f"the document with MalformedPolicyDocument. Put commentary in "
                    f"iam/README.md instead.")
    if doc.get("Version") != "2012-10-17":
        errs.append(f"{path.name}: Version must be the policy-language version "
                    f"'2012-10-17', got {doc.get('Version')!r}")

    stmts = doc.get("Statement")
    if not isinstance(stmts, list) or not stmts:
        return errs + [f"{path.name}: Statement must be a non-empty list"]

    for i, st in enumerate(stmts):
        where = f"{path.name} statement[{i}]{' ' + st.get('Sid', '') if isinstance(st, dict) else ''}"
        if not isinstance(st, dict):
            errs.append(f"{where}: not an object")
            continue
        bad = set(st) - STMT
        if bad:
            errs.append(f"{where}: non-schema key(s) {sorted(bad)}")
        if st.get("Effect") not in {"Allow", "Deny"}:
            errs.append(f"{where}: Effect must be Allow or Deny")
        if not ({"Action", "NotAction"} & set(st)):
            errs.append(f"{where}: needs Action or NotAction")
        if "Principal" in st:
            acts = st.get("Action", [])
            acts = [acts] if isinstance(acts, str) else acts
            if not all(a.startswith("sts:AssumeRole") for a in acts):
                errs.append(f"{where}: trust policy action should be sts:AssumeRole* , got {acts}")
        cond = st.get("Condition", {})
        for op, kv in cond.items():
            if "StringLike" in op:
                for key in kv:
                    if key.endswith(":sub"):
                        errs.append(
                            f"{where}: StringLike on '{key}'. A wildcarded `sub` "
                            f"accepts every branch and pull request in the repo, "
                            f"which is equivalent to no scoping. Use StringEquals.")
    return errs


def main() -> int:
    files = sorted(IAM_DIR.glob("*.json"))
    if not files:
        print("::error::no policy documents found in iam/")
        return 1
    errs = [e for f in files for e in check(f)]
    for e in errs:
        print(f"::error::{e}")
    if errs:
        print(f"\nFAIL: {len(errs)} problem(s) across {len(files)} policy document(s).")
        return 1
    print(f"OK: {len(files)} IAM policy document(s) are schema-valid and appliable.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
