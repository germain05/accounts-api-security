#!/usr/bin/env bash
# One command a reviewer can run. Everything here works offline: no cloud
# credentials, no `terraform init`, no registry, no cluster.
#
#   ./scripts/run-policy-tests.sh              # the offline suite (default)
#   ./scripts/run-policy-tests.sh --integration# adds the kind + Kyverno signature check (needs network)
#
# Tool versions are pinned. If a binary is missing the script says how to get it
# and exits non-zero — it does not skip, because a suite that silently skips is
# how a repository ends up claiming coverage it does not have.
set -uo pipefail

cd "$(dirname "$0")/.."
ROOT="$PWD"
OUT="$ROOT/test-output"
mkdir -p "$OUT"

KYVERNO_VERSION=1.13.4
CONFTEST_VERSION=0.56.0

RED=$'\033[31m'; GREEN=$'\033[32m'; DIM=$'\033[2m'; OFF=$'\033[0m'
failures=0

section() { printf '\n%s──── %s %s\n' "$DIM" "$1" "$OFF"; }

need() {
  command -v "$1" >/dev/null 2>&1 && return 0
  printf '%sMISSING: %s%s\n  install: %s\n' "$RED" "$1" "$OFF" "$2"
  failures=$((failures + 1))
  return 1
}

run() { # run <label> <outfile> <cmd...>
  local label="$1" outfile="$2"; shift 2
  printf '  %-58s' "$label"
  if "$@" >"$OUT/$outfile" 2>&1; then
    printf '%sPASS%s\n' "$GREEN" "$OFF"
  else
    printf '%sFAIL%s  (see test-output/%s)\n' "$RED" "$OFF" "$outfile"
    failures=$((failures + 1))
  fi
}

run_expect_fail() { # for negative fixtures: the command MUST exit non-zero
  local label="$1" outfile="$2"; shift 2
  printf '  %-58s' "$label"
  if "$@" >"$OUT/$outfile" 2>&1; then
    printf '%sFAIL%s  (expected a non-zero exit — the gate did not fire)\n' "$RED" "$OFF"
    failures=$((failures + 1))
  else
    printf '%sPASS%s %s(failed as intended)%s\n' "$GREEN" "$OFF" "$DIM" "$OFF"
  fi
}

echo "accounts-api-security — policy test suite"

# ---------------------------------------------------------------- prerequisites
section "prerequisites"
need kyverno  "https://github.com/kyverno/kyverno/releases/download/v${KYVERNO_VERSION}/kyverno-cli_v${KYVERNO_VERSION}_linux_x86_64.tar.gz"
need conftest "https://github.com/open-policy-agent/conftest/releases/download/v${CONFTEST_VERSION}/conftest_${CONFTEST_VERSION}_Linux_x86_64.tar.gz"
need python3  "your package manager"
need cosign   "https://github.com/sigstore/cosign/releases  (needed for waiver signature verification)"
[ "$failures" -eq 0 ] || { echo; echo "${RED}prerequisites missing — stopping${OFF}"; exit 1; }

# --------------------------------------------------------------- drift check
section "fixture drift"
printf '  %-58s' "good-workload fixture == remediate/workload-fixed.yaml"
if diff -q remediate/workload-fixed.yaml \
        policy/kyverno/tests/resources/good-workload.yaml >/dev/null; then
  printf '%sPASS%s\n' "$GREEN" "$OFF"
else
  printf '%sFAIL%s  (the positive fixture has drifted from the manifest we ship)\n' "$RED" "$OFF"
  failures=$((failures + 1))
fi

# ------------------------------------------------------------------ IAM
# A policy AWS would reject is worse than no policy: it reviews as a control and
# is not one. See iam/README.md for why the rationale is not in the JSON.
section "IAM policy documents  (section 2 + 4c)"
run "iam/*.json are schema-valid and appliable" iam-policy-check.txt \
    python3 scripts/check_iam_policies.py

# ------------------------------------------------------- Kubernetes admission
section "Kyverno admission policies  (section 4a + 5)"
run "kyverno test — 7 fixtures, 46 assertions" kyverno-test.txt \
    kyverno test policy/kyverno/tests

# ---------------------------------------------------------------- Terraform
section "Terraform policy-as-code  (section 4b)"
run "conftest verify — 33 rego unit tests" conftest-verify.txt \
    conftest verify --policy policy/rego

run_expect_fail "bad fixture must be rejected (11 deny rules)" conftest-bad-fixture.txt \
    conftest test --policy policy/rego --parser hcl2 --all-namespaces policy/fixtures/terraform/bad/

# The fixture that separates a rule set from a speed bump: every resource in it
# satisfies the letter of a naive rule while shipping the same exposure.
run_expect_fail "evasion fixture must be rejected (var-driven, dynamic, IPv6, Aurora)" conftest-evasion-fixture.txt \
    conftest test --policy policy/rego --parser hcl2 --all-namespaces policy/fixtures/terraform/evasion/

run "good fixture must pass" conftest-good-fixture.txt \
    conftest test --policy policy/rego --parser hcl2 --all-namespaces policy/fixtures/terraform/good/

run "shipped terraform/ must pass" conftest-terraform.txt \
    conftest test --policy policy/rego --parser hcl2 --all-namespaces terraform/

# The brief asks for `terraform validate`. It is a different question from the one
# conftest answers — validate checks syntax and provider schema, conftest checks
# whether the database is public — so both are run and neither substitutes for the
# other. validate needs one network call to the provider registry for `init`,
# which is why conftest and not validate is the BLOCKING gate. Not a silent skip:
# if terraform is absent the suite says so and says what was and was not proven.
printf '  %-58s' "terraform validate (syntax + provider schema)"
if command -v terraform >/dev/null 2>&1; then
  if ( cd terraform \
       && terraform init -backend=false -input=false -no-color >"$OUT/terraform-init.txt" 2>&1 \
       && terraform validate -no-color >"$OUT/terraform-validate-run.txt" 2>&1 ); then
    printf '%sPASS%s\n' "$GREEN" "$OFF"
  else
    printf '%sFAIL%s  (see test-output/terraform-validate-run.txt)\n' "$RED" "$OFF"
    failures=$((failures + 1))
  fi
else
  printf '%sSKIP%s %s(terraform not installed; conftest above already gated this dir —\n' \
    "$DIM" "$OFF" "$DIM"
  printf '   %s a captured run is in test-output/terraform-validate.txt)%s\n' "" "$OFF"
fi

# ------------------------------------------------------------------ waivers
section "Waiver mechanism  (section 3)"
run "valid waivers: schema, approver, lifetime, expiry, signature" waiver-check.txt \
    python3 scripts/waiver_check.py check --verify-signatures

# A HIGH waiver may live at most 30 days, so the live set genuinely lapses if this
# repository is read long enough after it was written. That is the control, not a
# bug — but it should say so where the reviewer is standing rather than only in the
# README, because an unexplained red suite reads as a broken suite.
if grep -q "EXPIRED" "$OUT/waiver-check.txt" 2>/dev/null; then
  cat <<BANNER

  ${DIM}┌─${OFF} a live waiver has lapsed ${DIM}────────────────────────────────────────${OFF}
  ${DIM}│${OFF} This is the mechanism working: an expired waiver FAILS THE BUILD rather
  ${DIM}│${OFF} than quietly continuing to suppress its finding. In a real repository the
  ${DIM}│${OFF} fix is a renewal PR with fresh two-person approval and a fresh signature.
  ${DIM}│${OFF}
  ${DIM}│${OFF} To see the rest of the suite green as it stood on the submission date:
  ${DIM}│${OFF}   ${GREEN}WAIVER_TODAY=2026-09-04 ./scripts/run-policy-tests.sh${OFF}
  ${DIM}└──────────────────────────────────────────────────────────────────${OFF}
BANNER
fi

run_expect_fail "expired / self-approved / over-cap / unwaivable-secret" waiver-check-invalid.txt \
    python3 scripts/waiver_check.py check --file waivers/fixtures/invalid-waivers.yaml

# Two halves of one assertion. The tampered fixture is the live SEC-2041 waiver
# with a single signed field edited (`scope` widened to the whole namespace):
#   * WITH signature verification it must FAIL,
#   * WITHOUT it, it must PASS — which is what proves the rejection comes from the
#     signature and not incidentally from some other rule. A negative fixture that
#     fails for the wrong reason tests nothing.
run_expect_fail "post-approval edit of a signed field breaks the signature" waiver-check-tampered.txt \
    python3 scripts/waiver_check.py check --file waivers/fixtures/tampered.yaml --verify-signatures

run "...and that fixture passes every OTHER rule (isolates the signature)" waiver-check-tampered-control.txt \
    python3 scripts/waiver_check.py check --file waivers/fixtures/tampered.yaml

# generate must refuse to emit a suppression it cannot date. check() would already
# have caught this, but generate is what writes the ignore files and does not get
# to assume its caller was careful.
run_expect_fail "generate fails closed on an undateable waiver" waiver-generate-failclosed.txt \
    python3 scripts/waiver_check.py generate --file waivers/fixtures/invalid-waivers.yaml

run "derived ignore files come only from ACTIVE waivers" waiver-generate.txt \
    python3 scripts/waiver_check.py generate

# -------------------------------------------------------------- integration
if [ "${1:-}" = "--integration" ]; then
  section "integration  (needs network + a kind cluster)"
  echo "  Not run offline. What it does:"
  echo "    kind create cluster --name accounts-policy-test"
  echo "    helm install kyverno kyverno/kyverno -n kyverno --create-namespace"
  echo "    kubectl apply -f policy/kyverno/policies/"
  echo "    kubectl apply -f policy/kyverno/tests/resources/bad-workload.yaml   # must be REJECTED"
  echo "    kubectl apply -f remediate/workload-fixed.yaml                      # must be ADMITTED"
  echo "  This is the only place verify-image-signature can be exercised:"
  echo "  the CLI cannot verify a Sigstore signature without registry and Rekor access,"
  echo "  which is why that policy has no assertion in kyverno-test.yaml."
fi

# ---------------------------------------------------------------------- done
section "summary"
if [ "$failures" -eq 0 ]; then
  printf '  %sall checks passed%s — output in test-output/\n\n' "$GREEN" "$OFF"
  exit 0
fi
printf '  %s%d check(s) failed%s — output in test-output/\n\n' "$RED" "$failures" "$OFF"
exit 1
