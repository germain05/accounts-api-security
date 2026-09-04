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

# ------------------------------------------------------- Kubernetes admission
section "Kyverno admission policies  (section 4a + 5)"
run "kyverno test — 3 fixtures, 39 assertions" kyverno-test.txt \
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

# ------------------------------------------------------------------ waivers
section "Waiver mechanism  (section 3)"
run "valid waivers: schema, approver, lifetime, expiry, signature" waiver-check.txt \
    python3 scripts/waiver_check.py check --verify-signatures

run_expect_fail "expired / self-approved / over-cap / unwaivable-secret" waiver-check-invalid.txt \
    python3 scripts/waiver_check.py check --file waivers/fixtures/invalid-waivers.yaml

run_expect_fail "post-approval edit of \`expires\` breaks the signature" waiver-check-tampered.txt \
    python3 scripts/waiver_check.py check --file waivers/fixtures/tampered.yaml --verify-signatures

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
