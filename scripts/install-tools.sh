#!/usr/bin/env bash
# Fetch the four pinned binaries the offline policy suite needs, into ./bin.
#
#   ./scripts/install-tools.sh && export PATH="$PWD/bin:$PATH"
#   ./scripts/run-policy-tests.sh
#
# Nothing is installed system-wide and nothing needs a package manager, so a
# reviewer can run the suite and then delete one directory. Versions are pinned
# to the ones the committed output in test-output/ was produced with — a policy
# suite that passes on a different engine version has proven less than it looks.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p bin && cd bin

KYVERNO=1.13.4
CONFTEST=0.56.0
COSIGN=2.4.1
GITLEAKS=8.21.2

case "$(uname -s)" in
  Darwin) OS=darwin; CONFTEST_OS=Darwin ;;
  Linux)  OS=linux;  CONFTEST_OS=Linux  ;;
  *) echo "unsupported OS: $(uname -s)"; exit 1 ;;
esac
case "$(uname -m)" in
  arm64|aarch64) ARCH=arm64; KARCH=arm64; CARCH=arm64; GLARCH=arm64 ;;
  x86_64|amd64)  ARCH=amd64; KARCH=x86_64; CARCH=x86_64; GLARCH=x64 ;;
  *) echo "unsupported arch: $(uname -m)"; exit 1 ;;
esac

get() { echo "  $1"; curl -fsSL -o "$2" "$1"; }

echo "installing into $(pwd) for ${OS}/${ARCH}"

get "https://github.com/kyverno/kyverno/releases/download/v${KYVERNO}/kyverno-cli_v${KYVERNO}_${OS}_${KARCH}.tar.gz" k.tgz
tar xzf k.tgz kyverno && rm -f k.tgz

get "https://github.com/open-policy-agent/conftest/releases/download/v${CONFTEST}/conftest_${CONFTEST}_${CONFTEST_OS}_${CARCH}.tar.gz" c.tgz
tar xzf c.tgz conftest && rm -f c.tgz LICENSE README.md 2>/dev/null || true

get "https://github.com/sigstore/cosign/releases/download/v${COSIGN}/cosign-${OS}-${ARCH}" cosign
chmod +x cosign

get "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS}/gitleaks_${GITLEAKS}_${OS}_${GLARCH}.tar.gz" g.tgz
tar xzf g.tgz gitleaks && rm -f g.tgz LICENSE README.md 2>/dev/null || true

chmod +x kyverno conftest gitleaks cosign
python3 -c "import yaml" 2>/dev/null || echo "  note: 'pip install pyyaml' is still needed for the waiver checker"

echo
echo "done. now:"
echo "  export PATH=\"\$(cd .. && pwd)/bin:\$PATH\""
echo "  ./scripts/run-policy-tests.sh"
