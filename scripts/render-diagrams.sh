#!/usr/bin/env bash
# Re-render the trust-boundary diagram from its Mermaid source.
#
# The .mmd source is the artefact of record; the .svg and .png are generated so
# the diagram survives into contexts that do not draw Mermaid — PDF exports,
# some editors, and the assessment form's uploader.
#
#   npm install -g @mermaid-js/mermaid-cli
#   ./scripts/render-diagrams.sh
set -euo pipefail
cd "$(dirname "$0")/.."
command -v mmdc >/dev/null || { echo "mmdc not found: npm install -g @mermaid-js/mermaid-cli"; exit 1; }
mmdc -i docs/img/trust-boundaries.mmd -o docs/img/trust-boundaries.svg -b white
mmdc -i docs/img/trust-boundaries.mmd -o docs/img/trust-boundaries.png -b white -w 1600
echo "rendered docs/img/trust-boundaries.{svg,png}"
