#!/bin/bash
# Run the full RC4 / TLS Hygiene Index analysis pipeline.
# Must be run from the surveys/ directory with the venv active,
# and results/IE-20260317-171424/ present.
#
# Usage:
#   source venv/bin/activate
#   bash run_rc4_analysis.sh

set -e

SRCDIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SRCDIR"

run() {
    echo ">>> $1"
    python3 "$1"
    echo "    done."
    echo
}

run rc4_hygiene_pipeline.py
run rc4_figures.py

echo "All done. Outputs in rc4/ and rc4_hygiene_charts/"
