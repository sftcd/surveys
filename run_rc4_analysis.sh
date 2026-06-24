#!/bin/bash
# Run the full RC4 / TLS Hygiene Index analysis pipeline.
# Must be run from the surveys/ directory with the venv active.
#
# Usage:
#   source venv/bin/activate
#   bash run_rc4_analysis.sh
#
# The script auto-detects the most recent results/<CC>-<timestamp>/ folder.
# To use a specific folder:
#   bash run_rc4_analysis.sh results/IE-20260317-171424

set -e

SRCDIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SRCDIR"

# ── Locate results directory ──────────────────────────────────────────────────
if [ -n "$1" ]; then
    RESDIR="$1"
else
    RESDIR=$(ls -td results/*/ 2>/dev/null | head -1)
    RESDIR="${RESDIR%/}"
fi

if [ -z "$RESDIR" ] || [ ! -d "$RESDIR" ]; then
    echo "ERROR: no results directory found. Run a scan first, or pass the path as an argument."
    echo "  bash run_rc4_analysis.sh results/IE-20260317-171424"
    exit 1
fi

echo "Using results directory: $RESDIR"
echo

RECORDS="$RESDIR/records.fresh"
RC4_JSON="rc4/rc4_analysis.json"

mkdir -p rc4

run() {
    echo ">>> $*"
    python3 "$@"
    echo "    done."
    echo
}

echo "=== Step 1: RC4 extraction ==="
run rc4_analysis.py -i "$RECORDS" -o "$RC4_JSON"

echo "=== Step 2: TLS Hygiene Index pipeline ==="
run rc4_hygiene_pipeline.py --records "$RECORDS" --rc4 "$RC4_JSON" --results "$RESDIR"

echo "=== Step 3: Figures ==="
run rc4_figures.py --results "$RESDIR"

echo "All done. Outputs in rc4/ and rc4_hygiene_charts/"
