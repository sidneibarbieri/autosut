#!/bin/bash
# collect_evidence.sh - Summarize canonical evidence directory
# Usage: ./collect_evidence.sh
#
# NOTE:
#   Canonical evidence is produced directly in:
#     release/evidence/<campaign_timestamp>/
#   by scripts/run_campaign.py.
#   This script does not copy from legacy paths.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
EVIDENCE_DIR="$ROOT_DIR/release/evidence"
MATRIX_SCRIPT="$ROOT_DIR/scripts/generate_campaign_matrix.py"
PAPER_READY_SCRIPT="$ROOT_DIR/scripts/generate_paper_ready_artifacts.py"

echo "======================================================================"
echo "STICKS Evidence Summary"
echo "======================================================================"

if [[ -d "$EVIDENCE_DIR" ]]; then
    LATEST_SUMMARIES=$(find "$EVIDENCE_DIR" -name "summary.json" -type f -exec ls -t {} + | head -10)

    if [[ -z "$LATEST_SUMMARIES" ]]; then
        echo "No evidence summaries found in $EVIDENCE_DIR"
        exit 1
    fi

    echo "Latest evidence runs:"
    while read -r summary; do
        [[ -n "$summary" ]] || continue
        run_dir="$(dirname "$summary")"
        run_name="$(basename "$run_dir")"
        echo "  - $run_name"
        python3 - <<PYEOF
import json
with open("$summary", "r", encoding="utf-8") as f:
    data = json.load(f)
print(f"      campaign={data.get('campaign_id','?')} success={data.get('successful',0)}/{data.get('total_techniques',0)} fidelity={data.get('fidelity_distribution',{})}")
PYEOF
    done <<< "$LATEST_SUMMARIES"

    if [[ -f "$MATRIX_SCRIPT" ]]; then
        echo ""
        echo "Refreshing consolidated campaign-SUT-fidelity matrix..."
        python3 "$MATRIX_SCRIPT"
    fi

    if [[ -f "$PAPER_READY_SCRIPT" ]]; then
        echo ""
        echo "Generating paper-ready traceability and macros..."
        python3 "$PAPER_READY_SCRIPT"
    fi

    echo ""
    echo "======================================================================"
    echo "Evidence directory: $EVIDENCE_DIR"
    echo "======================================================================"
else
    echo "No canonical evidence directory found. Run a campaign first:"
    echo "  python3 scripts/run_campaign.py --campaign 0.c0011"
    exit 1
fi
