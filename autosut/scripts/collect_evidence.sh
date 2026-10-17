#!/bin/bash
# collect_evidence.sh - Summarize locally generated execution records
# Usage: ./collect_evidence.sh
#
# Records produced by scripts/run_campaign.py are stored under
# release/evidence/<campaign_timestamp>/. They are useful for local diagnosis,
# but do not alter the sealed canonical claim ledger.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
EVIDENCE_DIR="$ROOT_DIR/release/evidence"
echo "======================================================================"
echo "AutoSUT Local Execution Record Summary"
echo "======================================================================"

if [[ -d "$EVIDENCE_DIR" ]]; then
    LATEST_SUMMARIES=$(find "$EVIDENCE_DIR" -name "summary.json" -type f -exec ls -t {} + | head -10)

    if [[ -z "$LATEST_SUMMARIES" ]]; then
        echo "No evidence summaries found in $EVIDENCE_DIR"
        exit 1
    fi

    echo "Most recent local execution records (not canonical claim evidence):"
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

    echo ""
    echo "======================================================================"
    echo "Local execution record directory: $EVIDENCE_DIR"
    echo "Canonical claim authority: release/CLAIM_EVIDENCE_TRACEABILITY.md"
    echo "======================================================================"
else
    echo "No canonical evidence directory found. Run a campaign first:"
    echo "  python3 scripts/run_campaign.py --campaign 0.c0011"
    exit 1
fi
