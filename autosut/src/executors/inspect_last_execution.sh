#!/usr/bin/env bash
# inspect_last_execution.sh - inspect the latest campaign execution.
# Usage: ./inspect_last_execution.sh [campaign_id]
# Example: ./inspect_last_execution.sh 0.c0011

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EVIDENCE_DIR="${SCRIPT_DIR}/../../data/campaign_evidence"

CAMPAIGN_ID="${1:-}"

if [[ -z "$CAMPAIGN_ID" ]]; then
    # List recently available campaign evidence directories.
    echo "Available campaigns:"
    find "$EVIDENCE_DIR" -maxdepth 1 -type d -name '*_*' | sort -t_ -k3,3 -k4,4 | tail -5 | while read -r dir; do
        basename "$dir"
    done
    echo ""
    echo "Usage: $0 <campaign_id>"
    echo "Example: $0 0.c0011"
    exit 1
fi

# Find the most recent evidence directory for the campaign.
LATEST_DIR=$(find "$EVIDENCE_DIR" -maxdepth 1 -type d -name "${CAMPAIGN_ID}_*" | sort -t_ -k3,3 -k4,4 | tail -1)

if [[ -z "$LATEST_DIR" ]]; then
    echo "FAIL no evidence found for campaign: $CAMPAIGN_ID"
    exit 1
fi

echo "==================================================================="
echo "EXECUTION INSPECTION: $(basename "$LATEST_DIR")"
echo "==================================================================="
echo ""

# Validate the expected evidence structure.
MANIFEST="$LATEST_DIR/manifest.json"
SUMMARY="$LATEST_DIR/summary.json"
PER_TECHNIQUE="$LATEST_DIR/per_technique"

if [[ ! -f "$MANIFEST" ]]; then
    echo "FAIL manifest.json not found"
    exit 1
fi

if [[ ! -f "$SUMMARY" ]]; then
    echo "FAIL summary.json not found"
    exit 1
fi

# Display summary.
python3 - <<PY
import json
import sys

with open("$SUMMARY") as f:
    data = json.load(f)

print(f"Campaign: {data['campaign_name']}")
print(f"Status: {data['status'].upper()}")
print(f"Techniques: {data['successful_techniques']}/{data['total_techniques']} successful")
print(f"Duration: {data['execution_duration_seconds']:.1f}s")
print(f"Start: {data['start_time']}")
print("")

# Technique table.
print("EXECUTED TECHNIQUES:")
print("-" * 70)
for t in data['manifest']['techniques']:
    icon = "OK" if t['status'] == 'success' else "FAIL"
    mode = t['execution_mode']
    print(f"{icon} {t['technique_id']:<12} ({mode:<18}) - {t['technique_name']}")
print("-" * 70)
PY

echo ""
echo "Created artifacts:"
python3 - <<PY
import json
with open("$MANIFEST") as f:
    data = json.load(f)
for artifact in data['artifacts_created'][:10]:
    print(f"  - {artifact}")
if len(data['artifacts_created']) > 10:
    print(f"  ... and {len(data['artifacts_created']) - 10} more artifacts")
PY

echo ""
echo "Full directory: $LATEST_DIR"
echo "==================================================================="
