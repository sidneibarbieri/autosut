#!/usr/bin/env bash
# run_baseline.sh - run a reproducible baseline campaign.
# Usage: ./run_baseline.sh [campaign_id]
# Example: ./run_baseline.sh 0.c0011

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

CAMPAIGN_ID="${1:-0.c0011}"

# Map campaign_id to the corresponding runner.
if [[ "$CAMPAIGN_ID" == "0.c0011" ]]; then
    RUNNER="$SCRIPT_DIR/campaign_runner.py"
elif [[ "$CAMPAIGN_ID" == "0.pikabot_distribution_february_2024" ]]; then
    RUNNER="$SCRIPT_DIR/campaign_runner_0pikabot.py"
else
    echo "FAIL unsupported campaign: $CAMPAIGN_ID"
    echo "Available campaigns: 0.c0011, 0.pikabot_distribution_february_2024"
    exit 1
fi

echo "==================================================================="
echo "BASELINE LOCAL EXECUTION"
echo "==================================================================="
echo "Campaign: $CAMPAIGN_ID"
echo "Runner: $(basename "$RUNNER")"
echo "==================================================================="
echo ""

# Execute the runner.
if [[ -f "$RUNNER" ]]; then
    python3 "$RUNNER"
else
    echo "FAIL runner not found: $RUNNER"
    exit 1
fi

echo ""
echo "==================================================================="
echo "OK execution complete"
echo "Inspect results with: ./inspect_last_execution.sh $CAMPAIGN_ID"
echo "==================================================================="
