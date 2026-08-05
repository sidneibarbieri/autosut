#!/bin/bash
# reset.sh - Legacy wrapper for canonical teardown
# Canonical flow:
#   1) ./destroy_lab.sh
#   2) ./run_campaign.sh <campaign_id>

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "[reset.sh] DEPRECATED: performing canonical teardown only"
"$SCRIPT_DIR/destroy_lab.sh" "$@"

echo ""
echo "Next:"
echo "  ./run_campaign.sh 0.c0011"
