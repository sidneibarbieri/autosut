#!/bin/bash
# =============================================================================
# Start Campaign Execution Environment
#
# This script:
# 1. Starts Vagrant VMs (Caldera + targets)
# 2. Waits for Caldera to be ready
# 3. Executes campaigns
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
cd "$PROJECT_ROOT/measurement/sut"

echo "=== Starting Campaign Execution Environment ==="

# Start Vagrant
echo "[1/3] Starting Vagrant VMs..."
vagrant up

# Wait for Caldera
echo "[2/3] Waiting for Caldera to be ready..."
MAX_RETRIES=30
RETRY_COUNT=0

while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    if curl -s http://localhost:8888 > /dev/null 2>&1; then
        echo "Caldera is ready!"
        break
    fi
    echo "  Waiting... ($RETRY_COUNT/$MAX_RETRIES)"
    sleep 10
    RETRY_COUNT=$((RETRY_COUNT + 1))
done

if [ $RETRY_COUNT -eq $MAX_RETRIES ]; then
    echo "ERROR: Caldera did not start in time"
    exit 1
fi

# Execute campaigns
echo "[3/3] Executing campaigns..."
python3 "$SCRIPT_DIR/execute_campaign.py" \
    --campaign 0.solarwinds_compromise \
    --runs 5

echo "=== Environment Ready ==="
echo "Caldera: http://localhost:8888"
