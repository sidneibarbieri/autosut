#!/bin/bash
# Campaign Execution Script for IaC Environment
# Executes true MITRE campaigns in Vagrant environment

set -e

CAMPAIGN_ID=${1:-"C0001"}
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOFTWARE_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== MITRE ATT&CK Campaign Execution ==="
echo "Campaign: $CAMPAIGN_ID"
echo "Software Dir: $SOFTWARE_DIR"

# Check if Vagrant is running
echo "Checking Vagrant environment..."
cd "$SCRIPT_DIR"

if ! vagrant status | grep -q "running"; then
    echo "Starting Vagrant environment..."
    vagrant up
else
    echo "Vagrant environment already running"
fi

# Verify VMs are accessible
echo "Verifying VM connectivity..."
vagrant ssh target -c "echo 'Target VM accessible'" || {
    echo "ERROR: Target VM not accessible"
    exit 1
}

vagrant ssh attacker -c "echo 'Attacker VM accessible'" || {
    echo "ERROR: Attacker VM not accessible"
    exit 1
}

# Execute campaign
echo "Executing campaign $CAMPAIGN_ID..."
cd "$SOFTWARE_DIR"

python3 scripts/run_campaign.py --campaign "$CAMPAIGN_ID"

echo "=== Campaign Execution Complete ==="
echo "Check release/evidence/ for execution results"
