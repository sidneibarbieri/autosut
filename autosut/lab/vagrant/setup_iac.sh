#!/bin/bash
# IaC Setup and Validation Script
# Sets up and validates the complete IaC environment

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOFTWARE_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== IaC Environment Setup ==="

# Check dependencies
echo "Checking dependencies..."
command -v vagrant >/dev/null 2>&1 || {
    echo "ERROR: Vagrant not found"
    exit 1
}

command -v virsh >/dev/null 2>&1 || {
    echo "ERROR: virsh not found"
    exit 1
}

# Start libvirt if needed
echo "Checking libvirt status..."
if ! virsh list >/dev/null 2>&1; then
    echo "Starting libvirt..."
    sudo systemctl start libvirtd
    sudo systemctl enable libvirtd
fi

# Setup Vagrant plugins
echo "Checking Vagrant plugins..."
if ! vagrant plugin list | grep -q vagrant-libvirt; then
    echo "Installing vagrant-libvirt plugin..."
    vagrant plugin install vagrant-libvirt
fi

# Generate Vagrantfile
echo "Generating Vagrantfile..."
cd "$SOFTWARE_DIR"
python3 generate_iac_configs.py

# Start IaC environment
echo "Starting IaC environment..."
cd lab/vagrant
vagrant up

# Validate environment
echo "Validating IaC environment..."
echo "Target VM status:"
vagrant ssh target -c "hostname && whoami && pwd"

echo "Attacker VM status:"
vagrant ssh attacker -c "hostname && whoami && pwd"

# Test connectivity
echo "Testing connectivity..."
vagrant ssh attacker -c "ping -c 1 192.168.56.10"

echo "=== IaC Setup Complete ==="
echo "Environment ready for campaign execution"
echo "Use: ./execute_campaign.sh [CAMPAIGN_ID]"
