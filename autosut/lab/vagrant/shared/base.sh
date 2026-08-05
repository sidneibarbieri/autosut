#!/bin/bash
# base.sh - Base configuration for all VMs
#
# FAIL-FAST: Package installation is critical — abort on failure.

set -euo pipefail

. /tmp/apt_guard.sh

log_info()  { echo "[BASE] $1"; }
log_error() { echo "[BASE] ERROR: $1" >&2; }

disable_periodic_apt_jobs

log_info "Updating system..."
apt_update_quiet || {
    log_error "apt-get update failed — aborting"
    exit 1
}

log_info "Installing base packages..."
apt_install_minimal \
    curl \
    wget \
    iputils-ping \
    python3 \
    openssh-server \
    sudo \
    || {
        log_error "Failed to install base packages — aborting"
        exit 1
    }

log_info "Configuring SSH..."
systemctl enable ssh || {
    log_error "Failed to enable SSH — aborting"
    exit 1
}
systemctl start ssh || systemctl restart ssh || {
    log_error "Failed to start SSH — aborting"
    exit 1
}

log_info "Setting up hosts file..."
# Avoid duplicate entries on re-provision
if ! grep -q "caldera-server" /etc/hosts 2>/dev/null; then
    cat >> /etc/hosts << 'EOF'
192.168.56.10   caldera caldera-server
192.168.56.20   attacker attacker-linux
192.168.56.30   target1 target-linux-1
192.168.56.31   target2 target-linux-2
EOF
fi

log_info "Base configuration complete"
