#!/bin/bash
# apt_guard.sh - Deterministic apt/dpkg helpers for reproducible VM provisioning

set -euo pipefail

apt_guard_log() { echo "[APT-GUARD] $1"; }
apt_guard_error() { echo "[APT-GUARD] ERROR: $1" >&2; }

disable_periodic_apt_jobs() {
    export DEBIAN_FRONTEND=noninteractive

    cat > /etc/apt/apt.conf.d/99sticks-no-periodic <<'EOF'
APT::Periodic::Enable "0";
APT::Periodic::Update-Package-Lists "0";
APT::Periodic::Unattended-Upgrade "0";
EOF

    systemctl stop unattended-upgrades.service >/dev/null 2>&1 || true
    systemctl disable unattended-upgrades.service >/dev/null 2>&1 || true
}

wait_for_apt_ready() {
    local timeout_seconds="${1:-300}"
    local start_time
    start_time="$(date +%s)"

    while pgrep -f unattended-upgrade >/dev/null 2>&1 \
        || pgrep -x apt-get >/dev/null 2>&1 \
        || pgrep -x apt >/dev/null 2>&1 \
        || pgrep -x dpkg >/dev/null 2>&1; do
        if (( $(date +%s) - start_time >= timeout_seconds )); then
            apt_guard_error "Timed out waiting for apt/dpkg locks to clear"
            return 1
        fi

        apt_guard_log "Waiting for apt/dpkg locks to clear..."
        sleep 5
    done
}

apt_update_quiet() {
    wait_for_apt_ready
    apt-get update -qq
}

apt_install_quiet() {
    wait_for_apt_ready
    apt-get install -y -qq "$@"
}

apt_install_minimal() {
    wait_for_apt_ready
    apt-get install -y -qq --no-install-recommends "$@"
}
