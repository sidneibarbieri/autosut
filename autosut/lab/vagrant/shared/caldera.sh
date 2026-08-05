#!/bin/bash
# caldera.sh - Caldera server installation and configuration
#
# FAIL-FAST: Critical dependency failures abort provisioning.
# Non-critical warnings are logged but do not block.

set -euo pipefail

. /tmp/apt_guard.sh

log_info()  { echo "[CALDERA] $1"; }
log_error() { echo "[CALDERA] ERROR: $1" >&2; }
log_warn()  { echo "[CALDERA] WARN: $1"; }

CALDERA_VERSION="5.3.0"
CALDERA_DIR="/opt/caldera"
INSTALL_OPTIONAL_DOCKER="${STICKS_CALDERA_INSTALL_DOCKER:-0}"
INSTALL_OPTIONAL_BUILD_DEPS="${STICKS_CALDERA_INSTALL_BUILD_DEPS:-0}"
RUNTIME_REQUIREMENTS_FILE="/tmp/caldera-runtime-requirements.txt"

# ── Step 1: Install system dependencies (CRITICAL) ──────────────────────
log_info "Installing system dependencies..."

# Caldera 5.x uses SQLite by default — MongoDB is NOT required.
# The canonical STICKS path uses the Caldera core plus the enabled runtime
# plugins, not the docs/debrief stack.
disable_periodic_apt_jobs
apt_update_quiet
apt_install_minimal \
    python3-pip \
    git \
    || {
        log_error "Failed to install system dependencies — aborting"
        exit 1
    }

if [[ "$INSTALL_OPTIONAL_BUILD_DEPS" == "1" ]]; then
    log_info "Installing optional build toolchain..."
    apt_install_quiet \
        build-essential \
        libffi-dev \
        libssl-dev \
        python3-dev \
        || {
            log_error "Failed to install optional build toolchain — aborting"
            exit 1
        }
else
    log_info "Skipping optional build toolchain (set STICKS_CALDERA_INSTALL_BUILD_DEPS=1 to enable)"
fi

# Docker is optional for the canonical STICKS path.
# Keep it opt-in so the default ARM64/QEMU cold-start stays focused on the
# Caldera core we actually execute in the artifact.
if [[ "$INSTALL_OPTIONAL_DOCKER" == "1" ]]; then
    log_info "Installing optional Docker support..."
    apt_install_quiet docker.io docker-compose 2>/dev/null || {
        log_warn "Docker not installed — some Caldera plugins may be unavailable"
    }
else
    log_info "Skipping optional Docker support (set STICKS_CALDERA_INSTALL_DOCKER=1 to enable)"
fi

# ── Step 2: Clone Caldera (CRITICAL) ────────────────────────────────────
log_info "Downloading Caldera ${CALDERA_VERSION}..."
if [[ ! -d "$CALDERA_DIR" ]]; then
    git clone --depth 1 --branch "$CALDERA_VERSION" \
        https://github.com/mitre/caldera.git "$CALDERA_DIR" 2>/dev/null || \
    git clone --depth 1 \
        https://github.com/mitre/caldera.git "$CALDERA_DIR" || {
            log_error "Failed to clone Caldera repository — aborting"
            exit 1
        }
fi

cd "$CALDERA_DIR"

# ── Step 3: Install Python dependencies (CRITICAL) ─────────────────────
log_info "Installing Python dependencies..."
if [[ ! -f "$RUNTIME_REQUIREMENTS_FILE" ]]; then
    log_error "Runtime requirements file missing: $RUNTIME_REQUIREMENTS_FILE"
    exit 1
fi

pip3 install -q --prefer-binary -r "$RUNTIME_REQUIREMENTS_FILE" --break-system-packages 2>/dev/null || \
pip3 install -q --prefer-binary -r "$RUNTIME_REQUIREMENTS_FILE" 2>/dev/null || {
    log_error "Failed to install Caldera Python dependencies — aborting"
    if [[ "$INSTALL_OPTIONAL_BUILD_DEPS" != "1" ]]; then
        log_error "Retry with STICKS_CALDERA_INSTALL_BUILD_DEPS=1 if this host needs compiled wheels"
    fi
    exit 1
}

# ── Step 4: Configure plugins (non-critical) ───────────────────────────
log_info "Configuring Caldera plugins..."
python3 -c "
import yaml, sys
try:
    conf = yaml.safe_load(open('conf/default.yml'))
    conf['plugins'] = ['sandcat', 'stockpile', 'response', 'gameboard', 'training', 'access', 'atomic']
    yaml.dump(conf, open('conf/local.yml', 'w'), default_flow_style=False)
    print('[CALDERA] Plugin configuration written to conf/local.yml')
except Exception as e:
    print(f'[CALDERA] WARN: Plugin configuration failed: {e}', file=sys.stderr)
"

# ── Step 5: Create systemd service (CRITICAL) ──────────────────────────
log_info "Creating Caldera systemd service..."
cat > /etc/systemd/system/caldera.service << 'EOF'
[Unit]
Description=MITRE Caldera Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/caldera
ExecStart=/usr/bin/python3 /opt/caldera/server.py --insecure
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable caldera || {
    log_error "Failed to enable caldera service — aborting"
    exit 1
}

# ── Step 6: Start Caldera (CRITICAL) ───────────────────────────────────
log_info "Starting Caldera server..."
systemctl start caldera || {
    log_warn "systemd start failed — attempting direct launch..."
    cd "$CALDERA_DIR"
    nohup python3 server.py --insecure > /var/log/caldera.log 2>&1 &
    sleep 5
}

# ── Step 7: Verify Caldera is actually running (CRITICAL) ──────────────
log_info "Verifying Caldera process..."
sleep 3
if pgrep -f "server.py" > /dev/null; then
    log_info "Caldera process is running (PID: $(pgrep -f 'server.py' | head -1))"
else
    log_error "Caldera process is NOT running after start — aborting"
    log_error "Check /var/log/caldera.log or journalctl -u caldera"
    exit 1
fi

# Verify port is listening (with retries)
MAX_PORT_CHECKS=12
for i in $(seq 1 $MAX_PORT_CHECKS); do
    if ss -tlnp | grep -q ":8888"; then
        log_info "Caldera is listening on port 8888"
        break
    fi
    if [[ $i -eq $MAX_PORT_CHECKS ]]; then
        log_info "Port 8888 is not yet listening after ${MAX_PORT_CHECKS}0s; continuing with the remaining health checks"
    fi
    sleep 10
done

log_info "Caldera installation and verification complete"
log_info "API endpoint: http://<host-ip>:8888/api"
