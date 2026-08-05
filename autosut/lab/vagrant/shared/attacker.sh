#!/bin/bash
# attacker.sh - Attacker tools installation

set -euo pipefail

. /tmp/apt_guard.sh

log_info() { echo "[ATTACKER] $1"; }
log_error() { echo "[ATTACKER] ERROR: $1" >&2; }

INSTALL_EXTENDED_TOOLS="${STICKS_ATTACKER_INSTALL_EXTENDED_TOOLS:-0}"

log_info "Installing attacker core tools..."

disable_periodic_apt_jobs

apt_install_minimal \
    nmap \
    netcat-openbsd \
    curl \
    wget \
    openssh-client \
    python3-requests \
    sshpass || {
        log_error "Failed to install attacker core tools"
        exit 1
    }

if [[ "$INSTALL_EXTENDED_TOOLS" == "1" ]]; then
    log_info "Installing extended attacker tools..."
    apt_install_quiet \
        hydra \
        john \
        hashcat \
        sqlmap \
        gobuster \
        dirb \
        whatweb || {
            log_error "Failed to install extended attacker tools"
            exit 1
        }
else
    log_info "Skipping extended attacker tools (set STICKS_ATTACKER_INSTALL_EXTENDED_TOOLS=1 to enable)"
fi

# Install Caldera agent (Sandcat)
log_info "Installing Caldera agent..."
mkdir -p /opt/caldera-agent
cd /opt/caldera-agent

# Download sandcat
if wget -q http://192.168.56.10:8888/file/download/sandcat.go; then
    log_info "Downloaded Sandcat seed agent"
else
    log_info "Sandcat will be downloaded at runtime"
fi

# Create helper scripts
log_info "Creating helper scripts..."
cat > /usr/local/bin/deploy-agent.sh << 'EOF'
#!/bin/bash
# Deploy Caldera agent to target
TARGET=$1
echo "Deploying agent to $TARGET..."
scp /opt/caldera-agent/sandcat.go "vagrant@$TARGET:/tmp/" 2>/dev/null || \
    echo "Agent deployment requires manual step"
EOF

chmod +x /usr/local/bin/deploy-agent.sh

# Add lab user with password (for campaign access)
log_info "Setting up lab user..."
if ! id -u attacker >/dev/null 2>&1; then
    useradd -m -s /bin/bash attacker
fi
echo "attacker:attacker123" | chpasswd

# Create SSH keys for campaign use
mkdir -p /home/attacker/.ssh
if [[ ! -f /home/attacker/.ssh/id_rsa ]]; then
    ssh-keygen -t rsa -f /home/attacker/.ssh/id_rsa -N ""
fi
chown -R attacker:attacker /home/attacker/.ssh

log_info "Attacker configuration complete"
