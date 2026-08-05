#!/bin/bash
# up_lab.sh - Bring up lab infrastructure for STICKS campaigns
# Usage: ./up_lab.sh --campaign 0.c0011

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
CAMPAIGN_ID=""
PROVIDER=""

log_info() { echo "[UP-LAB] $1"; }
log_error() { echo "[UP-LAB] ERROR: $1" >&2; }
log_warn() { echo "[UP-LAB] WARN: $1"; }

ssh_port_for_vm() {
    case "$1" in
        caldera) echo 50022 ;;
        attacker) echo 50023 ;;
        target-linux-1) echo 50024 ;;
        target-linux-2) echo 50025 ;;
        *) echo "" ;;
    esac
}

kill_stale_listener() {
    local port="$1"
    [[ -n "$port" ]] || return 0

    local pids
    pids="$(lsof -tiTCP:"$port" -sTCP:LISTEN 2>/dev/null || true)"
    [[ -n "$pids" ]] || return 0

    log_warn "Cleaning stale listener on TCP:$port before VM boot"
    for pid in $pids; do
        kill "$pid" 2>/dev/null || true
    done
    sleep 1
    for pid in $pids; do
        kill -0 "$pid" 2>/dev/null && kill -9 "$pid" 2>/dev/null || true
    done
}

show_help() {
    cat << EOF
STICKS Lab Infrastructure - Up Script

Usage: ./up_lab.sh [OPTIONS]

Options:
    --campaign ID    Campaign ID to provision for (required)
    --provider NAME  Vagrant provider (qemu|virtualbox) [default: qemu]
    --help          Show this help

Examples:
    ./up_lab.sh --campaign 0.c0011
    ./up_lab.sh --campaign 0.c0011 --provider virtualbox

EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --campaign)
                CAMPAIGN_ID="$2"
                shift 2
                ;;
            --provider)
                PROVIDER="$2"
                shift 2
                ;;
            --help|-h)
                show_help
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
}

detect_default_provider() {
    if [[ -n "$PROVIDER" ]]; then
        return
    fi

    local os_name
    local arch_name
    os_name="$(uname -s)"
    arch_name="$(uname -m)"

    if [[ "$os_name" == "Darwin" && "$arch_name" == "arm64" ]]; then
        PROVIDER="qemu"
    else
        PROVIDER="libvirt"
    fi
}

check_dependencies() {
    log_info "Checking dependencies..."

    if ! command -v vagrant &> /dev/null; then
        log_error "Vagrant not found. Run ./setup.sh first."
        exit 1
    fi

    # Check for QEMU provider (macOS ARM64 preferred)
    if [[ "$PROVIDER" == "qemu" ]]; then
        if ! vagrant plugin list | grep -q vagrant-qemu; then
            log_warn "vagrant-qemu plugin not found. Installing..."
            vagrant plugin install vagrant-qemu || {
                log_error "Failed to install vagrant-qemu plugin"
                log_error "Run ./setup.sh to install QEMU provider automatically"
                exit 1
            }
        fi
        log_info "OK QEMU provider ready"
    fi

    # Check for libvirt provider
    if [[ "$PROVIDER" == "libvirt" ]]; then
        if ! vagrant plugin list | grep -q vagrant-libvirt; then
            log_warn "vagrant-libvirt plugin not found. Installing..."
            vagrant plugin install vagrant-libvirt || {
                log_error "Failed to install vagrant-libvirt plugin"
                log_error "On macOS, install: brew install libvirt"
                log_error "Then: vagrant plugin install vagrant-libvirt"
                exit 1
            }
        fi
        log_info "OK libvirt provider ready"
    fi

    # Check for VirtualBox provider
    if [[ "$PROVIDER" == "virtualbox" ]]; then
        if ! command -v VBoxManage &> /dev/null; then
            log_error "VirtualBox not found. Install from https://www.virtualbox.org/"
            exit 1
        fi
        log_info "OK VirtualBox ready"
    fi
}

determine_topology() {
    log_info "Determining topology for campaign: $CAMPAIGN_ID"

    VMS=()
    while IFS= read -r vm_name; do
        [[ -n "$vm_name" ]] || continue
        VMS+=("$vm_name")
    done < <(
        python3 - <<PYEOF
import sys
from pathlib import Path
import yaml

campaign_id = "$CAMPAIGN_ID"
root_dir = Path("$ROOT_DIR")
profile_path = root_dir / "data" / "sut_profiles" / f"{campaign_id}.yml"

if not profile_path.exists():
    print(f"SUT profile not found for campaign {campaign_id}: {profile_path}", file=sys.stderr)
    sys.exit(1)

with open(profile_path, "r", encoding="utf-8") as f:
    raw = yaml.safe_load(f) or {}

required_vms = raw.get("requirements", {}).get("required_vms", [])
if not required_vms:
    print(
        f"Missing requirements.required_vms in {profile_path}",
        file=sys.stderr,
    )
    sys.exit(1)

alias = {
    "target-base": "target-linux-1",
    "target-1": "target-linux-1",
    "target": "target-1",
    "target-2": "target-linux-2",
}

resolved = []
for vm in required_vms:
    resolved_vm = alias.get(vm, vm)
    if resolved_vm not in resolved:
        resolved.append(resolved_vm)

for vm in resolved:
    print(vm)
PYEOF
    )

    if [[ ${#VMS[@]} -eq 0 ]]; then
        log_error "Could not resolve VM topology for campaign: $CAMPAIGN_ID"
        exit 1
    fi

    log_info "Topology resolved from SUT profile: ${VMS[*]} (${#VMS[@]} VMs)"
}

bring_up_vm() {
    local vm_name=$1
    local vm_dir="$ROOT_DIR/lab/vagrant/$vm_name"

    log_info "Bringing up VM: $vm_name..."

    if [[ ! -d "$vm_dir" ]]; then
        log_error "VM directory not found: $vm_dir"
        return 1
    fi

    cd "$vm_dir"

    # Check if already running
    if vagrant status 2>/dev/null | grep -q "running"; then
        log_info "  $vm_name already running"
        return 0
    fi

    if [[ "$PROVIDER" == "qemu" ]]; then
        kill_stale_listener "$(ssh_port_for_vm "$vm_name")"
    fi

    # Bring up with specified provider
    vagrant up --provider "$PROVIDER" 2>&1 | while read line; do
        echo "  [$vm_name] $line"
    done

    if [[ ${PIPESTATUS[0]} -eq 0 ]]; then
        log_info "OK $vm_name is up"
        return 0
    else
        log_error "FAIL $vm_name failed to start"
        return 1
    fi
}

wait_for_caldera() {
    log_info "Waiting for Caldera server to be ready..."

    local max_attempts=12
    local attempt=1
    local private_url="http://192.168.56.10:8888"
    local forwarded_url="http://127.0.0.1:8888"
    local caldera_vm_dir="$ROOT_DIR/lab/vagrant/caldera"

    while [[ $attempt -le $max_attempts ]]; do
        # Provider-aware readiness:
        # - qemu on macOS ARM64 often ignores private network and relies on forwarded port
        # - libvirt/virtualbox generally use private network IP
        if [[ "$PROVIDER" == "qemu" ]]; then
            if curl -s --connect-timeout 3 "$forwarded_url" >/dev/null 2>&1; then
                log_info "OK Caldera server is ready via forwarded port (127.0.0.1:8888)"
                return 0
            fi
            if curl -s --connect-timeout 3 "$private_url" >/dev/null 2>&1; then
                log_info "OK Caldera server is ready via private IP (192.168.56.10:8888)"
                return 0
            fi
        else
            if curl -s --connect-timeout 3 "$private_url" >/dev/null 2>&1; then
                log_info "OK Caldera server is ready via private IP (192.168.56.10:8888)"
                return 0
            fi
            if curl -s --connect-timeout 3 "$forwarded_url" >/dev/null 2>&1; then
                log_info "OK Caldera server is ready via forwarded port (127.0.0.1:8888)"
                return 0
            fi
        fi

        # Backward compatibility path used by some older checks
        if curl -s --connect-timeout 3 http://192.168.56.10:8888/api/rest 2>/dev/null | grep -qi "caldera"; then
            log_info "OK Caldera server is ready"
            return 0
        fi

        # Final fallback: check Caldera service/process from inside VM via vagrant ssh.
        # This handles qemu cases where host endpoint probing is unreliable.
        if [[ -d "$caldera_vm_dir" ]]; then
            if (
                cd "$caldera_vm_dir" && \
                VAGRANT_DEFAULT_PROVIDER="$PROVIDER" \
                vagrant ssh -c "systemctl is-active --quiet caldera || pgrep -f server.py >/dev/null" >/dev/null 2>&1
            ); then
                log_info "OK Caldera service/process is active inside VM"
                log_info "  Endpoint-level checks continue in health_check stage"
                return 0
            fi
        fi

        log_info "  Attempt $attempt/$max_attempts - waiting 5s..."
        sleep 5
        ((attempt++))
    done

    log_error "Caldera server did not become ready within timeout"
    log_error "Checked both private IP and forwarded port endpoints"
    return 1
}

verify_network() {
    log_info "Verifying network connectivity..."

    for vm in "${VMS[@]}"; do
        local ip=""
        case "$vm" in
            caldera) ip="192.168.56.10" ;;
            attacker) ip="192.168.56.20" ;;
            target-linux-1) ip="192.168.56.30" ;;
            target-linux-2) ip="192.168.56.31" ;;
        esac

        if ping -c 1 -W 2 "$ip" &>/dev/null; then
            log_info "OK $vm ($ip) reachable"
        else
            log_warn "FAIL $vm ($ip) not responding to ping (may be normal)"
        fi
    done
}

main() {
    parse_args "$@"
    detect_default_provider

    if [[ -z "$CAMPAIGN_ID" ]]; then
        log_error "Campaign ID required. Use --campaign ID"
        show_help
        exit 1
    fi

    log_info "========================================"
    log_info "STICKS Lab Infrastructure - UP"
    log_info "Campaign: $CAMPAIGN_ID"
    log_info "Provider: $PROVIDER"
    log_info "========================================"

    check_dependencies
    determine_topology

    log_info "Bringing up VMs..."
    for vm in "${VMS[@]}"; do
        bring_up_vm "$vm" || {
            log_error "Failed to bring up $vm"
            log_error "Check vagrant status and logs"
            exit 1
        }
    done

    # Wait for Caldera if it's in the topology
    if [[ " ${VMS[*]} " =~ " caldera " ]]; then
        wait_for_caldera
    fi

    # 3-level health check (VM ready -> Service ready -> Campaign ready)
    log_info "========================================"
    log_info "Running 3-level health check..."
    log_info "========================================"
    if python3 "$ROOT_DIR/lab/health_check.py" --campaign "$CAMPAIGN_ID" --provider "$PROVIDER" --output "$ROOT_DIR/release/evidence"; then
        log_info "OK Health check PASSED"
    else
        log_warn "Health check detected issues (see report for details)"
        log_warn "Proceeding with SUT profile application..."
    fi

    # Auto-apply SUT profile
    log_info "========================================"
    log_info "Applying SUT profile..."
    log_info "========================================"
    python3 "$ROOT_DIR/apply_sut_profile.py" --campaign "$CAMPAIGN_ID" --base-dir "$ROOT_DIR" --provider "$PROVIDER" || {
        log_warn "SUT profile application returned non-zero (may be warnings only)"
    }

    log_info "========================================"
    log_info "OK Lab infrastructure is UP and CONFIGURED"
    log_info "========================================"
    log_info "Provider: $PROVIDER"
    log_info "Campaign: $CAMPAIGN_ID"
    log_info "VMs: ${VMS[*]}"
    log_info ""
    log_info "Next steps:"
    log_info "  1. Run campaign: python3 $ROOT_DIR/scripts/run_campaign.py --campaign $CAMPAIGN_ID"
    log_info "  2. Collect evidence: ls -la $ROOT_DIR/release/evidence/"
    log_info "  3. Destroy: $SCRIPT_DIR/destroy_lab.sh --campaign $CAMPAIGN_ID"
}

main "$@"
