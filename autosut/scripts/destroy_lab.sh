#!/bin/bash
# destroy_lab.sh - Canonical lab teardown script
# Usage: ./destroy_lab.sh [--campaign <id>]
#
# Notes:
# - Campaign filter is optional; current implementation destroys all managed VMs.
# - Safe for repeated runs.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
CAMPAIGN_ID=""
TARGET_VMS=()

log_info() { echo "[DESTROY-LAB] $1"; }
log_warn() { echo "[DESTROY-LAB] WARN: $1"; }

resolve_topology() {
    [[ -n "$CAMPAIGN_ID" ]] || return 0

    while IFS= read -r vm_name; do
        [[ -n "$vm_name" ]] || continue
        TARGET_VMS+=("$vm_name")
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

with open(profile_path, "r", encoding="utf-8") as handle:
    raw = yaml.safe_load(handle) or {}

required_vms = raw.get("requirements", {}).get("required_vms", [])
alias = {
    "target-base": "target-linux-1",
    "target-1": "target-linux-1",
    "target": "target-linux-1",
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
}

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

    log_warn "Cleaning stale listener on TCP:$port"
    for pid in $pids; do
        kill "$pid" 2>/dev/null || true
    done
    sleep 1
    for pid in $pids; do
        kill -0 "$pid" 2>/dev/null && kill -9 "$pid" 2>/dev/null || true
    done
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --campaign)
            CAMPAIGN_ID="${2:-}"
            shift 2
            ;;
        --help|-h)
            echo "Usage: ./destroy_lab.sh [--campaign <id>]"
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
    esac
done

if [[ -n "$CAMPAIGN_ID" ]]; then
    log_info "Campaign filter received: $CAMPAIGN_ID"
    resolve_topology || true
fi

log_info "Destroying managed Vagrant VMs..."
for vm_dir in "$ROOT_DIR"/lab/vagrant/*; do
    [[ -d "$vm_dir" ]] || continue
    [[ -f "$vm_dir/Vagrantfile" ]] || continue

    vm_name="$(basename "$vm_dir")"
    if [[ ${#TARGET_VMS[@]} -gt 0 ]]; then
        skip_vm=true
        for target_vm in "${TARGET_VMS[@]}"; do
            if [[ "$vm_name" == "$target_vm" ]]; then
                skip_vm=false
                break
            fi
        done
        $skip_vm && continue
    fi

    log_info "Destroying VM in $vm_name"

    (
        cd "$vm_dir"
        vagrant destroy -f >/dev/null 2>&1 || true
    )

    rm -rf "$vm_dir/.vagrant"
    kill_stale_listener "$(ssh_port_for_vm "$vm_name")"
done

log_info "Cleaning runtime artifacts..."
rm -rf "$ROOT_DIR"/data/state/* 2>/dev/null || true
rm -rf "$ROOT_DIR"/data/artifacts/* 2>/dev/null || true

log_info "Teardown complete"
