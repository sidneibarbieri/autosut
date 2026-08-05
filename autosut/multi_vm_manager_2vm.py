#!/usr/bin/env python3
"""
Multi-VM QEMU manager for AutoSUT 2-VM setup (attacker + target).

Caldera server runs on the Mac host (not in a VM).
VMs reach the host via QEMU user-mode NAT gateway at 10.0.2.2.

Architecture:
    Mac host -> caldera_mock.py -> localhost:8888
    attacker VM (port 2224) -> sandcat agent -> http://10.0.2.2:8888
    target   VM (port 2223) -> sandcat agent -> http://10.0.2.2:8888
"""

import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List

# Paths
REPO_ROOT = Path(__file__).resolve().parent
RUNTIME_DIR = REPO_ROOT / "lab" / "qemu" / "runtime"
EVIDENCE_DIR = REPO_ROOT / "evidence" / "qemu-multi"
BASE_IMAGE = REPO_ROOT / "lab" / "qemu" / "images" / "jammy-server-cloudimg-arm64.img"
UEFI_CODE = Path("/opt/homebrew/share/qemu/edk2-aarch64-code.fd")

# Caldera host address reachable from inside QEMU user-mode VMs
CALDERA_HOST_FOR_AGENTS = "10.0.2.2"

# SSH polling
SSH_TIMEOUT = 120
SSH_POLL_INTERVAL = 5
VM_STARTUP_STAGGER = 3

# 2-VM configuration — Caldera server is on the Mac host
VM_CONFIG: Dict[str, Dict] = {
    "attacker": {
        "name": "attacker",
        "hostname": "attacker",
        "memory": "4096",
        "smp": "2",
        "admin_port": "2224",
        "overlay": RUNTIME_DIR / "attacker-overlay.qcow2",
        "seed": RUNTIME_DIR / "attacker-seed.iso",
        "vars": RUNTIME_DIR / "attacker-vars.fd",
        "role": "attacker",
        "agent_group": "red",
    },
    "target": {
        "name": "target",
        "hostname": "target",
        "memory": "2048",
        "smp": "2",
        "admin_port": "2223",
        "overlay": RUNTIME_DIR / "target-overlay.qcow2",
        "seed": RUNTIME_DIR / "target-seed.iso",
        "vars": RUNTIME_DIR / "target-vars.fd",
        "role": "target",
        "agent_group": "blue",
    },
}


def log(msg: str) -> None:
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {msg}")


def run_cmd(cmd: List[str], check: bool = False) -> subprocess.CompletedProcess:
    """Run shell command, log it, return result."""
    log(f"EXEC: {' '.join(str(c) for c in cmd)}")
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


def _cloud_init_attacker(vm_name: str, agent_group: str) -> tuple:
    """Generate cloud-init user-data and meta-data for attacker/target VMs."""
    user_data = f"""#cloud-config
hostname: {vm_name}
manage_etc_hosts: true
ssh_pwauth: true
chpasswd:
  list: |
    ubuntu:ubuntu
  expire: false
packages:
  - openssh-server
  - curl
write_files:
  - path: /etc/ssh/sshd_config.d/99-password.conf
    permissions: '0600'
    content: |
      PasswordAuthentication yes
      PermitRootLogin yes
runcmd:
  - systemctl restart ssh
  - sleep 15
  - curl -s -X POST http://{CALDERA_HOST_FOR_AGENTS}:8888/file/download \\
      -H 'file:sandcat.go' \\
      -H 'platform:linux' \\
      -H 'architecture:arm64' \\
      -o /home/ubuntu/sandcat-agent
  - chmod +x /home/ubuntu/sandcat-agent
  - nohup /home/ubuntu/sandcat-agent \\
      -server http://{CALDERA_HOST_FOR_AGENTS}:8888 \\
      -group {agent_group} \\
      > /tmp/sandcat.log 2>&1 &
  - echo "{vm_name} initialized at $(date)" > /var/tmp/{vm_name}-ready.txt
final_message: "Cloud-init complete for {vm_name} — agent group: {agent_group}"
"""
    meta_data = f"instance-id: {vm_name}\nlocal-hostname: {vm_name}\n"
    return user_data, meta_data


def _create_seed_iso(vm_name: str, config: Dict) -> bool:
    """Write cloud-init ISO for a VM."""
    iso_dir = RUNTIME_DIR / f"{vm_name}-iso-root"
    iso_dir.mkdir(parents=True, exist_ok=True)

    user_data, meta_data = _cloud_init_attacker(vm_name, config["agent_group"])
    (iso_dir / "user-data").write_text(user_data)
    (iso_dir / "meta-data").write_text(meta_data)

    result = run_cmd([
        "xorriso", "-as", "mkisofs",
        "-output", str(config["seed"]),
        "-volid", "cidata",
        "-joliet", "-rock",
        str(iso_dir),
    ])
    return result.returncode == 0


def _create_overlay(config: Dict) -> bool:
    """Create a QEMU overlay image backed by the base image."""
    result = run_cmd([
        "qemu-img", "create",
        "-f", "qcow2",
        "-F", "qcow2",
        "-b", str(BASE_IMAGE),
        str(config["overlay"]),
    ])
    return result.returncode == 0


def _create_vars_fd(config: Dict) -> bool:
    """Create UEFI vars file."""
    result = run_cmd(["truncate", "-s", "64M", str(config["vars"])])
    return result.returncode == 0


def _prepare_artifacts(vm_name: str, config: Dict) -> bool:
    """Prepare QEMU artifacts for a VM."""
    if config["overlay"].exists():
        log(f"Reusing overlay for {vm_name} (fast boot)")
    else:
        if not _create_overlay(config):
            log(f"FAIL failed to create overlay for {vm_name}")
            return False
        if not _create_vars_fd(config):
            log(f"FAIL failed to create vars for {vm_name}")
            return False

    # Always regenerate seed so cloud-init reflects current config
    if not _create_seed_iso(vm_name, config):
        log(f"FAIL failed to create seed ISO for {vm_name}")
        return False

    return True


def _start_vm(config: Dict) -> bool:
    """Start a single VM as a background QEMU process."""
    log(f"Starting {config['name']} (SSH port: {config['admin_port']})")

    cmd = [
        "qemu-system-aarch64",
        "-machine", "virt,accel=hvf",
        "-cpu", "host",
        "-smp", config["smp"],
        "-m", config["memory"],
        "-nographic",
        "-monitor", "none",
        "-serial", f"file:{EVIDENCE_DIR}/{config['name']}-console.log",
        "-drive", f"if=pflash,format=raw,file={UEFI_CODE},readonly=on",
        "-drive", f"if=pflash,format=raw,file={config['vars']}",
        "-drive", f"if=virtio,file={config['overlay']},format=qcow2,cache=none",
        "-drive", f"if=virtio,file={config['seed']},media=cdrom",
        "-netdev",
        f"user,id=net0,net=192.168.100.0/24"
        f",hostfwd=tcp::{config['admin_port']}-:22",
        "-device", "virtio-net-pci,netdev=net0",
    ]

    log(f"EXEC: {' '.join(cmd)}")
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)

    if proc.poll() is not None:
        log(f"FAIL QEMU exited immediately (code {proc.poll()}) for {config['name']}")
        return False

    pid_file = EVIDENCE_DIR / f"{config['name']}-pid.txt"
    pid_file.write_text(str(proc.pid))
    log(f"{config['name']} started with PID {proc.pid}")
    return True


def _wait_for_ssh(port: int, vm_name: str, timeout: int = SSH_TIMEOUT) -> bool:
    """Poll SSH on a VM port until it accepts password auth."""
    log(f"Waiting for SSH on port {port} (timeout: {timeout}s)...")
    elapsed = 0
    while elapsed < timeout:
        result = subprocess.run(
            [
                "sshpass", "-p", "ubuntu",
                "ssh",
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                "-o", "ConnectTimeout=5",
                "-o", "PreferredAuthentications=password",
                "-p", str(port),
                "ubuntu@127.0.0.1",
                "echo ok",
            ],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0 and "ok" in result.stdout:
            log(f"OK SSH ready on port {port} ({elapsed}s)")
            return True
        time.sleep(SSH_POLL_INTERVAL)
        elapsed += SSH_POLL_INTERVAL
    log(f"FAIL SSH not ready on port {port} after {timeout}s")
    return False


def _validate_ssh(config: Dict) -> bool:
    """Validate SSH works and save evidence."""
    result = run_cmd([
        "sshpass", "-p", "ubuntu",
        "ssh",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=10",
        "-p", config["admin_port"],
        "ubuntu@127.0.0.1",
        "hostname && whoami && echo 'SSH OK'",
    ])
    success = result.returncode == 0
    evidence_file = EVIDENCE_DIR / f"{config['name']}-ssh-validation.txt"
    content = result.stdout if success else result.stderr
    evidence_file.write_text(
        f"{'successful' if success else 'failed'} for {config['name']}\n{content}"
    )
    log(f"{'OK' if success else 'FAIL'} {config['name']} SSH {'OK' if success else 'FAILED'}")
    return success


def _validate_agent_reachability(config: Dict) -> bool:
    """Check that the VM can reach the Caldera host at 10.0.2.2."""
    result = run_cmd([
        "sshpass", "-p", "ubuntu",
        "ssh",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=10",
        "-p", config["admin_port"],
        "ubuntu@127.0.0.1",
        f"curl -s --connect-timeout 5 http://{CALDERA_HOST_FOR_AGENTS}:8888/api/v2/abilities -o /dev/null -w '%{{http_code}}'",
    ])
    # 200 or 401 both mean the server is reachable
    reachable = result.returncode == 0 and result.stdout.strip() in ("200", "401")
    log(
        f"{'OK' if reachable else 'WARN'} {config['name']} -> Caldera host "
        f"{'reachable' if reachable else 'not reachable'} "
        f"(HTTP {result.stdout.strip() or 'no response'})"
    )
    return reachable


def _read_pid(pid_file: Path) -> int | None:
    if not pid_file.exists():
        return None
    raw_pid = pid_file.read_text().strip()
    if not raw_pid:
        return None
    return int(raw_pid)


def _process_is_alive(pid: int | None) -> bool:
    if pid is None:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def _check_ssh_ready(config: Dict) -> bool:
    result = subprocess.run(
        [
            "sshpass", "-p", "ubuntu",
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=3",
            "-o", "PreferredAuthentications=password",
            "-p", str(config["admin_port"]),
            "ubuntu@127.0.0.1",
            "echo ok",
        ],
        capture_output=True,
        text=True,
        timeout=8,
    )
    return result.returncode == 0 and "ok" in result.stdout


def _overall_status(vm_rows: List[Dict[str, object]]) -> str:
    if all(not row["process_up"] for row in vm_rows):
        return "stopped"
    if all(row["process_up"] and row["ssh_up"] for row in vm_rows):
        return "ready"
    return "degraded"


def collect_status() -> Dict[str, object]:
    vm_rows: List[Dict[str, object]] = []
    for vm_name, config in VM_CONFIG.items():
        pid_file = EVIDENCE_DIR / f"{vm_name}-pid.txt"
        pid = _read_pid(pid_file)
        process_up = _process_is_alive(pid)
        ssh_up = _check_ssh_ready(config) if process_up else False
        vm_rows.append(
            {
                "name": vm_name,
                "pid": pid,
                "process_up": process_up,
                "ssh_up": ssh_up,
                "admin_port": config["admin_port"],
            }
        )
    return {"vms": vm_rows, "overall": _overall_status(vm_rows)}


def status() -> None:
    snapshot = collect_status()
    print("AutoSUT 2-VM status")
    for row in snapshot["vms"]:
        pid_text = row["pid"] if row["pid"] is not None else "missing"
        process_text = "up" if row["process_up"] else "down"
        ssh_text = "up" if row["ssh_up"] else "down"
        print(
            f"  {row['name']}: pid={pid_text} process={process_text} "
            f"ssh={ssh_text} port={row['admin_port']}"
        )
    print(f"  overall: {snapshot['overall']}")


def stop_all() -> None:
    """Terminate all VM processes."""
    log("Stopping all VMs...")
    for vm_name in VM_CONFIG:
        pid_file = EVIDENCE_DIR / f"{vm_name}-pid.txt"
        if not pid_file.exists():
            log(f"{vm_name} already stopped")
            continue
        pid = int(pid_file.read_text().strip())
        try:
            os.kill(pid, signal.SIGTERM)
            time.sleep(2)
            os.kill(pid, signal.SIGKILL)
            log(f"{vm_name} stopped")
        except ProcessLookupError:
            log(f"{vm_name} already stopped")
        finally:
            pid_file.unlink(missing_ok=True)


def up() -> bool:
    """Start 2-VM environment (attacker + target)."""
    log("Starting AutoSUT 2-VM environment (attacker + target)...")

    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)

    stop_all()

    # Prepare and launch VMs
    for vm_name, config in VM_CONFIG.items():
        log(f"Preparing {vm_name} artifacts...")
        if not _prepare_artifacts(vm_name, config):
            return False

    log("Starting VMs in background...")
    for vm_name, config in VM_CONFIG.items():
        if not _start_vm(config):
            log(f"FAIL failed to start {vm_name}")
            return False
        time.sleep(VM_STARTUP_STAGGER)

    # Wait for SSH
    log("Waiting for VMs to boot...")
    all_ssh_ready = True
    for vm_name, config in VM_CONFIG.items():
        if not _wait_for_ssh(int(config["admin_port"]), vm_name):
            all_ssh_ready = False

    if not all_ssh_ready:
        log("FAIL some VMs failed SSH readiness")
        return False

    # Validate SSH and agent reachability
    log("Running validations...")
    ssh_results = {vm_name: _validate_ssh(config) for vm_name, config in VM_CONFIG.items()}
    agents_reachable = {
        vm_name: _validate_agent_reachability(config) for vm_name, config in VM_CONFIG.items()
    }

    success = all(ssh_results.values()) and all(agents_reachable.values())
    log(f"2-VM setup: {'SUCCESS' if success else 'FAILED'}")
    return success


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python3 multi_vm_manager_2vm.py [up|down|status]")
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == "up":
        sys.exit(0 if up() else 1)
    elif cmd == "down":
        stop_all()
    elif cmd == "status":
        status()
    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)


if __name__ == "__main__":
    main()
