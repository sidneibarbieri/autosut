#!/usr/bin/env python3
"""
Three-level health check for STICKS lab infrastructure.

Level 1 — VM Ready:       SSH is reachable on each host.
Level 2 — Service Ready:  Critical services (Caldera API, Apache, SSH) respond.
Level 3 — Campaign Ready: Inter-host connectivity validated for the campaign topology.

Each level depends on the previous one passing.
Exit codes: 0 = all passed, 1 = failures detected.
"""

import argparse
import json
import os
import platform
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
import yaml

# VM IP mapping (declared topology)
VM_IPS: Dict[str, str] = {
    "caldera": "192.168.56.10",
    "attacker": "192.168.56.20",
    "target-linux-1": "192.168.56.30",
    "target-linux-2": "192.168.56.31",
}

# SSH forwarded ports for qemu provider (fallback when private network unavailable)
VM_SSH_PORTS: Dict[str, int] = {
    "caldera": 50022,
    "attacker": 50023,
    "target-linux-1": 50024,
    "target-linux-2": 50025,
}

@dataclass
class CheckResult:
    name: str
    passed: bool
    message: str
    details: str = ""


@dataclass
class HealthReport:
    campaign_id: str
    timestamp: str
    provider: str
    level1_vm_ready: List[CheckResult] = field(default_factory=list)
    level2_service_ready: List[CheckResult] = field(default_factory=list)
    level3_campaign_ready: List[CheckResult] = field(default_factory=list)
    overall_passed: bool = False

    def all_level1_passed(self) -> bool:
        return all(c.passed for c in self.level1_vm_ready)

    def all_level2_passed(self) -> bool:
        return all(c.passed for c in self.level2_service_ready)

    def all_level3_passed(self) -> bool:
        return all(c.passed for c in self.level3_campaign_ready)


def _run_cmd(cmd: List[str], timeout: int = 10) -> subprocess.CompletedProcess:
    """Run command with timeout, never raise on failure."""
    try:
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(
            args=cmd,
            returncode=124,
            stdout="",
            stderr="timeout",
        )
    except FileNotFoundError:
        return subprocess.CompletedProcess(
            args=cmd,
            returncode=127,
            stdout="",
            stderr=f"command not found: {cmd[0]}",
        )


def _run_vagrant_ssh(
    vm_name: str, remote_cmd: str, timeout: int = 20
) -> subprocess.CompletedProcess:
    """Run command inside a VM via vagrant ssh from the VM directory."""
    vm_dir = Path(__file__).resolve().parent / "vagrant" / vm_name
    if not vm_dir.exists():
        return subprocess.CompletedProcess(
            args=["vagrant", "ssh", "-c", remote_cmd],
            returncode=1,
            stdout="",
            stderr=f"vagrant dir not found: {vm_dir}",
        )
    try:
        env = os.environ.copy()
        env["VAGRANT_DEFAULT_PROVIDER"] = detect_provider()
        return subprocess.run(
            ["vagrant", "ssh", "-c", remote_cmd],
            cwd=str(vm_dir),
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(
            args=["vagrant", "ssh", "-c", remote_cmd],
            returncode=124,
            stdout="",
            stderr="timeout",
        )
    except FileNotFoundError:
        return subprocess.CompletedProcess(
            args=["vagrant", "ssh", "-c", remote_cmd],
            returncode=127,
            stdout="",
            stderr="command not found: vagrant",
        )


def detect_provider() -> str:
    """Detect which Vagrant provider is in use."""
    if platform.system() == "Darwin" and platform.machine() == "arm64":
        return "qemu"
    return "libvirt"


def _resolve_topology_from_sut(campaign_id: str) -> List[str]:
    """Resolve VM topology from SUT profile requirements.required_vms."""
    root_dir = Path(__file__).resolve().parent.parent
    profile_path = root_dir / "data" / "sut_profiles" / f"{campaign_id}.yml"
    if not profile_path.exists():
        raise ValueError(f"SUT profile not found for campaign: {campaign_id}")

    with open(profile_path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}

    required_vms = raw.get("requirements", {}).get("required_vms", [])
    if not required_vms:
        raise ValueError(
            f"Missing requirements.required_vms in SUT profile: {profile_path}"
        )

    alias = {
        "target-base": "target-linux-1",
        "target-1": "target-linux-1",
        "target-2": "target-linux-2",
    }

    resolved = []
    for vm in required_vms:
        vm_name = alias.get(vm, vm)
        if vm_name not in resolved:
            resolved.append(vm_name)
    return resolved


# ---------------------------------------------------------------------------
# Level 1 — VM Ready (SSH reachable)
# ---------------------------------------------------------------------------


def check_vm_ssh_private(vm_name: str) -> CheckResult:
    """Check SSH via private network IP."""
    ip = VM_IPS.get(vm_name, "")
    if not ip:
        return CheckResult(vm_name, False, f"No IP mapping for {vm_name}")

    result = _run_cmd(
        [
            "ssh",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "ConnectTimeout=5",
            "-o",
            "BatchMode=yes",
            f"vagrant@{ip}",
            "echo ok",
        ],
        timeout=10,
    )

    if result.returncode == 0 and "ok" in result.stdout:
        return CheckResult(vm_name, True, f"SSH OK via {ip}")
    return CheckResult(vm_name, False, f"SSH failed via {ip}", result.stderr.strip())


def check_vm_ssh_forwarded(vm_name: str) -> CheckResult:
    """Check SSH via forwarded port (qemu fallback)."""
    port = VM_SSH_PORTS.get(vm_name)
    if not port:
        return CheckResult(vm_name, False, f"No SSH port mapping for {vm_name}")

    result = _run_cmd(
        [
            "ssh",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "ConnectTimeout=5",
            "-o",
            "BatchMode=yes",
            "-p",
            str(port),
            "vagrant@127.0.0.1",
            "echo ok",
        ],
        timeout=10,
    )

    if result.returncode == 0 and "ok" in result.stdout:
        return CheckResult(vm_name, True, f"SSH OK via 127.0.0.1:{port}")
    return CheckResult(
        vm_name, False, f"SSH failed via 127.0.0.1:{port}", result.stderr.strip()
    )


def check_vm_ssh_vagrant(vm_name: str) -> CheckResult:
    """Check SSH via vagrant ssh from VM directory (provider-agnostic fallback)."""
    result = _run_vagrant_ssh(vm_name, "echo ok", timeout=15)
    if result.returncode == 0 and "ok" in result.stdout:
        return CheckResult(vm_name, True, "SSH OK via vagrant ssh")
    return CheckResult(vm_name, False, "SSH failed via vagrant ssh", result.stderr[:200])


def check_vm_vagrant_status(vm_name: str) -> CheckResult:
    """Check VM status via vagrant (last resort)."""
    vm_dir = Path(__file__).resolve().parent / "vagrant" / vm_name
    if not vm_dir.exists():
        return CheckResult(vm_name, False, f"Vagrant dir not found: {vm_dir}")

    result = _run_cmd(["vagrant", "status", "--machine-readable"], timeout=15)
    # Parse vagrant machine-readable output
    if result.returncode == 0 and "running" in result.stdout:
        return CheckResult(vm_name, True, "Vagrant reports running")
    return CheckResult(
        vm_name, False, "Vagrant does not report running", result.stdout[:200]
    )


def level1_vm_ready(vms: List[str], provider: str) -> List[CheckResult]:
    """Level 1: Check that each VM has reachable SSH."""
    results = []
    for vm in vms:
        # Try private network first
        check = check_vm_ssh_private(vm)
        if check.passed:
            results.append(check)
            continue

        # If qemu, try forwarded port
        if provider == "qemu":
            check = check_vm_ssh_vagrant(vm)
            if check.passed:
                results.append(check)
                continue
            check = check_vm_ssh_forwarded(vm)
            if check.passed:
                results.append(check)
                continue

        # Record failure with both attempts
        results.append(
            CheckResult(
                vm,
                False,
                f"SSH unreachable on {vm}",
                "Private IP and forwarded port both failed",
            )
        )

    return results


# ---------------------------------------------------------------------------
# Level 2 — Service Ready
# ---------------------------------------------------------------------------


def check_caldera_api(provider: str) -> CheckResult:
    """Check Caldera API/UI endpoint using provider-aware fallback."""
    candidates: List[str]
    if provider == "qemu":
        candidates = [
            "http://127.0.0.1:8888",
            "http://127.0.0.1:8888/api/rest",
            "http://192.168.56.10:8888",
            "http://192.168.56.10:8888/api/rest",
        ]
    else:
        candidates = [
            "http://192.168.56.10:8888",
            "http://192.168.56.10:8888/api/rest",
            "http://127.0.0.1:8888",
            "http://127.0.0.1:8888/api/rest",
        ]

    errors: List[str] = []
    for url in candidates:
        result = _run_cmd(["curl", "-s", "--connect-timeout", "5", url], timeout=10)
        if result.returncode == 0:
            return CheckResult(
                "caldera-api",
                True,
                f"Caldera endpoint responding at {url}",
                result.stdout[:200],
            )
        errors.append(f"{url}: rc={result.returncode}")

    if provider == "qemu":
        vm_result = _run_vagrant_ssh("caldera", "curl -s --connect-timeout 5 http://127.0.0.1:8888/ | head -c 50", timeout=20)
        if vm_result.returncode == 0:
            return CheckResult(
                "caldera-api",
                True,
                "Caldera endpoint responding inside caldera VM",
                vm_result.stdout[:200],
            )
        errors.append(f"inside-vm: rc={vm_result.returncode}")

    return CheckResult(
        "caldera-api",
        False,
        "Caldera API/UI not responding on any expected endpoint",
        "; ".join(errors)[:300],
    )


def check_ssh_service(vm_name: str, provider: str) -> CheckResult:
    """Check SSH service is accepting connections (already covered by L1)."""
    if provider == "qemu":
        result = _run_vagrant_ssh(
            vm_name, "systemctl is-active sshd || systemctl is-active ssh", timeout=15
        )
        if result.returncode == 0:
            return CheckResult(
                f"ssh-{vm_name}", True, f"SSH service active on {vm_name} via vagrant ssh"
            )
        return CheckResult(
            f"ssh-{vm_name}",
            False,
            f"SSH service check failed on {vm_name}",
            result.stderr.strip(),
        )

    ip = VM_IPS.get(vm_name, "")
    result = _run_cmd(
        [
            "ssh",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "ConnectTimeout=5",
            "-o",
            "BatchMode=yes",
            f"vagrant@{ip}",
            "systemctl is-active sshd || systemctl is-active ssh",
        ],
        timeout=10,
    )

    if result.returncode == 0:
        return CheckResult(f"ssh-{vm_name}", True, f"SSH service active on {vm_name}")
    return CheckResult(
        f"ssh-{vm_name}",
        False,
        f"SSH service check failed on {vm_name}",
        result.stderr.strip(),
    )


def check_apache_service(vm_name: str = "target-linux-1", provider: str = "libvirt") -> CheckResult:
    """Check Apache service for campaigns that need it (pikabot)."""
    if provider == "qemu":
        result = _run_vagrant_ssh(
            vm_name,
            "systemctl is-active apache2 || systemctl is-active httpd",
            timeout=15,
        )
        if result.returncode == 0:
            return CheckResult(
                f"apache-{vm_name}",
                True,
                f"Apache service active on {vm_name} via vagrant ssh",
            )
        return CheckResult(
            f"apache-{vm_name}",
            False,
            f"Apache service check failed on {vm_name}",
            result.stderr.strip(),
        )

    ip = VM_IPS.get(vm_name, "")
    url = f"http://{ip}/"
    result = _run_cmd(
        [
            "curl",
            "-s",
            "--connect-timeout",
            "5",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            url,
        ],
        timeout=10,
    )

    if result.returncode == 0 and result.stdout.strip().startswith(("2", "3", "4")):
        return CheckResult(
            f"apache-{vm_name}",
            True,
            f"Apache responding on {vm_name} (HTTP {result.stdout.strip()})",
        )
    return CheckResult(
        f"apache-{vm_name}",
        False,
        f"Apache not responding on {vm_name}",
        result.stderr.strip(),
    )


def level2_service_ready(
    vms: List[str], campaign_id: str, provider: str
) -> List[CheckResult]:
    """Level 2: Check base services that must be ready before SUT application."""
    results = []

    # Caldera API (always required)
    if "caldera" in vms:
        results.append(check_caldera_api(provider))

    # SSH on all targets
    for vm in vms:
        if vm.startswith("target"):
            results.append(check_ssh_service(vm, provider))

    return results


# ---------------------------------------------------------------------------
# Level 3 — Campaign Ready (inter-host connectivity)
# ---------------------------------------------------------------------------


def check_host_to_host(src_vm: str, dst_vm: str, provider: str) -> CheckResult:
    """Check connectivity from src to dst via SSH proxy."""
    src_ip = VM_IPS.get(src_vm, "")
    dst_ip = VM_IPS.get(dst_vm, "")

    if not src_ip or not dst_ip:
        return CheckResult(
            f"{src_vm}->{dst_vm}",
            False,
            "Missing IP mapping",
        )

    if provider == "qemu":
        result = _run_vagrant_ssh(
            src_vm,
            f"ping -c 1 -W 2 {dst_ip} && echo REACHABLE || echo UNREACHABLE",
            timeout=20,
        )
    else:
        # SSH into src and ping dst
        result = _run_cmd(
            [
                "ssh",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "ConnectTimeout=5",
                "-o",
                "BatchMode=yes",
                f"vagrant@{src_ip}",
                f"ping -c 1 -W 2 {dst_ip} && echo REACHABLE || echo UNREACHABLE",
            ],
            timeout=15,
        )

    if "REACHABLE" in result.stdout:
        return CheckResult(
            f"{src_vm}->{dst_vm}",
            True,
            f"{src_vm} can reach {dst_vm} ({dst_ip})",
        )
    return CheckResult(
        f"{src_vm}->{dst_vm}",
        False,
        f"{src_vm} cannot reach {dst_vm} ({dst_ip})",
        result.stderr.strip()[:200],
    )


def level3_campaign_ready(vms: List[str], campaign_id: str, provider: str) -> List[CheckResult]:
    """Level 3: Validate inter-host connectivity required by campaign."""
    results = []

    # Attacker must reach all targets
    if "attacker" in vms:
        for vm in vms:
            if vm.startswith("target"):
                results.append(check_host_to_host("attacker", vm, provider))

    # For lateral_test: target-1 must reach target-2
    if campaign_id == "0.lateral_test":
        if "target-linux-1" in vms and "target-linux-2" in vms:
            results.append(
                check_host_to_host("target-linux-1", "target-linux-2", provider)
            )

    # All targets must reach caldera (for agent callback)
    if "caldera" in vms:
        for vm in vms:
            if vm.startswith("target"):
                results.append(check_host_to_host(vm, "caldera", provider))

    return results


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------


def print_report(report: HealthReport):
    """Print human-readable health report."""
    print(f"\n{'=' * 70}")
    print(f"  HEALTH CHECK: {report.campaign_id}")
    print(f"  Provider: {report.provider}")
    print(f"  Timestamp: {report.timestamp}")
    print(f"{'=' * 70}\n")

    def _print_level(name: str, checks: List[CheckResult]):
        passed = sum(1 for c in checks if c.passed)
        total = len(checks)
        status = "PASS" if passed == total else "FAIL"
        print(f"  {name}: {status} ({passed}/{total})")
        for c in checks:
            icon = "OK  " if c.passed else "FAIL"
            print(f"    [{icon}] {c.name}: {c.message}")
            if not c.passed and c.details:
                print(f"           {c.details[:100]}")

    _print_level("Level 1 — VM Ready", report.level1_vm_ready)
    print()
    _print_level("Level 2 — Service Ready", report.level2_service_ready)
    print()
    _print_level("Level 3 — Campaign Ready", report.level3_campaign_ready)

    print(f"\n{'=' * 70}")
    overall = "PASS" if report.overall_passed else "FAIL"
    print(f"  OVERALL: {overall}")
    print(f"{'=' * 70}\n")


def save_report(report: HealthReport, output_dir: Path):
    """Save health report as JSON."""
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = output_dir / f"health_{report.campaign_id}_{timestamp}.json"

    data = {
        "campaign_id": report.campaign_id,
        "timestamp": report.timestamp,
        "provider": report.provider,
        "overall_passed": report.overall_passed,
        "level1_vm_ready": [asdict(c) for c in report.level1_vm_ready],
        "level2_service_ready": [asdict(c) for c in report.level2_service_ready],
        "level3_campaign_ready": [asdict(c) for c in report.level3_campaign_ready],
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    print(f"[HEALTH] Report saved to: {path}")
    return path


def run_health_check(campaign_id: str, provider: Optional[str] = None) -> HealthReport:
    """Run full 3-level health check for a campaign."""
    if provider is None:
        provider = detect_provider()

    vms = _resolve_topology_from_sut(campaign_id)

    report = HealthReport(
        campaign_id=campaign_id,
        timestamp=datetime.now().isoformat(),
        provider=provider,
    )

    # Level 1
    report.level1_vm_ready = level1_vm_ready(vms, provider)

    # Level 2 (only if L1 has at least some passes)
    if any(c.passed for c in report.level1_vm_ready):
        report.level2_service_ready = level2_service_ready(vms, campaign_id, provider)
    else:
        report.level2_service_ready = [
            CheckResult("skipped", False, "Level 2 skipped: no VMs reachable")
        ]

    # Level 3 (only if L1 all pass)
    if report.all_level1_passed():
        report.level3_campaign_ready = level3_campaign_ready(vms, campaign_id, provider)
    else:
        report.level3_campaign_ready = [
            CheckResult("skipped", False, "Level 3 skipped: not all VMs reachable")
        ]

    report.overall_passed = (
        report.all_level1_passed()
        and report.all_level2_passed()
        and report.all_level3_passed()
    )

    return report


def main():
    parser = argparse.ArgumentParser(
        description="STICKS Lab Health Check (3 levels)",
    )
    parser.add_argument(
        "--campaign",
        required=True,
        help="Campaign ID",
    )
    parser.add_argument(
        "--provider",
        help="Vagrant provider (qemu|libvirt|virtualbox)",
    )
    parser.add_argument(
        "--output",
        default="release/evidence",
        help="Output directory for health report",
    )
    parser.add_argument(
        "--json-only",
        action="store_true",
        help="Only save JSON, no console output",
    )

    args = parser.parse_args()

    report = run_health_check(args.campaign, args.provider)

    if not args.json_only:
        print_report(report)

    save_report(report, Path(args.output))

    return 0 if report.overall_passed else 1


if __name__ == "__main__":
    sys.exit(main())
