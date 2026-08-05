#!/usr/bin/env python3
"""Provider-aware transport helpers for executing commands inside lab VMs."""

from __future__ import annotations

import os
import platform
import shlex
import subprocess
from pathlib import Path

from loaders.campaign_loader import load_sut_profile

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
LAB_VAGRANT_DIR = PROJECT_ROOT / "lab" / "vagrant"

HOSTNAME_VM_ALIAS = {
    "target": "target-linux-1",
    "target-base": "target-linux-1",
    "target-secondary": "target-linux-2",
    "target-1": "target-linux-1",
    "target-2": "target-linux-2",
    "target-ray": "target-linux-1",
}

CONTROL_PLANE_VMS = {"attacker", "caldera"}


def detect_vagrant_provider() -> str:
    """Resolve the active Vagrant provider for the current host or orchestration env."""
    if os.environ.get("STICKS_VAGRANT_PROVIDER"):
        return os.environ["STICKS_VAGRANT_PROVIDER"]
    if os.environ.get("VAGRANT_DEFAULT_PROVIDER"):
        return os.environ["VAGRANT_DEFAULT_PROVIDER"]
    if platform.system() == "Darwin" and platform.machine() == "arm64":
        return "qemu"
    return "libvirt"


def build_vagrant_env(provider: str | None = None) -> dict[str, str]:
    """Build a stable subprocess environment for Vagrant commands."""
    env = os.environ.copy()
    env["VAGRANT_DEFAULT_PROVIDER"] = provider or detect_vagrant_provider()
    return env


def normalize_vm_name(host_name: str) -> str:
    """Resolve profile aliases to a concrete Vagrant VM directory name."""
    vm_name = HOSTNAME_VM_ALIAS.get(host_name, host_name)
    if vm_name.startswith("target-") and not (LAB_VAGRANT_DIR / vm_name).exists():
        return "target-linux-1"
    return vm_name


def resolve_target_vm_name(sut_profile_id: str) -> str:
    """Select the first non-control-plane target declared by the SUT profile."""
    sut_profile = load_sut_profile(sut_profile_id)

    candidate_hosts = [
        host_name
        for host_name in sut_profile.hosts.keys()
        if normalize_vm_name(host_name) not in CONTROL_PLANE_VMS
    ]
    if not candidate_hosts:
        candidate_hosts = [
            vm_name
            for vm_name in sut_profile.required_vms
            if normalize_vm_name(vm_name) not in CONTROL_PLANE_VMS
        ]

    if not candidate_hosts:
        raise ValueError(f"No target VM declared in SUT profile: {sut_profile_id}")

    for host_name in candidate_hosts:
        vm_name = normalize_vm_name(host_name)
        vm_dir = LAB_VAGRANT_DIR / vm_name
        if vm_dir.exists():
            return vm_name

    raise FileNotFoundError(
        f"No Vagrant directory found for SUT targets in {sut_profile_id}: "
        f"{', '.join(candidate_hosts)}"
    )


def run_command_in_vm(
    vm_name: str,
    remote_cmd: str,
    timeout: int = 45,
    provider: str | None = None,
) -> subprocess.CompletedProcess[str]:
    """Execute a shell command inside the requested VM via Vagrant."""
    vm_dir = LAB_VAGRANT_DIR / vm_name
    if not vm_dir.exists():
        raise FileNotFoundError(f"Vagrant directory not found for VM: {vm_dir}")

    return subprocess.run(
        ["vagrant", "ssh", "-c", remote_cmd],
        cwd=vm_dir,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=build_vagrant_env(provider),
    )


def detect_lab_infrastructure(sut_profile_id: str) -> str:
    """Probe whether Vagrant-managed VMs are reachable for the given SUT profile.

    Returns the detected provider string (e.g. "qemu", "libvirt") when the
    target VM responds to a basic SSH probe, or "" when no lab infrastructure
    is available.
    """
    provider = detect_vagrant_provider()
    try:
        vm_name = resolve_target_vm_name(sut_profile_id)
        result = run_command_in_vm(
            vm_name=vm_name,
            remote_cmd="echo STICKS_PROBE_OK",
            timeout=10,
            provider=provider,
        )
        if result.returncode == 0 and "STICKS_PROBE_OK" in result.stdout:
            return provider
    except (FileNotFoundError, ValueError, subprocess.TimeoutExpired, OSError):
        pass
    return ""


def run_bash_on_target_vm(
    sut_profile_id: str,
    bash_script: str,
    timeout: int = 45,
    provider: str | None = None,
) -> subprocess.CompletedProcess[str]:
    """Execute a bash script inside the target VM selected by the SUT profile."""
    vm_name = resolve_target_vm_name(sut_profile_id)
    remote_cmd = f"bash -lc {shlex.quote(bash_script)}"
    return run_command_in_vm(
        vm_name=vm_name,
        remote_cmd=remote_cmd,
        timeout=timeout,
        provider=provider,
    )
