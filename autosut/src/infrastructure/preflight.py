"""Qualify the host before any experiment materializes infrastructure.

The old artifact assumed its environment: the frozen Vagrantfile referenced runtime files and a
base image that were not in the package, and nothing checked for them before `vagrant up`. This
module removes that assumption. It probes the host once, deterministically and read-only, and
reports which backends are usable here and which are blocked and why.

A backend where every tool is present is reported as requires_boot_qualification, never
qualified: a working toolchain is not evidence that a guest boots (the Windows ARM64 backend had
a complete toolchain and still failed to boot). Only a passing boot/enroll/teardown qualification
promotes a backend to qualified; the preflight decides what is worth attempting, not what works.
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
from pathlib import Path
from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, ConfigDict


class BackendStatus(str, Enum):
    """How ready a backend is on this host, graded conservatively."""

    QUALIFIED = "qualified"
    REQUIRES_BOOT_QUALIFICATION = "requires_boot_qualification"
    BLOCKED = "blocked"


class ToolProbe(BaseModel):
    """One external tool the substrate may depend on."""

    model_config = ConfigDict(extra="forbid")

    name: str
    present: bool
    version: str | None
    detail: str | None


class HostResources(BaseModel):
    """The host's coarse capacity, enough to gate materialization."""

    model_config = ConfigDict(extra="forbid")

    operating_system: str
    architecture: str
    cpu_count: int
    memory_gib: float
    free_disk_gib: float


class BackendQualification(BaseModel):
    """Whether one backend is usable on this host, and what it lacks if not."""

    model_config = ConfigDict(extra="forbid")

    backend: str
    status: BackendStatus
    requirement_gaps: list[str]
    note: str


class PreflightReport(BaseModel):
    """The full host-qualification snapshot consumed before materialization."""

    model_config = ConfigDict(extra="forbid")

    captured_at: str
    host: HostResources
    tools: list[ToolProbe]
    qemu_accelerators: dict[str, list[str]]
    backends: list[BackendQualification]
    note: str


_VERSION_PROBE_ARGS = ("--version",)
_MINIMUM_DISK_GIB = 40.0


def _probe_tool(name: str, version_args: tuple[str, ...] = _VERSION_PROBE_ARGS) -> ToolProbe:
    """Record whether a tool is on PATH and its reported version, without raising."""
    resolved = shutil.which(name)
    if resolved is None:
        return ToolProbe(name=name, present=False, version=None, detail=None)
    completed = subprocess.run(
        [resolved, *version_args],
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )
    first_line = (completed.stdout or completed.stderr).strip().splitlines()
    version = first_line[0] if first_line else None
    return ToolProbe(name=name, present=True, version=version, detail=resolved)


def _host_resources() -> HostResources:
    """Read OS, architecture, CPU count, memory, and free disk from the host."""
    free_disk_bytes = shutil.disk_usage(os.getcwd()).free
    memory_bytes = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
    return HostResources(
        operating_system=f"{platform.system()} {platform.release()}",
        architecture=platform.machine().lower(),
        cpu_count=os.cpu_count() or 0,
        memory_gib=round(memory_bytes / 1024**3, 1),
        free_disk_gib=round(free_disk_bytes / 1024**3, 1),
    )


def _qemu_accelerators(binary: str) -> list[str]:
    """Accelerators a QEMU binary offers, empty when the binary is absent."""
    resolved = shutil.which(binary)
    if resolved is None:
        return []
    completed = subprocess.run(
        [resolved, "-accel", "help"],
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )
    accelerators = []
    for line in completed.stdout.splitlines():
        candidate = line.strip()
        if candidate and candidate not in {"Accelerators supported in QEMU binary:"}:
            accelerators.append(candidate)
    return accelerators


def _find(tools: list[ToolProbe], name: str) -> ToolProbe | None:
    return next((tool for tool in tools if tool.name == name), None)


def _is_present(tools: list[ToolProbe], name: str) -> bool:
    probe = _find(tools, name)
    return probe is not None and probe.present


def _qualify_docker(tools: list[ToolProbe]) -> BackendQualification:
    """Docker is qualified only when the client is present and its daemon answers."""
    gaps: list[str] = []
    if not _is_present(tools, "docker"):
        gaps.append("docker client not on PATH")
        return BackendQualification(
            backend="docker",
            status=BackendStatus.BLOCKED,
            requirement_gaps=gaps,
            note="Install Docker and start its daemon.",
        )
    daemon = subprocess.run(
        ["docker", "info"], capture_output=True, text=True, check=False, timeout=30
    )
    if daemon.returncode != 0:
        gaps.append("docker daemon not responding to `docker info`")
        return BackendQualification(
            backend="docker",
            status=BackendStatus.BLOCKED,
            requirement_gaps=gaps,
            note="Docker client is present but the daemon is not reachable.",
        )
    return BackendQualification(
        backend="docker",
        status=BackendStatus.QUALIFIED,
        requirement_gaps=[],
        note="Client present and daemon reachable; the canonical portable substrate.",
    )


def _qualify_qemu_linux_arm64(
    host: HostResources, tools: list[ToolProbe], accelerators: dict[str, list[str]]
) -> BackendQualification:
    """A Linux ARM64 VM needs the toolchain, HVF, and disk; a boot test still gates it."""
    gaps: list[str] = []
    if host.architecture not in {"arm64", "aarch64"}:
        gaps.append("host is not arm64, so HVF cannot accelerate an aarch64 guest")
    if not _is_present(tools, "vagrant"):
        gaps.append("vagrant not on PATH")
    if not _is_present(tools, "qemu-system-aarch64"):
        gaps.append("qemu-system-aarch64 not on PATH")
    if "hvf" not in accelerators.get("qemu-system-aarch64", []):
        gaps.append("qemu-system-aarch64 does not offer the hvf accelerator")
    if host.free_disk_gib < _MINIMUM_DISK_GIB:
        gaps.append(
            f"free disk {host.free_disk_gib} GiB below the {_MINIMUM_DISK_GIB} GiB minimum"
        )
    if gaps:
        return BackendQualification(
            backend="qemu_linux_arm64",
            status=BackendStatus.BLOCKED,
            requirement_gaps=gaps,
            note="Missing a hard requirement; do not attempt materialization.",
        )
    return BackendQualification(
        backend="qemu_linux_arm64",
        status=BackendStatus.REQUIRES_BOOT_QUALIFICATION,
        requirement_gaps=[],
        note=(
            "Toolchain, HVF, and disk are present, but a working toolchain is not evidence a "
            "guest boots. A boot/ssh/teardown qualification must pass before this is qualified."
        ),
    )


def _qualify_windows_x86_64(
    host: HostResources, accelerators: dict[str, list[str]]
) -> BackendQualification:
    """Require an available accelerator for Windows x86_64 before attempting boot."""
    x86_accelerators = accelerators.get("qemu-system-x86_64", [])
    gaps: list[str] = []
    if host.architecture not in {"x86_64", "amd64"}:
        gaps.append("host architecture cannot hardware-accelerate an x86_64 guest")
    elif not any(name in x86_accelerators for name in ("kvm", "hvf", "whpx")):
        gaps.append("qemu-system-x86_64 has no supported hardware accelerator")
    elif host.operating_system.startswith("Linux"):
        if "kvm" not in x86_accelerators:
            gaps.append("Linux Windows backend requires the KVM accelerator")
        elif not os.access(Path("/dev/kvm"), os.R_OK | os.W_OK):
            gaps.append("/dev/kvm is absent or not readable and writable by this user")
    if host.free_disk_gib < _MINIMUM_DISK_GIB:
        gaps.append(
            f"free disk {host.free_disk_gib} GiB below the {_MINIMUM_DISK_GIB} GiB minimum"
        )
    if gaps:
        return BackendQualification(
            backend="windows_x86_64",
            status=BackendStatus.BLOCKED,
            requirement_gaps=gaps,
            note=(
                "Requires an x86_64 host with hardware virtualization; tracked in "
                "release/experiments/windows_backend_qualification/."
            ),
        )
    return BackendQualification(
        backend="windows_x86_64",
        status=BackendStatus.REQUIRES_BOOT_QUALIFICATION,
        requirement_gaps=[],
        note="x86_64 acceleration is available; a boot qualification still gates this backend.",
    )


def run_preflight() -> PreflightReport:
    """Probe the host once and return the backend-qualification snapshot."""
    tools = [
        _probe_tool("docker"),
        _probe_tool("vagrant"),
        _probe_tool("qemu-system-aarch64"),
        _probe_tool("qemu-system-x86_64"),
        _probe_tool("vde_switch"),
        _probe_tool("python3"),
    ]
    accelerators = {
        "qemu-system-aarch64": _qemu_accelerators("qemu-system-aarch64"),
        "qemu-system-x86_64": _qemu_accelerators("qemu-system-x86_64"),
    }
    host = _host_resources()
    backends = [
        _qualify_docker(tools),
        _qualify_qemu_linux_arm64(host, tools, accelerators),
        _qualify_windows_x86_64(host, accelerators),
    ]
    return PreflightReport(
        captured_at=datetime.now(timezone.utc).isoformat(),
        host=host,
        tools=tools,
        qemu_accelerators=accelerators,
        backends=backends,
        note=(
            "A live host snapshot taken before materialization, not a frozen-input artifact. "
            "requires_boot_qualification means the toolchain is present but a guest boot has not "
            "yet been proven on this host; only a passing boot qualification promotes a backend "
            "to qualified."
        ),
    )
