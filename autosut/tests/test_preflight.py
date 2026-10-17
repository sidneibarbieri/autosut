"""The preflight qualifies this host conservatively and consistently.

It is a live host probe, so the test asserts structural invariants and host-stable facts rather
than byte-identity: every backend is graded, a blocked backend always names a gap, and a backend
that is merely tool-complete is never reported as qualified.
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from infrastructure.preflight import (  # noqa: E402
    BackendStatus,
    HostResources,
    _qualify_windows_x86_64,
    run_preflight,
)


def _linux_x86_host():
    return HostResources(
        operating_system="Linux test", architecture="x86_64", cpu_count=8,
        memory_gib=32, free_disk_gib=100,
    )


def test_windows_x86_requires_an_accelerator():
    backend = _qualify_windows_x86_64(
        _linux_x86_host(), {"qemu-system-x86_64": ["tcg"]},
    )
    assert backend.status is BackendStatus.BLOCKED
    assert any("hardware accelerator" in gap for gap in backend.requirement_gaps)


def test_advertised_kvm_is_insufficient_without_device_access(monkeypatch):
    monkeypatch.setattr("infrastructure.preflight.os.access", lambda *args: False)
    backend = _qualify_windows_x86_64(
        _linux_x86_host(), {"qemu-system-x86_64": ["tcg", "kvm"]},
    )
    assert backend.status is BackendStatus.BLOCKED
    assert any("/dev/kvm" in gap for gap in backend.requirement_gaps)


def test_accessible_kvm_still_requires_guest_boot_qualification(monkeypatch):
    monkeypatch.setattr("infrastructure.preflight.os.access", lambda *args: True)
    backend = _qualify_windows_x86_64(
        _linux_x86_host(), {"qemu-system-x86_64": ["tcg", "kvm"]},
    )
    assert backend.status is BackendStatus.REQUIRES_BOOT_QUALIFICATION
    assert backend.requirement_gaps == []


def _report():
    return run_preflight()


def test_all_three_backends_are_graded():
    names = {backend.backend for backend in _report().backends}
    assert names == {"docker", "qemu_linux_arm64", "windows_x86_64"}


def test_blocked_backends_always_name_a_gap_and_ready_ones_never_do():
    for backend in _report().backends:
        if backend.status is BackendStatus.BLOCKED:
            assert backend.requirement_gaps
        else:
            assert backend.requirement_gaps == []


def test_a_tool_complete_backend_is_never_reported_qualified_without_a_boot_test():
    """qemu_linux_arm64 tops out at requires_boot_qualification from the preflight alone."""
    qemu = next(b for b in _report().backends if b.backend == "qemu_linux_arm64")
    assert qemu.status is not BackendStatus.QUALIFIED


def test_windows_is_blocked_on_an_arm64_host():
    report = _report()
    if report.host.architecture in {"arm64", "aarch64"}:
        windows = next(b for b in report.backends if b.backend == "windows_x86_64")
        assert windows.status is BackendStatus.BLOCKED


def test_every_probed_tool_reports_presence_consistently():
    for tool in _report().tools:
        if tool.present:
            assert tool.detail is not None
        else:
            assert tool.version is None and tool.detail is None
