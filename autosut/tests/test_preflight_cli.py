"""Backend-specific preflight exits cannot be rescued by another backend."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from infrastructure.preflight import (  # noqa: E402
    BackendQualification,
    BackendStatus,
    HostResources,
    PreflightReport,
)


@pytest.fixture
def preflight_cli(monkeypatch):
    script = Path(__file__).resolve().parents[1] / "scripts" / "preflight.py"
    specification = importlib.util.spec_from_file_location("backend_preflight_cli", script)
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    report = PreflightReport(
        captured_at="2026-10-11T00:00:00+00:00",
        host=HostResources(operating_system="Linux fixture", architecture="x86_64",
                           cpu_count=8, memory_gib=32, free_disk_gib=100),
        tools=[], qemu_accelerators={},
        backends=[
            BackendQualification(backend="docker", status=BackendStatus.QUALIFIED,
                                 requirement_gaps=[], note="Daemon reachable"),
            BackendQualification(backend="qemu_linux_arm64",
                                 status=BackendStatus.REQUIRES_BOOT_QUALIFICATION,
                                 requirement_gaps=[], note="Boot not demonstrated"),
            BackendQualification(backend="windows_x86_64", status=BackendStatus.BLOCKED,
                                 requirement_gaps=["No KVM access"], note="Blocked"),
        ], note="Synthetic host fixture",
    )
    monkeypatch.setattr(module, "run_preflight", lambda: report)
    return module


@pytest.mark.parametrize("backend, expected", [
    ("windows_x86_64", 1),
    ("docker", 0),
    ("qemu_linux_arm64", 0),
    ("unknown", 2),
])
def test_requested_backend_controls_exit(preflight_cli, monkeypatch, tmp_path, backend, expected):
    output = tmp_path / "preflight.json"
    monkeypatch.setattr(sys, "argv", ["preflight.py", "--require-backend", backend,
                                      "--output", str(output)])
    try:
        result = preflight_cli.main()
    except SystemExit as error:
        result = error.code
    assert result == expected
    assert output.exists() is (expected != 2)


def test_unselected_probe_preserves_any_backend_exit(preflight_cli, monkeypatch, tmp_path):
    output = tmp_path / "preflight.json"
    monkeypatch.setattr(sys, "argv", ["preflight.py", "--output", str(output)])
    assert preflight_cli.main() == 0
    assert output.exists()
