from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from executors import lab_transport


def test_detect_vagrant_provider_prefers_explicit_sticks_env(monkeypatch) -> None:
    monkeypatch.setenv("STICKS_VAGRANT_PROVIDER", "qemu")
    monkeypatch.delenv("VAGRANT_DEFAULT_PROVIDER", raising=False)

    assert lab_transport.detect_vagrant_provider() == "qemu"


def test_run_command_in_vm_sets_vagrant_default_provider(monkeypatch, tmp_path: Path) -> None:
    vm_dir = tmp_path / "lab" / "vagrant" / "target-linux-1"
    vm_dir.mkdir(parents=True)
    monkeypatch.setattr(lab_transport, "LAB_VAGRANT_DIR", tmp_path / "lab" / "vagrant")

    captured: dict[str, object] = {}

    def fake_run(command, cwd=None, capture_output=None, text=None, timeout=None, env=None):
        captured["command"] = command
        captured["cwd"] = cwd
        captured["env"] = env
        return subprocess.CompletedProcess(command, 0, "ok", "")

    monkeypatch.setattr(lab_transport.subprocess, "run", fake_run)
    monkeypatch.setenv("STICKS_VAGRANT_PROVIDER", "qemu")

    result = lab_transport.run_command_in_vm("target-linux-1", "echo ok")

    assert result.returncode == 0
    assert captured["command"] == ["vagrant", "ssh", "-c", "echo ok"]
    assert captured["cwd"] == vm_dir
    assert captured["env"]["VAGRANT_DEFAULT_PROVIDER"] == "qemu"


def test_run_bash_on_target_vm_passes_provider_to_vagrant_transport(monkeypatch) -> None:
    monkeypatch.setattr(lab_transport, "resolve_target_vm_name", lambda _: "target-linux-1")
    captured: dict[str, object] = {}

    def fake_run_command_in_vm(vm_name: str, remote_cmd: str, timeout: int, provider: str | None = None):
        captured["vm_name"] = vm_name
        captured["remote_cmd"] = remote_cmd
        captured["timeout"] = timeout
        captured["provider"] = provider
        return subprocess.CompletedProcess(["vagrant"], 0, "ok", "")

    monkeypatch.setattr(lab_transport, "run_command_in_vm", fake_run_command_in_vm)

    result = lab_transport.run_bash_on_target_vm(
        sut_profile_id="0.shadowray",
        bash_script="echo hello",
        timeout=12,
        provider="qemu",
    )

    assert result.returncode == 0
    assert captured["vm_name"] == "target-linux-1"
    assert captured["timeout"] == 12
    assert captured["provider"] == "qemu"
    assert "bash -lc" in captured["remote_cmd"]
