from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC_ROOT = PROJECT_ROOT / "src"
LAB_ROOT = PROJECT_ROOT / "lab"

if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))


def _load_module(module_name: str, module_path: Path):
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def test_apply_sut_profile_sets_vagrant_provider_for_qemu(
    monkeypatch, tmp_path: Path
) -> None:
    module = _load_module("apply_sut_profile_test", SRC_ROOT / "apply_sut_profile.py")
    vm_dir = tmp_path / "lab" / "vagrant" / "target-linux-1"
    vm_dir.mkdir(parents=True)
    captured: dict[str, object] = {}

    def fake_run(command, cwd=None, capture_output=None, text=None, timeout=None, env=None):
        captured["command"] = command
        captured["cwd"] = cwd
        captured["env"] = env
        return subprocess.CompletedProcess(command, 0, "ok", "")

    monkeypatch.setattr(module.subprocess, "run", fake_run)

    success, stdout, stderr = module.execute_ssh_command(
        host_ip="192.168.56.30",
        command="echo ok",
        provider="qemu",
        vm_name="target-linux-1",
        base_dir=tmp_path,
    )

    assert success is True
    assert stdout == "ok"
    assert stderr == ""
    assert captured["command"] == ["vagrant", "ssh", "-c", "echo ok"]
    assert captured["cwd"] == str(vm_dir)
    assert captured["env"]["VAGRANT_DEFAULT_PROVIDER"] == "qemu"


def test_health_check_vagrant_ssh_sets_detected_provider(
    monkeypatch, tmp_path: Path
) -> None:
    module = _load_module("health_check_test", LAB_ROOT / "health_check.py")
    vm_dir = tmp_path / "vagrant" / "target-linux-1"
    vm_dir.mkdir(parents=True)
    captured: dict[str, object] = {}

    def fake_run(command, cwd=None, capture_output=None, text=None, timeout=None, env=None):
        captured["command"] = command
        captured["cwd"] = cwd
        captured["env"] = env
        return subprocess.CompletedProcess(command, 0, "ok", "")

    monkeypatch.setattr(module, "__file__", str(tmp_path / "health_check.py"))
    monkeypatch.setattr(module, "detect_provider", lambda: "qemu")
    monkeypatch.setattr(module.subprocess, "run", fake_run)

    result = module._run_vagrant_ssh("target-linux-1", "echo ok")

    assert result.returncode == 0
    assert captured["command"] == ["vagrant", "ssh", "-c", "echo ok"]
    assert captured["cwd"] == str(vm_dir)
    assert captured["env"]["VAGRANT_DEFAULT_PROVIDER"] == "qemu"


def test_apply_sut_to_host_stages_declared_files(
    monkeypatch, tmp_path: Path
) -> None:
    module = _load_module("apply_sut_profile_files_test", SRC_ROOT / "apply_sut_profile.py")
    commands: list[str] = []

    def fake_execute(
        host_ip,
        command,
        user="vagrant",
        password="vagrant",
        provider="libvirt",
        vm_name=None,
        base_dir=None,
    ):
        commands.append(command)
        return True, "ok", ""

    monkeypatch.setattr(module, "execute_ssh_command", fake_execute)

    profile = {
        "sut_configuration": {
            "target-base": {
                "files": [
                    {
                        "path": "/home/vagrant/documents/brief.txt",
                        "content": "briefing",
                        "owner": "vagrant",
                        "permissions": "600",
                    }
                ],
                "services": [],
                "users": [],
                "deliberate_weaknesses": [],
            }
        }
    }
    host = {
        "hostname": "target-base",
        "ip": "192.168.56.30",
        "role": "target",
        "vm_name": "target-linux-1",
    }

    result = module.apply_sut_to_host(host, profile, tmp_path, "libvirt")

    assert result["files_staged"] == ["/home/vagrant/documents/brief.txt"]
    assert any("/home/vagrant/documents/brief.txt" in command for command in commands)
