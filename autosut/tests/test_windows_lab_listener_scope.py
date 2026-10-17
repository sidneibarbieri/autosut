"""Windows integration listeners must not expose the lab to the LAN."""

import sys
from pathlib import Path
from types import SimpleNamespace

from infrastructure import caldera_instance

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts" / "infra"))
import windows_cyber_gate
from orchestrator import windows_qemu_environment
from orchestrator.models import SUTProfile


def test_caldera_port_is_published_only_on_loopback(monkeypatch):
    commands = []

    def record_command(command, **kwargs):
        commands.append(command)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(caldera_instance, "_free_tcp_port", lambda: 41234)
    monkeypatch.setattr(caldera_instance.subprocess, "run", record_command)

    caldera_instance.CalderaInstance.materialize("autosut-scope-test")

    command = commands[0]
    assert command[command.index("-p") + 1] == "127.0.0.1:41234:8888"


def test_agent_download_server_binds_only_loopback(tmp_path):
    server = windows_cyber_gate._serve_directory(tmp_path, 0)
    try:
        assert server.server_address[0] == "127.0.0.1"
    finally:
        server.shutdown()
        server.server_close()


def test_qemu_winrm_forward_binds_only_loopback(monkeypatch, tmp_path):
    commands = []
    created_instances = []
    backend = windows_qemu_environment.WindowsQemuEnvironment
    base = tmp_path / "base.qcow2"
    base.touch()

    def record_process(command, **kwargs):
        commands.append(command)
        return SimpleNamespace(pid=123, poll=lambda: None)

    monkeypatch.setattr(backend, "check", lambda: SimpleNamespace(ready=True))
    monkeypatch.setattr(backend, "_detect_early_qemu_exit", lambda self: None)
    def require_early_ownership(instance, **kwargs):
        assert created_instances == [instance]
        return "test-guest"

    monkeypatch.setattr(backend, "_wait_ready", require_early_ownership)
    monkeypatch.setattr(windows_qemu_environment, "_winrm_credential", lambda: "synthetic")
    monkeypatch.setattr(windows_qemu_environment, "_reserve_port", lambda: 41235)
    monkeypatch.setattr(windows_qemu_environment.time, "sleep", lambda seconds: None)
    monkeypatch.setattr(windows_qemu_environment.shutil, "copyfile", lambda *args: None)
    monkeypatch.setattr(windows_qemu_environment.subprocess, "run", lambda *args, **kwargs: None)
    monkeypatch.setattr(windows_qemu_environment.subprocess, "Popen", record_process)
    profile = SUTProfile(sut_id="listener-scope", backend="windows-qemu", base_image=str(base))

    instance = backend.bring_up(
        profile, tmp_path / "test-run", on_created=created_instances.append,
    )
    try:
        command = commands[1]
        assert command[command.index("-netdev") + 1] == (
            "user,id=net0,hostfwd=tcp:127.0.0.1:41235-:5985"
        )
    finally:
        for handle in instance._log_handles:
            handle.close()
