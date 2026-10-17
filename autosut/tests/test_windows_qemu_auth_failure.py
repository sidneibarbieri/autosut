"""Wrong sealed-image credentials must fail before the long boot deadline."""

import selectors
import subprocess
import sys
import threading
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import Mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from orchestrator import windows_qemu_environment
from orchestrator.models import SUTProfile
from orchestrator.windows_qemu_environment import WindowsQemuEnvironment


class InvalidCredentialsError(Exception):
    """Test double for the optional WinRM dependency."""


class TransportConnectionError(Exception):
    """Test double for Requests connection failures."""


def _stub_winrm(monkeypatch):
    winrm_module = ModuleType("winrm")
    exceptions_module = ModuleType("winrm.exceptions")
    exceptions_module.InvalidCredentialsError = InvalidCredentialsError
    winrm_module.exceptions = exceptions_module
    monkeypatch.setitem(sys.modules, "winrm", winrm_module)
    monkeypatch.setitem(sys.modules, "winrm.exceptions", exceptions_module)
    requests_module = ModuleType("requests")
    transport_exceptions = ModuleType("requests.exceptions")
    transport_exceptions.ConnectionError = TransportConnectionError
    transport_exceptions.Timeout = TimeoutError
    requests_module.exceptions = transport_exceptions
    monkeypatch.setitem(sys.modules, "requests", requests_module)
    monkeypatch.setitem(sys.modules, "requests.exceptions", transport_exceptions)


def test_repeated_invalid_credentials_fail_fast(monkeypatch):
    _stub_winrm(monkeypatch)
    backend = object.__new__(WindowsQemuEnvironment)
    backend._bootstrap_cancelled = Mock(wraps=threading.Event())
    backend._bootstrap_cancelled.wait.return_value = False
    backend._guest = Mock()
    backend._guest.poll.return_value = None
    backend._session = Mock(side_effect=InvalidCredentialsError("rejected"))
    monkeypatch.setattr("orchestrator.windows_qemu_environment.time.sleep", lambda _: None)

    with pytest.raises(RuntimeError, match="rejected the WinRM credential three times"):
        backend._wait_ready(deadline_seconds=1500)

    assert backend._session.call_count == 3


def test_cancelled_boot_never_attempts_winrm(monkeypatch):
    _stub_winrm(monkeypatch)
    backend = object.__new__(WindowsQemuEnvironment)
    backend._bootstrap_cancelled = threading.Event()
    backend._bootstrap_cancelled.set()
    backend._session = Mock()

    with pytest.raises(RuntimeError, match="bootstrap cancelled"):
        backend._wait_ready(deadline_seconds=1500)

    backend._session.assert_not_called()


def test_ready_hostname_uses_the_authenticated_probe_response(monkeypatch):
    _stub_winrm(monkeypatch)
    backend = object.__new__(WindowsQemuEnvironment)
    backend._bootstrap_cancelled = threading.Event()
    backend._guest = Mock()
    backend._guest.poll.return_value = None
    response = SimpleNamespace(status_code=0, std_out=b"FRESH-WIN\r\n")
    backend._session = Mock(return_value=SimpleNamespace(run_ps=Mock(return_value=response)))

    assert backend._wait_ready(deadline_seconds=30) == "FRESH-WIN"
    backend._session.assert_called_once_with(timeout=25)
    command = backend._session.return_value.run_ps.call_args.args[0]
    assert "C:\\qualification\\provisioning.done" in command


def test_readiness_propagates_programming_errors(monkeypatch):
    _stub_winrm(monkeypatch)
    backend = object.__new__(WindowsQemuEnvironment)
    backend._bootstrap_cancelled = Mock(wraps=threading.Event())
    backend._bootstrap_cancelled.wait.side_effect = AssertionError("must not retry")
    backend._guest = Mock()
    backend._guest.poll.return_value = None
    backend._session = Mock(side_effect=TypeError("invalid client configuration"))

    with pytest.raises(TypeError, match="invalid client configuration"):
        backend._wait_ready(deadline_seconds=1500)

    backend._session.assert_called_once()


def test_readiness_retries_connection_failures(monkeypatch):
    _stub_winrm(monkeypatch)
    backend = object.__new__(WindowsQemuEnvironment)
    backend._bootstrap_cancelled = Mock(wraps=threading.Event())
    backend._bootstrap_cancelled.wait.return_value = False
    backend._guest = Mock()
    backend._guest.poll.return_value = None
    ready_session = Mock()
    ready_session.run_ps.return_value.status_code = 0
    backend._session = Mock(side_effect=[TransportConnectionError("booting"), ready_session])

    backend._wait_ready(deadline_seconds=1500)

    assert backend._session.call_count == 2
    backend._bootstrap_cancelled.wait.assert_called_once_with(20)


@pytest.mark.parametrize("cleanup_result", [True, False])
def test_teardown_is_idempotent_and_preserves_failure(cleanup_result):
    backend = object.__new__(WindowsQemuEnvironment)
    backend._bootstrap_cancelled = threading.Event()
    backend._teardown_lock = threading.Lock()
    backend._teardown_result = None
    backend._perform_teardown = Mock(return_value=cleanup_result)

    assert backend.teardown() is cleanup_result
    assert backend.teardown() is cleanup_result
    assert backend._bootstrap_cancelled.is_set()
    backend._perform_teardown.assert_called_once_with()


def test_failed_boot_teardown_forces_guest_without_waiting_for_winrm(monkeypatch, tmp_path):
    backend = object.__new__(WindowsQemuEnvironment)
    backend._guest_ready = False
    backend._guest = Mock()
    backend._guest.poll.return_value = None
    backend._tpm = Mock()
    backend._tpm.poll.return_value = None
    backend._session = Mock(side_effect=AssertionError("WinRM is not authenticated"))
    backend._log_handles = []
    backend._tpm_socket = tmp_path / "guest.sock"
    backend._overlay = tmp_path / "guest.qcow2"
    backend._vars_file = tmp_path / "guest-vars.fd"
    backend._tpm_state = tmp_path / "guest-tpm"
    backend._monitor_dir = tmp_path / "monitor"
    backend._monitor_dir.mkdir()
    backend.workdir = tmp_path
    backend.residual_inventory = Mock(return_value=SimpleNamespace(clean=True))
    monkeypatch.setattr(
        windows_qemu_environment.time, "sleep",
        lambda seconds: pytest.fail("failed boot must not wait for graceful shutdown"),
    )

    assert backend._perform_teardown() is False
    backend._session.assert_not_called()
    backend._guest.terminate.assert_called_once_with()
    assert backend.teardown_record.forced_termination_used
    assert not backend.teardown_record.shutdown_requested
    assert not backend._monitor_dir.exists()


def test_readiness_identifies_missing_winrm_dependency(monkeypatch):
    monkeypatch.setattr(
        "orchestrator.windows_qemu_environment.importlib.util.find_spec",
        lambda name: None if name == "winrm" else Mock(),
    )

    readiness = WindowsQemuEnvironment.check()

    assert not readiness.ready
    assert any("pywinrm" in gap for gap in readiness.gaps)


@pytest.mark.skipif(sys.platform == "win32", reason="QEMU backend uses POSIX process signals")
def test_forced_tpm_exit_is_reaped_before_state_removal(monkeypatch, tmp_path):
    child = subprocess.Popen(
        [sys.executable, "-c",
         ("import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
          "print('ready', flush=True); time.sleep(3600)")],
        stdout=subprocess.PIPE, text=True,
    )
    original_wait = child.wait
    original_remove = windows_qemu_environment.shutil.rmtree
    backend = object.__new__(WindowsQemuEnvironment)
    backend._guest_ready = False
    backend._guest = SimpleNamespace(poll=lambda: 0)
    backend._tpm = child
    backend._log_handles = []
    backend._tpm_socket = tmp_path / "tpm.sock"
    backend._overlay = tmp_path / "guest.qcow2"
    backend._vars_file = tmp_path / "guest-vars.fd"
    backend._tpm_state = tmp_path / "tpm-state"
    backend._tpm_state.mkdir()
    backend._monitor_dir = tmp_path / "monitor"
    backend._monitor_dir.mkdir()
    backend.workdir = tmp_path
    backend.namespace = "test-reap"
    backend.winrm_port = 41235
    wait_calls = 0

    def bounded_wait(timeout=None):
        nonlocal wait_calls
        wait_calls += 1
        return original_wait(timeout=0.02 if wait_calls == 1 else timeout)

    def remove_after_reap(path, **kwargs):
        if Path(path) == backend._tpm_state:
            assert child.returncode is not None, "TPM child must exit before state removal"
        return original_remove(path, **kwargs)

    try:
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ)
            assert selector.select(timeout=5), "synthetic child failed to start"
            assert child.stdout.readline().strip() == "ready"
        monkeypatch.setattr(child, "wait", bounded_wait)
        monkeypatch.setattr(windows_qemu_environment.shutil, "rmtree", remove_after_reap)
        monkeypatch.setattr(windows_qemu_environment, "_pgrep", lambda pattern: [])
        monkeypatch.setattr(windows_qemu_environment, "_port_is_listening", lambda port: False)
        assert backend._perform_teardown() is False
        assert backend.residual_inventory().clean
        assert not backend._tpm_state.exists()
        assert not backend._monitor_dir.exists()
    finally:
        child.kill()
        original_wait(timeout=5)
        child.stdout.close()


def test_qemu_start_failure_reaps_tpm_and_removes_run_files(monkeypatch, tmp_path):
    base = tmp_path / "base.qcow2"
    base.touch()
    profile = SUTProfile(sut_id="partial-start", backend="windows-qemu", base_image=str(base))
    tpm = Mock()
    tpm.poll.return_value = None
    workdir = tmp_path / "run" / "windows-qemu"
    monitor_dir = tmp_path / "monitor"
    qemu_commands = []

    def create_overlay(command, **kwargs):
        (workdir / "guest.qcow2").touch()
        return SimpleNamespace(returncode=0)

    def copy_firmware(source, destination):
        Path(destination).touch()

    def start_process(command, **kwargs):
        if command[0] == "swtpm":
            return tpm
        qemu_commands.append(command)
        raise OSError("synthetic QEMU launch failure")

    def new_monitor_dir(token):
        monitor_dir.mkdir(mode=0o700)
        return monitor_dir

    monkeypatch.setattr(WindowsQemuEnvironment, "check", lambda: SimpleNamespace(ready=True))
    monkeypatch.setattr(windows_qemu_environment, "_winrm_credential", lambda: "synthetic")
    monkeypatch.setattr(windows_qemu_environment, "_reserve_port", lambda: 41235)
    monkeypatch.setattr(windows_qemu_environment.time, "sleep", lambda seconds: None)
    monkeypatch.setattr(windows_qemu_environment.shutil, "copyfile", copy_firmware)
    monkeypatch.setattr(windows_qemu_environment.subprocess, "run", create_overlay)
    monkeypatch.setattr(windows_qemu_environment.subprocess, "Popen", start_process)
    monkeypatch.setattr(windows_qemu_environment, "_new_monitor_dir", new_monitor_dir)

    with pytest.raises(OSError, match="synthetic QEMU launch failure"):
        WindowsQemuEnvironment.bring_up(profile, tmp_path / "run")

    tpm.terminate.assert_called_once_with()
    tpm.wait.assert_called_once_with(timeout=30)
    assert not (workdir / "guest.qcow2").exists()
    assert not (workdir / "guest-vars.fd").exists()
    assert not (workdir / "guest-tpm").exists()
    assert not monitor_dir.exists()
    assert "-monitor" in qemu_commands[0]
    assert (workdir / "qemu.stderr.log").exists()


def test_interrupted_ownership_callback_tears_down_created_guest(monkeypatch, tmp_path):
    base = tmp_path / "base.qcow2"
    base.touch()
    profile = SUTProfile(sut_id="interrupted-start", backend="windows-qemu", base_image=str(base))
    torn_down = []

    def teardown(instance):
        for handle in instance._log_handles:
            handle.close()
        torn_down.append(instance)
        return True

    monkeypatch.setattr(WindowsQemuEnvironment, "check", lambda: SimpleNamespace(ready=True))
    monkeypatch.setattr(WindowsQemuEnvironment, "teardown", teardown)
    monkeypatch.setattr(windows_qemu_environment, "_winrm_credential", lambda: "synthetic")
    monkeypatch.setattr(windows_qemu_environment, "_reserve_port", lambda: 41235)
    monkeypatch.setattr(windows_qemu_environment.time, "sleep", lambda seconds: None)
    monkeypatch.setattr(windows_qemu_environment.shutil, "copyfile", lambda *args: None)
    monkeypatch.setattr(windows_qemu_environment.subprocess, "run", lambda *args, **kwargs: None)
    monkeypatch.setattr(windows_qemu_environment.subprocess, "Popen", lambda *args, **kwargs: Mock())

    def interrupt_after_ownership(instance):
        raise KeyboardInterrupt("synthetic interruption")

    with pytest.raises(KeyboardInterrupt, match="synthetic interruption"):
        WindowsQemuEnvironment.bring_up(
            profile, tmp_path / "run", on_created=interrupt_after_ownership,
        )

    assert len(torn_down) == 1


@pytest.mark.parametrize("clone_name", ["first", "clone-" + "界" * 60])
def test_same_named_clones_in_distinct_runs_get_distinct_tpm_sockets(
    monkeypatch, tmp_path, clone_name,
):
    base = tmp_path / "base.qcow2"
    base.touch()
    profile = SUTProfile(sut_id="socket-isolation", backend="windows-qemu", base_image=str(base))
    sockets = []

    def start_process(command, **kwargs):
        if command[0] == "swtpm":
            control = command[command.index("--ctrl") + 1]
            sockets.append(Path(control.split("path=", 1)[1]))
            process = Mock()
            process.poll.return_value = 0
            return process
        raise OSError("stop before guest boot")

    monkeypatch.setattr(WindowsQemuEnvironment, "check", lambda: SimpleNamespace(ready=True))
    monkeypatch.setattr(windows_qemu_environment, "_winrm_credential", lambda: "synthetic")
    monkeypatch.setattr(windows_qemu_environment, "_reserve_port", lambda: 41235)
    monkeypatch.setattr(windows_qemu_environment.time, "sleep", lambda seconds: None)
    monkeypatch.setattr(windows_qemu_environment.shutil, "copyfile", lambda *args: None)
    monkeypatch.setattr(windows_qemu_environment.subprocess, "run", lambda *args, **kwargs: None)
    monkeypatch.setattr(windows_qemu_environment.subprocess, "Popen", start_process)

    for run_name in ("pair-a", "pair-b"):
        with pytest.raises(OSError, match="stop before guest boot"):
            WindowsQemuEnvironment.bring_up(profile, tmp_path / run_name / clone_name)

    assert len(sockets) == 2
    assert sockets[0] != sockets[1]
    assert all(len(str(path).encode()) < 104 for path in sockets)
    assert all(not path.parent.exists() for path in sockets)
