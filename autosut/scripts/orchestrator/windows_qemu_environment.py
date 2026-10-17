"""Windows-on-ARM64 QEMU execution-substrate backend (EnvironmentBackend).

Each run boots a fresh qcow2 overlay of an immutable generalized base with its own firmware vars, swtpm
TPM state, and forwarded WinRM port; the first-boot ``specialize`` pass gives the clone a distinct
machine identity. ``run_shell`` runs a command as PowerShell over WinRM/NTLM and returns the same
:class:`CommandResult` the other backends return. The provider knows its transport is WinRM; it does not
know what a procedure, Caldera, an agent, a PAW, or a nonce is (those live in the execution and
scientific layers above the lifecycle).

Robustness: every resource is namespaced to the run (from ``run_dir``); QEMU/swtpm output is captured
into the run bundle; teardown records an observable shutdown outcome; and the residual inventory is
fail-closed (an uninspectable resource makes the run not-clean).

Credential seam: this backend reads a caller-supplied WinRM password from
``$AUTOSUT_WIN_PASSWORD``. The Windows integration entrypoint mints a new
password for each disposable clone and clears its logical references after the
run. The backend alone does not mint or qualify credentials. Image and
transient-host clearance remain separate qualification gates.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import socket
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable
from contextlib import ExitStack
from pathlib import Path
from typing import IO

from pydantic import BaseModel, ConfigDict

from .environment_base import BackendReadiness, CommandResult, EnvironmentBackend
from .models import SUTProfile

_EDK2_CODE = Path("/opt/homebrew/share/qemu/edk2-aarch64-code.fd")
_EDK2_VARS = Path("/opt/homebrew/share/qemu/edk2-arm-vars.fd")
_WINRM_USER = "labadmin"
_CREDENTIAL_ENV = "AUTOSUT_WIN_PASSWORD"
_READY_COMMAND = (
    "if (-not (Test-Path 'C:\\qualification\\provisioning.done')) { exit 1 }\n"
    "$env:COMPUTERNAME"
)


class WindowsResidualInventory(BaseModel):
    """A fail-closed inventory of everything this backend could leave behind after a run.

    ``inventory_completed`` is False if any probe could not be evaluated; the run must then be
    treated as not-clean rather than assumed clean. ``clean`` requires a completed inventory with no
    residual resources.
    """

    model_config = ConfigDict(extra="forbid")

    scope: str
    inventory_completed: bool
    residual_resources: list[str]
    probe_errors: list[str]

    @property
    def clean(self) -> bool:
        return self.inventory_completed and not self.residual_resources


class WindowsTeardownRecord(BaseModel):
    """The observable outcome of a teardown; nothing about the shutdown is silently discarded."""

    model_config = ConfigDict(extra="forbid")

    shutdown_requested: bool
    shutdown_transport_error: str | None
    guest_exited_naturally: bool
    forced_termination_used: bool
    controller_credential_cleared: bool = False


def _port_is_listening(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.settimeout(1.0)
        return probe.connect_ex(("127.0.0.1", port)) == 0


def _pgrep(pattern: str) -> list[str]:
    """Process ids whose command line matches ``pattern``. Raises if pgrep itself cannot run."""
    result = subprocess.run(["pgrep", "-f", pattern], capture_output=True, text=True,
                            check=False, timeout=30)
    if result.returncode not in (0, 1):
        raise RuntimeError(f"pgrep failed for {pattern!r}: rc={result.returncode} {result.stderr}")
    return result.stdout.split()


def _winrm_credential() -> str:
    """Read the caller's run-scoped WinRM password."""
    password = os.environ.get(_CREDENTIAL_ENV)
    if not password:
        raise RuntimeError(
            f"WindowsQemuEnvironment needs a run-scoped WinRM credential in ${_CREDENTIAL_ENV}. "
            "Use the ephemeral Windows integration entrypoint or provide an independently "
            "qualified run-scoped credential."
        )
    return password


def _stop_startup_process(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=30)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=30)


def _new_monitor_dir(token: str) -> Path:
    """Keep the diagnostic socket short and private on macOS."""
    return Path(tempfile.mkdtemp(prefix=f"autosut-{token}-monitor-", dir="/tmp"))


def _remove_startup_files(overlay: Path, vars_file: Path, tpm_state: Path,
                          tpm_socket: Path) -> None:
    tpm_socket.unlink(missing_ok=True)
    overlay.unlink(missing_ok=True)
    vars_file.unlink(missing_ok=True)
    if tpm_state.exists():
        shutil.rmtree(tpm_state)


class WindowsQemuEnvironment(EnvironmentBackend):
    """One Windows ARM64 QEMU guest provisioned for a single campaign run.

    Contract-identical to the Docker and Linux/QEMU backends: bring up, run shell, tear down, so the
    orchestrator and executor stay substrate-agnostic.
    """

    backend_name = "windows-qemu"

    @classmethod
    def check(cls) -> BackendReadiness:
        """Dependency preflight: are the host tools and firmware present to attempt materialization?

        This is a narrow dependency check, not a scientific readiness claim and not a boot proof.
        A passing check means bring-up is worth attempting; promotion past it is a qualification
        run's job.
        """
        gaps: list[str] = []
        if shutil.which("qemu-system-aarch64") is None:
            gaps.append("qemu-system-aarch64 not on PATH")
        if shutil.which("swtpm") is None:
            gaps.append("swtpm not on PATH (brew install swtpm)")
        if shutil.which("qemu-img") is None:
            gaps.append("qemu-img not on PATH")
        if importlib.util.find_spec("winrm") is None:
            gaps.append("pywinrm is not installed in the active Python environment")
        if not _EDK2_CODE.exists():
            gaps.append(f"edk2 firmware code missing: {_EDK2_CODE}")
        if not _EDK2_VARS.exists():
            gaps.append(f"edk2 firmware vars template missing: {_EDK2_VARS}")
        return BackendReadiness(cls.backend_name, ready=not gaps, gaps=gaps)

    def __init__(self, *, sut: SUTProfile, run_dir: Path, workdir: Path, namespace: str,
                 winrm_port: int, password: str, guest: subprocess.Popen, tpm: subprocess.Popen,
                 tpm_socket: Path, overlay: Path, vars_file: Path, tpm_state: Path,
                 monitor_dir: Path, log_handles: list[IO[bytes]], hostname: str,
                 stopped_disk_observer: Callable[[Path], None] | None = None):
        self.sut = sut
        self.run_dir = run_dir
        self.workdir = workdir
        self.namespace = namespace
        self.winrm_port = winrm_port
        self._password = password
        self._guest = guest
        self._tpm = tpm
        self._tpm_socket = tpm_socket
        self._overlay = overlay
        self._vars_file = vars_file
        self._tpm_state = tpm_state
        self._monitor_dir = monitor_dir
        self._log_handles = log_handles
        self._hostname = hostname
        self._stopped_disk_observer = stopped_disk_observer
        self._guest_ready = False
        self._bootstrap_cancelled = threading.Event()
        self._teardown_lock = threading.Lock()
        self._teardown_result: bool | None = None
        self.teardown_record: WindowsTeardownRecord | None = None

    @property
    def host_id(self) -> str:
        return f"{self._hostname}@windows-qemu:{self.winrm_port}"

    @classmethod
    def bring_up(
        cls, sut: SUTProfile, run_dir: Path,
        *, on_created: Callable[[WindowsQemuEnvironment], None] | None = None,
        stopped_disk_observer: Callable[[Path], None] | None = None,
    ) -> WindowsQemuEnvironment:
        readiness = cls.check()
        if not readiness.ready:
            raise RuntimeError(f"windows-qemu not ready: {'; '.join(readiness.gaps)}")
        base = Path(sut.base_image)
        if not base.exists():
            raise RuntimeError(f"windows-qemu base image not found: {base}")
        password = _winrm_credential()

        # Everything is namespaced to the run, not the pid, so concurrent runs never collide and the
        # inventory/teardown can key on one token.
        namespace = run_dir.name
        token = namespace.rsplit("-", 1)[-1][:12] or namespace[:12]
        workdir = run_dir / "windows-qemu"
        workdir.mkdir(parents=True, exist_ok=False)
        overlay = workdir / "guest.qcow2"
        vars_file = workdir / "guest-vars.fd"
        tpm_state = workdir / "guest-tpm"
        winrm_port = _reserve_port()

        with ExitStack() as startup:
            monitor_dir = _new_monitor_dir(token)
            tpm_socket = monitor_dir / "tpm.sock"
            startup.callback(shutil.rmtree, monitor_dir)
            startup.callback(_remove_startup_files, overlay, vars_file, tpm_state, tpm_socket)
            subprocess.run(
                ["qemu-img", "create", "-f", "qcow2", "-b", str(base.resolve()), "-F", "qcow2",
                 str(overlay)],
                check=True, capture_output=True, text=True, timeout=120,
            )
            shutil.copyfile(_EDK2_VARS, vars_file)
            tpm_state.mkdir(parents=True, exist_ok=True)

            swtpm_log = (workdir / "swtpm.log").open("wb")
            startup.callback(swtpm_log.close)
            qemu_out = (workdir / "qemu.stdout.log").open("wb")
            startup.callback(qemu_out.close)
            qemu_err = (workdir / "qemu.stderr.log").open("wb")
            startup.callback(qemu_err.close)
            log_handles: list[IO[bytes]] = [swtpm_log, qemu_out, qemu_err]

            tpm = subprocess.Popen(
                ["swtpm", "socket", "--tpm2", "--tpmstate", f"dir={tpm_state}",
                 "--ctrl", f"type=unixio,path={tpm_socket}", "--flags", "startup-clear"],
                stdout=swtpm_log, stderr=swtpm_log,
            )
            startup.callback(_stop_startup_process, tpm)
            time.sleep(3)
            guest = subprocess.Popen(
                ["qemu-system-aarch64", "-M", "virt-11.0,gic-version=3", "-accel", "hvf",
                 "-cpu", "host", "-smp", str(sut.smp), "-m", str(sut.memory_mb),
                 "-drive", f"if=pflash,format=raw,readonly=on,file={_EDK2_CODE}",
                 "-drive", f"if=pflash,format=raw,file={vars_file}",
                 "-chardev", f"socket,id=chrtpm,path={tpm_socket}",
                 "-tpmdev", "emulator,id=tpm0,chardev=chrtpm", "-device", "tpm-tis-device,tpmdev=tpm0",
                 "-device", "ramfb", "-device", "qemu-xhci,id=usb",
                 "-device", "usb-kbd", "-device", "usb-tablet",
                 "-device", "nvme,drive=target,serial=winnvme",
                 "-drive", f"if=none,id=target,file={overlay},format=qcow2",
                 "-netdev", f"user,id=net0,hostfwd=tcp:127.0.0.1:{winrm_port}-:5985",
                 "-device", "virtio-net-pci,netdev=net0",
                 "-serial", f"file:{workdir / 'guest-serial.log'}",
                 "-monitor", f"unix:{monitor_dir / 'hmp.sock'},server=on,wait=off",
                 "-display", "none"],
                stdout=qemu_out, stderr=qemu_err,
            )
            startup.callback(_stop_startup_process, guest)
            instance = cls(
                sut=sut, run_dir=run_dir, workdir=workdir, namespace=namespace,
                winrm_port=winrm_port, password=password, guest=guest, tpm=tpm,
                tpm_socket=tpm_socket, overlay=overlay, vars_file=vars_file,
                stopped_disk_observer=stopped_disk_observer,
                tpm_state=tpm_state, monitor_dir=monitor_dir,
                log_handles=log_handles, hostname="windows-qemu",
            )
            startup.pop_all()
        try:
            if on_created is not None:
                on_created(instance)
            instance._detect_early_qemu_exit()
            instance._hostname = instance._wait_ready(deadline_seconds=1500)
            instance._guest_ready = True
        except BaseException:
            # Signals also need to release an instance created before readiness.
            instance.teardown()
            raise
        return instance

    def _detect_early_qemu_exit(self) -> None:
        """Fail closed if QEMU died at start-up (e.g. the forwarded port was taken after reservation)."""
        time.sleep(2)
        code = self._guest.poll()
        if code is not None:
            stderr = (self.workdir / "qemu.stderr.log").read_text(errors="replace")[-800:]
            raise RuntimeError(f"qemu exited immediately (code {code}); tail of stderr:\n{stderr}")

    def _session(self, timeout: int = 60):
        if not self._password:
            raise RuntimeError("Windows controller credential has been cleared")
        import winrm
        # Apply the caller's timeout to the WinRM operation; the HTTP read must outlast it.
        return winrm.Session(
            f"http://127.0.0.1:{self.winrm_port}/wsman", auth=(_WINRM_USER, self._password),
            transport="ntlm", operation_timeout_sec=timeout, read_timeout_sec=timeout + 30,
        )

    def _wait_ready(self, deadline_seconds: float) -> str:
        from requests.exceptions import ConnectionError, Timeout
        from winrm.exceptions import InvalidCredentialsError

        deadline = time.time() + deadline_seconds
        last_error: Exception | None = None
        rejected_credentials = 0
        while time.time() < deadline:
            if self._bootstrap_cancelled.is_set():
                raise RuntimeError("Windows bootstrap cancelled during teardown")
            if self._guest.poll() is not None:
                raise RuntimeError("qemu exited while waiting for the guest to answer WinRM")
            try:
                response = self._session(timeout=25).run_ps(_READY_COMMAND)
                if response.status_code == 0:
                    hostname = response.std_out.decode(errors="replace").strip()
                    if not hostname:
                        raise RuntimeError("Windows guest returned an empty hostname")
                    return hostname
            except InvalidCredentialsError as error:
                rejected_credentials += 1
                if rejected_credentials >= 3:
                    raise RuntimeError(
                        "Windows guest rejected the WinRM credential three times; "
                        "check the sealed image credential source"
                    ) from error
            except (ConnectionError, Timeout) as error:
                last_error = error
            self._bootstrap_cancelled.wait(20)
        raise RuntimeError("windows-qemu guest did not answer WinRM before the deadline") from last_error

    def run_shell(self, command: str, log_name: str | None = None,
                  timeout: int = 600) -> CommandResult:
        """Run ``command`` as PowerShell over WinRM and return the uniform CommandResult.

        ``timeout`` bounds the WinRM operation. The command is a PowerShell command line: OS-specific
        procedure text belongs to the campaign and SUT profile, never to this backend, which only
        executes what it is given.
        """
        response = self._session(timeout=timeout).run_ps(command)
        result = CommandResult(
            cmd=command, exit_code=response.status_code,
            stdout=response.std_out.decode(errors="replace"),
            stderr=response.std_err.decode(errors="replace"),
        )
        if log_name:
            log_path = self.run_dir / log_name
            log_path.parent.mkdir(parents=True, exist_ok=True)
            log_path.write_text(
                f"$ {command}\nexit_code: {result.exit_code}\n"
                f"--- stdout ---\n{result.stdout}\n--- stderr ---\n{result.stderr}\n",
                encoding="utf-8",
            )
        return result

    def teardown(self) -> bool:
        """Cancel bootstrap and serialize cleanup across lifecycle and bootstrap workers."""
        self._bootstrap_cancelled.set()
        with self._teardown_lock:
            if self._teardown_result is None:
                self._teardown_result = self._perform_teardown()
            return self._teardown_result

    def _perform_teardown(self) -> bool:
        """Request a graceful shutdown, force it if needed, and record the outcome observably.

        The WinRM transport dropping as Windows powers off is expected, so it is classified (recorded
        as ``shutdown_transport_error``) rather than silently swallowed; whether the guest actually
        exited on its own is a separate, explicit fact.
        """
        transport_error: str | None = None
        if self._guest_ready:
            try:
                self._session(timeout=30).run_ps("Stop-Computer -Force")
            except Exception as error:  # noqa: BLE001 - classified below, not discarded
                transport_error = f"{type(error).__name__}: {error}"

        exited_naturally = self._guest.poll() is not None
        if self._guest_ready:
            for _ in range(72):
                if exited_naturally:
                    break
                time.sleep(5)
                exited_naturally = self._guest.poll() is not None
        forced = False
        if self._guest.poll() is None:
            self._guest.terminate()
            try:
                self._guest.wait(timeout=30)
            except subprocess.TimeoutExpired:
                self._guest.kill()
                self._guest.wait(timeout=30)
            forced = True

        if self._tpm.poll() is None:
            self._tpm.terminate()
            try:
                self._tpm.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self._tpm.kill()
                self._tpm.wait(timeout=15)
        self._password = ""
        for handle in self._log_handles:
            handle.close()

        observer = getattr(self, "_stopped_disk_observer", None)
        self._stopped_disk_observer = None
        acquisition_completed = observer is None
        try:
            if observer is not None:
                observer(self._overlay)
                acquisition_completed = True
        finally:
            self._tpm_socket.unlink(missing_ok=True)
            self._overlay.unlink(missing_ok=True)
            self._vars_file.unlink(missing_ok=True)
            shutil.rmtree(self._tpm_state, ignore_errors=True)
            shutil.rmtree(self._monitor_dir)
            if not acquisition_completed:
                self._teardown_result = False

        self.teardown_record = WindowsTeardownRecord(
            shutdown_requested=self._guest_ready,
            shutdown_transport_error=transport_error,
            guest_exited_naturally=exited_naturally,
            forced_termination_used=forced,
            controller_credential_cleared=not self._password,
        )
        (self.workdir / "teardown.json").write_text(
            self.teardown_record.model_dump_json(indent=2), encoding="utf-8")
        return self.residual_inventory().clean and self._guest_ready and exited_naturally and not forced

    def residual_inventory(self) -> WindowsResidualInventory:
        """Fail-closed inventory of every resource this run could leave behind.

        Each probe is guarded; if any probe cannot be evaluated, ``inventory_completed`` is False and
        the run is treated as not-clean rather than assumed clean.
        """
        residual: list[str] = []
        errors: list[str] = []

        def probe(label: str, fn) -> None:
            try:
                if fn():
                    residual.append(label)
            except Exception as error:  # noqa: BLE001 - a probe that cannot run fails the inventory
                errors.append(f"{label}: {type(error).__name__}: {error}")

        probe("qemu-process-alive", lambda: self._guest.poll() is None)
        probe("swtpm-process-alive", lambda: self._tpm.poll() is None)
        probe("qemu-by-overlay", lambda: bool(_pgrep(str(self._overlay))))
        probe("swtpm-by-socket", lambda: bool(_pgrep(f"autosut-{self.namespace.rsplit('-', 1)[-1][:12]}")))
        probe("tpm-control-socket", lambda: self._tpm_socket.exists())
        probe("overlay-qcow2", lambda: self._overlay.exists())
        probe("firmware-vars", lambda: self._vars_file.exists())
        probe("tpm-state-dir", lambda: self._tpm_state.exists())
        probe("monitor-dir", lambda: self._monitor_dir.exists())
        probe("forwarded-winrm-port", lambda: _port_is_listening(self.winrm_port))

        return WindowsResidualInventory(
            scope=f"windows-qemu:{self.namespace}",
            inventory_completed=not errors,
            residual_resources=residual,
            probe_errors=errors,
        )


def _reserve_port() -> int:
    """A currently-free TCP port for the WinRM forward.

    There is an unavoidable window between releasing the probe socket and QEMU binding the port; a
    port taken in that window makes QEMU exit at start-up, which ``_detect_early_qemu_exit`` catches
    and fails closed on, rather than proceeding against a wrong or shared port.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]
