"""Prove that two clones of one generalized Windows base receive independent identities.

The qualifying property for multi-host Windows is not a hostname: it is that two fresh instances,
booted from the same generalized image, each complete the specialize pass and end up with a distinct
machine SID, machine GUID, and computer name, remain reachable over WinRM, and leave nothing behind
when destroyed. This driver materializes each clone as its own qcow2 overlay over the immutable
generalized base, boots it, reads its identity over WinRM, shuts it down, and reports the comparison.

The base image is hashed before and after the clones so immutability is demonstrated rather than
assumed, a forced termination is recorded distinctly from a guest-initiated shutdown, and the host is
inventoried after teardown. Failures surface as errors instead of being swallowed, because a clone
that never answered must not be indistinguishable from one that answered with an empty identity.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess
import time
from pathlib import Path

from pydantic import BaseModel, ConfigDict

# A local account SID ends in a per-account RID; the machine SID is the prefix without it.
_RID_COMPONENTS = 1

_IDENTITY_PS = (
    "$sid=((New-Object System.Security.Principal.NTAccount('labadmin'))."
    "Translate([System.Security.Principal.SecurityIdentifier]).Value);"
    "$mg=(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Cryptography' -Name MachineGuid).MachineGuid;"
    "$uuid=(Get-CimInstance Win32_ComputerSystemProduct).UUID;"
    "$build=(Get-CimInstance Win32_OperatingSystem).BuildNumber;"
    "$env:COMPUTERNAME + '|' + $sid + '|' + $mg + '|' + $uuid + '|' + $build + '|' + "
    "$env:PROCESSOR_ARCHITECTURE"
)


class GuestIdentity(BaseModel):
    """The machine-specific identity a specialize pass assigned to one clone."""

    model_config = ConfigDict(extra="forbid")

    clone: str
    hostname: str
    machine_sid: str
    account_sid: str
    machine_guid: str
    system_uuid: str
    os_build: str
    architecture: str
    guest_exited_naturally: bool = False
    forced_termination_used: bool = False


class ResidualInventory(BaseModel):
    """What the host still holds after a clone was destroyed."""

    model_config = ConfigDict(extra="forbid")

    qemu_processes: list[str]
    swtpm_processes: list[str]
    leftover_overlays: list[str]
    leftover_tpm_state: list[str]

    @property
    def clean(self) -> bool:
        return not (
            self.qemu_processes
            or self.swtpm_processes
            or self.leftover_overlays
            or self.leftover_tpm_state
        )


class CloneComparison(BaseModel):
    """Both clone identities and every assertion that qualifies the generalized base."""

    model_config = ConfigDict(extra="forbid")

    base_sha256_before: str
    base_sha256_after: str
    clone_a: GuestIdentity
    clone_b: GuestIdentity
    residual_after_teardown: ResidualInventory

    @property
    def different_machine_sid(self) -> bool:
        return self.clone_a.machine_sid != self.clone_b.machine_sid

    @property
    def different_machine_guid(self) -> bool:
        return self.clone_a.machine_guid != self.clone_b.machine_guid

    @property
    def different_hostname(self) -> bool:
        return self.clone_a.hostname != self.clone_b.hostname

    @property
    def base_immutable(self) -> bool:
        return self.base_sha256_before == self.base_sha256_after

    @property
    def shutdowns_were_natural(self) -> bool:
        return not (self.clone_a.forced_termination_used or self.clone_b.forced_termination_used)

    @property
    def independent_identities(self) -> bool:
        return (
            self.different_machine_sid
            and self.different_machine_guid
            and self.different_hostname
            and self.base_immutable
            and self.shutdowns_were_natural
            and self.residual_after_teardown.clean
        )


def _machine_sid(account_sid: str) -> str:
    """Strip the trailing account RID so two accounts on one machine do not look distinct."""
    parts = account_sid.split("-")
    return "-".join(parts[:-_RID_COMPONENTS])


def _sha256(path: Path) -> str:
    result = subprocess.run(
        ["shasum", "-a", "256", str(path)], capture_output=True, text=True, check=True, timeout=900
    )
    return result.stdout.split()[0]


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def _processes_matching(pattern: str) -> list[str]:
    """List matching process ids. A pgrep failure other than 'no match' is fatal, not empty."""
    result = subprocess.run(["pgrep", "-f", pattern], capture_output=True, text=True, timeout=30)
    if result.returncode not in (0, 1):
        raise RuntimeError(f"cannot inventory processes matching {pattern!r}: {result.stderr}")
    return result.stdout.split()


class Clone:
    """One booted clone: its overlay, per-run TPM, forwarded WinRM port, and QEMU process."""

    def __init__(self, name: str, base: Path, workdir: Path, code: Path, vars_template: Path):
        self.name = name
        self.overlay = workdir / f"{name}.qcow2"
        self.tpm_state = workdir / f"{name}-tpm"
        self.tpm_socket = Path("/tmp") / f"cl{os.getpid()}{name[-1]}.sock"
        self.vars_file = workdir / f"{name}-vars.fd"
        self.serial_log = workdir / f"{name}.log"
        self.winrm_port = _free_port()

        subprocess.run(
            ["qemu-img", "create", "-f", "qcow2", "-b", str(base.resolve()), "-F", "qcow2",
             str(self.overlay)],
            check=True, capture_output=True, text=True, timeout=120,
        )
        shutil.copyfile(vars_template, self.vars_file)
        self.tpm_state.mkdir(exist_ok=True)
        self.tpm = subprocess.Popen(
            ["swtpm", "socket", "--tpm2", "--tpmstate", f"dir={self.tpm_state}",
             "--ctrl", f"type=unixio,path={self.tpm_socket}", "--flags", "startup-clear"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        time.sleep(3)
        self.guest = subprocess.Popen(
            ["qemu-system-aarch64", "-M", "virt-11.0,gic-version=3", "-accel", "hvf",
             "-cpu", "host", "-smp", "4", "-m", "6144",
             "-drive", f"if=pflash,format=raw,readonly=on,file={code}",
             "-drive", f"if=pflash,format=raw,file={self.vars_file}",
             "-chardev", f"socket,id=chrtpm,path={self.tpm_socket}",
             "-tpmdev", "emulator,id=tpm0,chardev=chrtpm",
             "-device", "tpm-tis-device,tpmdev=tpm0",
             "-device", "ramfb", "-device", "qemu-xhci,id=usb",
             "-device", "usb-kbd", "-device", "usb-tablet",
             "-device", "nvme,drive=target,serial=winnvme",
             "-drive", f"if=none,id=target,file={self.overlay},format=qcow2",
             "-netdev", f"user,id=net0,hostfwd=tcp::{self.winrm_port}-:5985",
             "-device", "virtio-net-pci,netdev=net0",
             "-serial", f"file:{self.serial_log}", "-display", "none"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

    def read_identity(self, password: str, deadline_seconds: float) -> GuestIdentity:
        """Wait for specialize + WinRM, then read the identity. A clone that never answers raises."""
        import winrm

        deadline = time.time() + deadline_seconds
        last_error: Exception | None = None
        while time.time() < deadline:
            try:
                session = winrm.Session(
                    f"http://127.0.0.1:{self.winrm_port}/wsman", auth=("labadmin", password),
                    transport="ntlm", read_timeout_sec=40, operation_timeout_sec=30,
                )
                result = session.run_ps(_IDENTITY_PS)
                if result.status_code == 0:
                    name, sid, guid, uuid, build, arch = result.std_out.decode().strip().split("|")
                    return GuestIdentity(
                        clone=self.name, hostname=name, machine_sid=_machine_sid(sid),
                        account_sid=sid, machine_guid=guid, system_uuid=uuid,
                        os_build=build, architecture=arch,
                    )
                last_error = RuntimeError(result.std_err.decode(errors="replace")[:200])
            except Exception as error:  # noqa: BLE001 - retained and re-raised with context below
                last_error = error
            time.sleep(20)
        raise RuntimeError(
            f"{self.name} did not become reachable over WinRM within {deadline_seconds}s"
        ) from last_error

    def destroy(self, identity: GuestIdentity, password: str) -> GuestIdentity:
        """Ask the guest to shut down, then remove its runtime state; record how it ended."""
        import winrm

        try:
            winrm.Session(
                f"http://127.0.0.1:{self.winrm_port}/wsman", auth=("labadmin", password),
                transport="ntlm", read_timeout_sec=25, operation_timeout_sec=20,
            ).run_ps("Stop-Computer -Force")
        except Exception:  # noqa: BLE001 - the transport drops as the guest powers off
            pass

        for _ in range(72):
            if self.guest.poll() is not None:
                identity.guest_exited_naturally = True
                break
            time.sleep(5)
        else:
            self.guest.terminate()
            self.guest.wait(timeout=30)
            identity.forced_termination_used = True

        self.tpm.terminate()
        self.tpm.wait(timeout=15)
        self.tpm_socket.unlink(missing_ok=True)
        self.overlay.unlink(missing_ok=True)
        self.vars_file.unlink(missing_ok=True)
        shutil.rmtree(self.tpm_state, ignore_errors=True)
        return identity


def compare_clones(
    base: Path, workdir: Path, code: Path, vars_template: Path, password: str,
    readiness_seconds: float,
) -> CloneComparison:
    workdir.mkdir(parents=True, exist_ok=True)
    sha_before = _sha256(base)

    identities: dict[str, GuestIdentity] = {}
    for name in ("clone_a", "clone_b"):
        clone = Clone(name, base, workdir, code, vars_template)
        identity = clone.read_identity(password, readiness_seconds)
        identities[name] = clone.destroy(identity, password)

    residual = ResidualInventory(
        qemu_processes=_processes_matching("clone_a.qcow2") + _processes_matching("clone_b.qcow2"),
        swtpm_processes=_processes_matching(f"cl{os.getpid()}"),
        leftover_overlays=[str(p) for p in workdir.glob("clone_*.qcow2")],
        leftover_tpm_state=[str(p) for p in workdir.glob("clone_*-tpm")],
    )
    return CloneComparison(
        base_sha256_before=sha_before,
        base_sha256_after=_sha256(base),
        clone_a=identities["clone_a"],
        clone_b=identities["clone_b"],
        residual_after_teardown=residual,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", type=Path, required=True)
    parser.add_argument("--workdir", type=Path, required=True)
    parser.add_argument("--code", type=Path,
                        default=Path("/opt/homebrew/share/qemu/edk2-aarch64-code.fd"))
    parser.add_argument("--vars", type=Path,
                        default=Path("/opt/homebrew/share/qemu/edk2-arm-vars.fd"))
    parser.add_argument("--password-env", default="AUTOSUT_WIN_PASSWORD")
    parser.add_argument("--readiness-seconds", type=float, default=1200.0)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    comparison = compare_clones(
        args.base, args.workdir, args.code, args.vars,
        os.environ[args.password_env], args.readiness_seconds,
    )
    report = comparison.model_dump()
    report["assertions"] = {
        "different_machine_sid": comparison.different_machine_sid,
        "different_machine_guid": comparison.different_machine_guid,
        "different_hostname": comparison.different_hostname,
        "base_immutable": comparison.base_immutable,
        "shutdowns_were_natural": comparison.shutdowns_were_natural,
        "zero_residuals": comparison.residual_after_teardown.clean,
        "independent_identities": comparison.independent_identities,
    }
    rendered = json.dumps(report, indent=2)
    print(rendered)
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    return 0 if comparison.independent_identities else 1


if __name__ == "__main__":
    raise SystemExit(main())
