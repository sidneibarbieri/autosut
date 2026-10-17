"""Bounded boot probe: does Windows ARM64 reach its installer under QEMU + HVF on this host?

This answers the one question that gates the whole Windows track before any Vagrant box or full
install is attempted: can the present Windows ARM64 ISO boot far enough to show its installer on this
Apple-Silicon host. It boots QEMU headless for a fixed window, captures one screenshot over QMP, then
shuts the guest down. It installs nothing and leaves no VM running.

Device choices reflect what Windows ARM64 can read without extra drivers: the install media is a
USB-storage CD (Windows has an inbox USB mass-storage driver, unlike virtio-scsi), and the target disk
is NVMe (also inbox). Firmware is the permissive edk2 pair so Secure Boot, in setup mode, does not
reject the boot -- Secure Boot and TPM belong to the full install step, not to reaching the installer.
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


class BootProbeResult(BaseModel):
    """What the probe observed, so a reviewer can judge boot without watching the screen."""

    model_config = ConfigDict(extra="forbid")

    still_running_at_capture: bool
    screenshot: str
    screenshot_bytes: int
    boot_seconds: float
    qemu_command: list[str]


def _qmp(sock_path: Path, commands: list[dict], timeout_seconds: float = 20.0) -> None:
    """Run a minimal QMP exchange: read the greeting, negotiate, then issue each command in order.

    The socket carries an explicit timeout so a QMP call against a guest that has wedged the monitor
    raises instead of blocking the probe forever -- observability must never depend on the thing it
    observes staying healthy.
    """
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(timeout_seconds)
        client.connect(str(sock_path))
        stream = client.makefile("rwb", buffering=0)
        stream.readline()  # server greeting
        for payload in [{"execute": "qmp_capabilities"}, *commands]:
            stream.write((json.dumps(payload) + "\n").encode())
            stream.readline()  # command reply


def _start_swtpm(workdir: Path) -> tuple[subprocess.Popen, Path]:
    """Start a software TPM 2.0 and return its process and the data socket QEMU attaches to.

    Windows 11 documents TPM 2.0 and UEFI Secure Boot as requirements; this lets a probe present
    that baseline. The socket lives under /tmp to stay within the macOS sun_path length limit.
    """
    state_dir = workdir / "tpm"
    state_dir.mkdir(exist_ok=True)
    # QEMU's tpm-emulator backend speaks the swtpm control protocol over the --ctrl socket, so that
    # is the socket the QEMU chardev must connect to; no separate command socket is used here.
    socket_path = Path("/tmp") / f"wtpm{os.getpid()}.sock"
    process = subprocess.Popen(
        ["swtpm", "socket", "--tpm2", "--tpmstate", f"dir={state_dir}",
         "--ctrl", f"type=unixio,path={socket_path}",
         "--flags", "startup-clear"],
        stdout=subprocess.DEVNULL, stderr=(workdir / "swtpm.stderr.log").open("wb"),
    )
    deadline = time.monotonic() + 10
    while not socket_path.exists() and process.poll() is None and time.monotonic() < deadline:
        time.sleep(0.2)
    return process, socket_path


def _build_command(
    paths: dict[str, Path], vars_file: Path, qmp_sock: Path, serial_log: Path,
    memory_mib: int, tpm_socket: Path | None, machine: str,
) -> list[str]:
    # The PL011 UART is routed to a file so the firmware's UEFI console output (and any text the
    # Windows boot manager writes through UEFI ConOut) is captured independently of the graphics
    # framebuffer: the serial log survives even when a screenshot shows a stale frame.
    command = [
        "qemu-system-aarch64",
        "-M", machine,
        "-accel", "hvf", "-cpu", "host", "-smp", "4", "-m", str(memory_mib),
        "-drive", f"if=pflash,format=raw,readonly=on,file={paths['code']}",
        "-drive", f"if=pflash,format=raw,file={vars_file}",
        "-device", "virtio-gpu-pci",
        "-device", "qemu-xhci,id=usb", "-device", "usb-kbd", "-device", "usb-tablet",
        "-device", "nvme,drive=target,serial=winnvme",
        "-drive", f"if=none,id=target,file={paths['disk']},format=qcow2",
        "-device", "usb-storage,drive=install,bus=usb.0",
        "-drive", f"if=none,id=install,file={paths['iso']},media=cdrom,readonly=on",
        "-qmp", f"unix:{qmp_sock},server,nowait",
        "-serial", f"file:{serial_log}",
        "-display", "none",
    ]
    if tpm_socket is not None:
        command += [
            "-chardev", f"socket,id=chrtpm,path={tpm_socket}",
            "-tpmdev", "emulator,id=tpm0,chardev=chrtpm",
            "-device", "tpm-tis-device,tpmdev=tpm0",
        ]
    return command


def probe(
    iso: Path, code: Path, vars_template: Path, workdir: Path, boot_seconds: float,
    tpm: bool, machine: str, memory_mib: int,
) -> BootProbeResult:
    workdir.mkdir(parents=True, exist_ok=True)
    vars_file = workdir / "uefi_vars.fd"
    shutil.copyfile(vars_template, vars_file)
    disk = workdir / "target.qcow2"
    subprocess.run(
        ["qemu-img", "create", "-f", "qcow2", str(disk), "64G"],
        check=True, capture_output=True, text=True, timeout=60,
    )

    tpm_process: subprocess.Popen | None = None
    tpm_socket: Path | None = None
    if tpm:
        tpm_process, tpm_socket = _start_swtpm(workdir)

    # A UNIX socket path must stay under 104 bytes (macOS sun_path); the scratchpad workdir is far
    # longer, so the QMP socket lives under /tmp with a short name and is removed afterwards.
    qmp_sock = Path("/tmp") / f"wq{os.getpid()}.sock"
    screenshot = workdir / "installer_screen.png"
    stderr_log = workdir / "qemu.stderr.log"
    serial_log = workdir / "serial.log"
    command = _build_command(
        {"code": code, "disk": disk, "iso": iso}, vars_file, qmp_sock, serial_log, memory_mib,
        tpm_socket, machine,
    )

    guest = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=stderr_log.open("wb"))
    try:
        while not qmp_sock.exists() and guest.poll() is None:
            time.sleep(0.5)
        started = time.monotonic()
        time.sleep(boot_seconds)
        still_running = guest.poll() is None
        if still_running:
            _qmp(qmp_sock, [
                {"execute": "screendump", "arguments": {"filename": str(screenshot), "format": "png"}},
                {"execute": "quit"},
            ])
        elapsed = round(time.monotonic() - started, 1)
    finally:
        if guest.poll() is None:
            guest.terminate()
            guest.wait(timeout=30)
        qmp_sock.unlink(missing_ok=True)
        if tpm_process is not None:
            tpm_process.terminate()
            tpm_process.wait(timeout=10)
            tpm_socket.unlink(missing_ok=True)
            Path(f"{tpm_socket}.ctrl").unlink(missing_ok=True)

    return BootProbeResult(
        still_running_at_capture=still_running,
        screenshot=str(screenshot) if screenshot.exists() else "",
        screenshot_bytes=screenshot.stat().st_size if screenshot.exists() else 0,
        boot_seconds=elapsed,
        qemu_command=command,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iso", type=Path, required=True)
    parser.add_argument("--code", type=Path, default=Path("/opt/homebrew/share/qemu/edk2-aarch64-code.fd"))
    parser.add_argument("--vars", type=Path, default=Path("/opt/homebrew/share/qemu/edk2-arm-vars.fd"))
    parser.add_argument("--workdir", type=Path, required=True)
    parser.add_argument("--boot-seconds", type=float, default=80.0)
    parser.add_argument("--tpm", action="store_true", help="attach a software TPM 2.0 via swtpm")
    parser.add_argument(
        "--machine", default="virt-11.0,gic-version=3",
        help="pinned QEMU machine type and options, e.g. virt-11.0,gic-version=3,highmem=off",
    )
    parser.add_argument(
        "--memory-mib", type=int, default=6144,
        help="guest RAM; must fit under 32-bit addressing when the machine sets highmem=off",
    )
    args = parser.parse_args()

    result = probe(
        args.iso, args.code, args.vars, args.workdir, args.boot_seconds, args.tpm, args.machine,
        args.memory_mib,
    )
    print(result.model_dump_json(indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
