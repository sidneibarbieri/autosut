"""Install a credential-free Windows ARM64 candidate up to the first reboot.

The output is a candidate, not a qualified base. Offline inspection must prove
the installation phase and absence of account credentials before promotion.
"""

from __future__ import annotations

import argparse
import json
import select
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path
from xml.etree import ElementTree

from pydantic import BaseModel, ConfigDict

SCRIPTS_DIR = Path(__file__).resolve().parents[1]
TEMPLATE = (
    SCRIPTS_DIR.parent
    / "lab/provisioning/windows-workgroup-lateral/autounattend.host_a.xml"
)
EDK2_CODE = Path("/opt/homebrew/share/qemu/edk2-aarch64-code.fd")
EDK2_VARS = Path("/opt/homebrew/share/qemu/edk2-arm-vars.fd")
UNATTEND_NAMESPACE = "urn:schemas-microsoft-com:unattend"


class BaseBuildInputs(BaseModel):
    """Files owned by one isolated installation attempt."""

    model_config = ConfigDict(extra="forbid")

    install_iso: Path
    answer_disk: Path
    answer_iso: Path
    target: Path
    firmware_vars: Path
    tpm_socket: Path
    serial_log: Path
    monitor_socket: Path
    qmp_socket: Path


def windows_pe_answer(template: Path) -> bytes:
    """Retain only disk installation settings, excluding account creation."""
    root = ElementTree.parse(template).getroot()
    settings_tag = f"{{{UNATTEND_NAMESPACE}}}settings"
    settings = root.findall(settings_tag)
    if [item.attrib.get("pass") for item in settings].count("windowsPE") != 1:
        raise ValueError("expected exactly one windowsPE pass")
    for item in settings:
        if item.attrib.get("pass") != "windowsPE":
            root.remove(item)
    ElementTree.register_namespace("", UNATTEND_NAMESPACE)
    ElementTree.register_namespace("wcm", "http://schemas.microsoft.com/WMIConfig/2002/State")
    answer = ElementTree.tostring(root, encoding="utf-8", xml_declaration=True)
    if any(marker in answer for marker in (b"Password", b"LocalAccount", b"AutoLogon", b"{{")):
        raise ValueError("installation answer contains account or template material")
    return answer


def startup_script() -> bytes:
    """Boot the installer from the second UEFI filesystem."""
    return b"fs1:\\EFI\\BOOT\\BOOTAA64.EFI\r\n"


def is_guest_reset(message: dict[str, object]) -> bool:
    """Distinguish Setup's reboot from a host signal or shutdown."""
    data = message.get("data")
    return (
        message.get("event") == "SHUTDOWN"
        and isinstance(data, dict)
        and data.get("guest") is True
        and data.get("reason") == "guest-reset"
    )


def boot_prompt_visible(screen_text: str) -> bool:
    """Recognize the installer prompt without treating Shell as Setup."""
    return "press any key to boot from cd or dvd" in screen_text.lower()


def _monitor_command(monitor_path: Path, command: str) -> None:
    subprocess.run(
        ["socat", "-T", "2", "-", f"UNIX-CONNECT:{monitor_path}"],
        input=f"{command}\n".encode(),
        check=True, capture_output=True, timeout=5,
    )


def _acknowledge_boot_prompt(
    guest: subprocess.Popen[bytes], monitor_path: Path,
) -> None:
    screenshot = monitor_path.with_name("installer-boot-screen.ppm")
    deadline = time.monotonic() + 120
    while guest.poll() is None and time.monotonic() < deadline:
        screenshot.unlink(missing_ok=True)
        _monitor_command(monitor_path, f"screendump {screenshot}")
        if not screenshot.is_file() or screenshot.stat().st_size == 0:
            time.sleep(0.3)
            continue
        text_result = subprocess.run(
            ["tesseract", str(screenshot), "stdout"],
            check=True, capture_output=True, text=True, timeout=10,
        )
        if boot_prompt_visible(text_result.stdout):
            _monitor_command(monitor_path, "sendkey spc")
            return
        time.sleep(0.3)
    raise RuntimeError("Windows installer boot prompt was not observed")


def install_qemu_command(inputs: BaseBuildInputs) -> list[str]:
    """Stop at Setup's first reboot, before specialize can consume credentials."""
    return [
        "qemu-system-aarch64", "-M", "virt-11.0,gic-version=3", "-accel", "hvf",
        "-cpu", "host", "-smp", "4", "-m", "6144",
        "-drive", f"if=pflash,format=raw,readonly=on,file={EDK2_CODE}",
        "-drive", f"if=pflash,format=raw,file={inputs.firmware_vars}",
        "-chardev", f"socket,id=chrtpm,path={inputs.tpm_socket}",
        "-tpmdev", "emulator,id=tpm0,chardev=chrtpm",
        "-device", "tpm-tis-device,tpmdev=tpm0", "-device", "ramfb",
        "-device", "qemu-xhci,id=usb", "-device", "usb-kbd", "-device", "usb-tablet",
        "-device", "nvme,drive=target,serial=winnvme,bootindex=3",
        "-drive", f"if=none,id=target,file={inputs.target},format=qcow2",
        "-drive", f"if=none,id=answer,file={inputs.answer_disk},format=raw,readonly=on",
        "-device", "usb-storage,drive=answer",
        "-drive", f"if=none,id=installer,media=cdrom,file={inputs.install_iso},readonly=on",
        "-device", "usb-storage,drive=installer,bootindex=1",
        "-drive", f"if=none,id=unattend,media=cdrom,file={inputs.answer_iso},readonly=on",
        "-device", "usb-storage,drive=unattend",
        "-nic", "none", "-serial", f"file:{inputs.serial_log}",
        "-monitor", f"unix:{inputs.monitor_socket},server=on,wait=off",
        "-qmp", f"unix:{inputs.qmp_socket},server=on,wait=off",
        "-display", "none", "-no-reboot",
    ]


def create_answer_disk(path: Path) -> None:
    """Place only the UEFI startup script on FAT."""
    subprocess.run(
        ["qemu-img", "create", "-f", "raw", str(path), "64M"],
        check=True, capture_output=True, text=True, timeout=120,
    )
    subprocess.run(
        ["mformat", "-i", str(path), "-F", "-v", "AUTOSUT", "::"],
        check=True, capture_output=True, text=True, timeout=120,
    )
    with tempfile.TemporaryDirectory(prefix="answer-files-", dir=path.parent) as directory:
        answer_dir = Path(directory)
        startup = answer_dir / "startup.nsh"
        startup.write_bytes(startup_script())
        subprocess.run(
            ["mcopy", "-i", str(path), str(startup), "::"],
            check=True, capture_output=True, text=True, timeout=120,
        )


def create_answer_iso(path: Path) -> None:
    """Expose the credential-free answer through Setup's CD-ROM search path."""
    with tempfile.TemporaryDirectory(prefix="answer-iso-", dir=path.parent) as directory:
        answer = Path(directory) / "Autounattend.xml"
        answer.write_bytes(windows_pe_answer(TEMPLATE))
        subprocess.run(
            ["xorriso", "-as", "mkisofs", "-quiet", "-J", "-V", "AUTOSUT", "-o", str(path),
             str(answer)],
            check=True, capture_output=True, text=True, timeout=120,
        )


def read_answer_disk_file(path: Path, name: str) -> bytes:
    """Read a named FAT file for deterministic media validation."""
    if name != "startup.nsh":
        raise ValueError("unsupported answer-media file")
    return subprocess.run(
        ["mtype", "-i", str(path), f"::{name}"],
        check=True, capture_output=True, timeout=120,
    ).stdout


def _prepare_media(inputs: BaseBuildInputs) -> None:
    create_answer_disk(inputs.answer_disk)
    create_answer_iso(inputs.answer_iso)
    subprocess.run(
        ["qemu-img", "create", "-f", "qcow2", str(inputs.target), "70G"],
        check=True, capture_output=True, text=True, timeout=120,
    )
    shutil.copyfile(EDK2_VARS, inputs.firmware_vars)


def netkvm_upload_commands(driver_dir: Path) -> list[str]:
    """Copy the signed ARM64 NIC package to the path used at first logon."""
    files = sorted(path for path in driver_dir.iterdir() if path.is_file())
    if not {"netkvm.inf", "netkvm.cat", "netkvm.sys"}.issubset(
        {path.name for path in files}
    ):
        raise ValueError("incomplete NetKVM ARM64 driver package")
    if any("\n" in path.name or " " in path.name for path in files):
        raise ValueError("unsupported NetKVM filename")
    return [
        "run", "mount /dev/sda3 /", "mkdir-p /drivers/netkvm",
        *(f"upload /work/netkvm/{path.name} /drivers/netkvm/{path.name}" for path in files),
        "is-file /drivers/netkvm/netkvm.inf",
    ]


def stage_netkvm_driver(
    target: Path, virtio_iso: Path, workdir: Path, guestfish_image: str,
) -> None:
    """Stage the NIC driver offline, without booting Windows or adding a user."""
    with tempfile.TemporaryDirectory(prefix="netkvm-", dir=workdir) as directory:
        driver_dir = Path(directory) / "netkvm"
        subprocess.run(
            ["xorriso", "-indev", str(virtio_iso), "-osirrox", "on", "-extract",
             "/NetKVM/w11/ARM64", str(driver_dir)],
            check=True, capture_output=True, text=True, timeout=120,
        )
        result = subprocess.run(
            ["docker", "run", "--rm", "-i", "--network", "none",
             "--platform", "linux/arm64", "--privileged",
             "-e", "LIBGUESTFS_BACKEND=direct",
             "-e", "LIBGUESTFS_BACKEND_SETTINGS=force_tcg",
             "-v", f"{workdir}:{workdir}:rw",
             "-v", f"{driver_dir}:/work/netkvm:ro",
             guestfish_image, "--rw", "-a", str(target)],
            input="\n".join(netkvm_upload_commands(driver_dir)) + "\n",
            check=True, stdout=subprocess.PIPE, text=True, timeout=900,
        )
        if result.stdout.strip() != "true":
            raise RuntimeError("guestfish did not confirm NetKVM staging")


def _wait_for_guest_reset(
    guest: subprocess.Popen[bytes], qmp_path: Path, monitor_path: Path,
) -> None:
    deadline = time.monotonic() + 3600
    while not qmp_path.exists() and guest.poll() is None and time.monotonic() < deadline:
        time.sleep(0.1)
    if not qmp_path.exists():
        raise RuntimeError("QMP did not start")

    observed_reset = False
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as qmp:
        qmp.connect(str(qmp_path))
        with qmp.makefile("rwb", buffering=0) as messages:
            greeting = json.loads(messages.readline())
            if "QMP" not in greeting:
                raise RuntimeError("QMP greeting missing")
            messages.write(b'{"execute":"qmp_capabilities"}\r\n')
            if "return" not in json.loads(messages.readline()):
                raise RuntimeError("QMP capabilities rejected")
            _acknowledge_boot_prompt(guest, monitor_path)
            while time.monotonic() < deadline:
                readable, _, _ = select.select([qmp], [], [], 1)
                if readable:
                    line = messages.readline()
                    if not line:
                        break
                    observed_reset |= is_guest_reset(json.loads(line))
                if guest.poll() is not None and not readable:
                    break
            else:
                raise TimeoutError("Windows Setup did not reboot within one hour")

    exit_code = guest.wait(timeout=30)
    if exit_code != 0 or not observed_reset:
        raise RuntimeError(
            f"Windows installer stopped without a guest reset (exit={exit_code})"
        )


def _run_installer(inputs: BaseBuildInputs, workdir: Path) -> None:
    tpm_state = workdir / "tpm-state"
    tpm_state.mkdir()
    with (workdir / "swtpm.log").open("wb") as tpm_log, \
         (workdir / "qemu.stdout.log").open("wb") as qemu_out, \
         (workdir / "qemu.stderr.log").open("wb") as qemu_err:
        tpm = subprocess.Popen(
            ["swtpm", "socket", "--tpm2", "--tpmstate", f"dir={tpm_state}",
             "--ctrl", f"type=unixio,path={inputs.tpm_socket}",
             "--flags", "startup-clear"],
            stdout=tpm_log, stderr=tpm_log,
        )
        try:
            time.sleep(3)
            guest = subprocess.Popen(install_qemu_command(inputs), stdout=qemu_out,
                                     stderr=qemu_err)
            try:
                _wait_for_guest_reset(guest, inputs.qmp_socket, inputs.monitor_socket)
            finally:
                if guest.poll() is None:
                    guest.terminate()
                    guest.wait(timeout=30)
        finally:
            if tpm.poll() is None:
                tpm.terminate()
                tpm.wait(timeout=30)


def build_candidate(
    install_iso: Path, virtio_iso: Path, workdir: Path, guestfish_image: str,
) -> Path:
    """Create a fresh, unqualified candidate without touching existing bases."""
    install_iso = install_iso.resolve(strict=True)
    virtio_iso = virtio_iso.resolve(strict=True)
    if not EDK2_CODE.is_file() or not EDK2_VARS.is_file():
        raise FileNotFoundError("ARM64 UEFI firmware is unavailable")
    workdir.mkdir(mode=0o700, parents=True, exist_ok=False)
    inputs = BaseBuildInputs(
        install_iso=install_iso,
        answer_disk=workdir / "answer.img",
        answer_iso=workdir / "answer.iso",
        target=workdir / "candidate.qcow2",
        firmware_vars=workdir / "firmware-vars.fd",
        tpm_socket=workdir / "tpm.sock",
        serial_log=workdir / "guest-serial.log",
        monitor_socket=workdir / "monitor.sock",
        qmp_socket=workdir / "qmp.sock",
    )
    _prepare_media(inputs)
    _run_installer(inputs, workdir)
    stage_netkvm_driver(inputs.target, virtio_iso, workdir, guestfish_image)
    return inputs.target


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--install-iso", type=Path, required=True)
    parser.add_argument("--virtio-iso", type=Path, required=True)
    parser.add_argument("--workdir", type=Path, required=True)
    parser.add_argument("--guestfish-image", default="autosut-guestfish:bookworm")
    arguments = parser.parse_args()
    candidate = build_candidate(
        arguments.install_iso, arguments.virtio_iso,
        arguments.workdir, arguments.guestfish_image,
    )
    print(f"Unqualified Windows base candidate: {candidate}")
    print("Offline phase and credential-residue inspection still required")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
