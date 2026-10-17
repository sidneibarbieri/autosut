"""The Windows base is installed without provisioning a standing account."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from xml.etree import ElementTree

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from infra import windows_base_builder


def test_install_answer_contains_only_windows_pe_settings():
    template = (
        Path(__file__).resolve().parents[1]
        / "lab/provisioning/windows-workgroup-lateral/autounattend.host_a.xml"
    )

    answer = windows_base_builder.windows_pe_answer(template)
    root = ElementTree.fromstring(answer)
    namespace = {"unattend": "urn:schemas-microsoft-com:unattend"}
    settings = root.findall("unattend:settings", namespace)

    assert [setting.attrib["pass"] for setting in settings] == ["windowsPE"]
    assert b"{{AUTOSUT_WINDOWS_LOCAL_ADMIN_PASSWORD}}" not in answer
    assert b"<Password>" not in answer
    assert b"<LocalAccount" not in answer


def test_install_command_stops_before_first_specialize(tmp_path):
    inputs = windows_base_builder.BaseBuildInputs(
        install_iso=tmp_path / "windows.iso",
        answer_disk=tmp_path / "answer.img",
        answer_iso=tmp_path / "answer.iso",
        target=tmp_path / "fresh-base.qcow2",
        firmware_vars=tmp_path / "firmware-vars.fd",
        tpm_socket=tmp_path / "tpm.sock",
        serial_log=tmp_path / "serial.log",
        monitor_socket=tmp_path / "monitor.sock",
        qmp_socket=tmp_path / "qmp.sock",
    )

    command = windows_base_builder.install_qemu_command(inputs)
    joined = " ".join(command)

    assert "-no-reboot" in command
    assert "usb-storage,drive=installer,bootindex=1" in command
    assert "usb-storage,drive=answer" in command
    assert "usb-storage,drive=unattend" in command
    assert f"file={inputs.answer_iso}" in joined
    assert command.index("usb-storage,drive=answer") < command.index(
        "usb-storage,drive=installer,bootindex=1"
    )
    assert f"file={inputs.answer_disk},format=raw" in joined
    assert f"file={inputs.target}" in joined
    assert "hostfwd" not in joined
    assert "AUTOSUT_WIN_PASSWORD" not in joined


def test_only_guest_initiated_reset_counts_as_install_boundary():
    assert windows_base_builder.is_guest_reset(
        {"event": "SHUTDOWN", "data": {"guest": True, "reason": "guest-reset"}},
    )
    assert not windows_base_builder.is_guest_reset(
        {"event": "SHUTDOWN", "data": {"guest": False, "reason": "host-signal"}},
    )
    assert not windows_base_builder.is_guest_reset(
        {"event": "SHUTDOWN", "data": {"guest": True, "reason": "guest-shutdown"}},
    )


def test_startup_script_loads_installer_without_account_material():
    script = windows_base_builder.startup_script()

    assert b"fs1:\\EFI\\BOOT\\BOOTAA64.EFI" in script
    assert b"Password" not in script


def test_boot_prompt_recognition_ignores_unrelated_setup_text():
    assert windows_base_builder.boot_prompt_visible(
        "Press any key to boot from CD or DVD......\nShell> _"
    )
    assert not windows_base_builder.boot_prompt_visible(
        "UEFI Interactive Shell\nShell> _"
    )
    assert not windows_base_builder.boot_prompt_visible(
        "Windows Setup\nSelect language"
    )


def test_boot_prompt_waits_until_qemu_produces_a_screenshot(tmp_path, monkeypatch):
    monitor = tmp_path / "monitor.sock"
    commands = []

    class RunningGuest:
        def poll(self):
            return None

    def monitor_command(path, command):
        assert path == monitor
        commands.append(command)
        if command.startswith("screendump") and commands.count(command) == 2:
            (tmp_path / "installer-boot-screen.ppm").write_bytes(b"P6\n1 1\n255\n000")

    def recognize_screenshot(*args, **kwargs):
        assert (tmp_path / "installer-boot-screen.ppm").is_file()
        return subprocess.CompletedProcess(args=args, returncode=0,
                                           stdout="Press any key to boot from CD or DVD")

    monkeypatch.setattr(windows_base_builder, "_monitor_command", monitor_command)
    monkeypatch.setattr(windows_base_builder.subprocess, "run", recognize_screenshot)
    monkeypatch.setattr(windows_base_builder.time, "sleep", lambda _: None)

    windows_base_builder._acknowledge_boot_prompt(RunningGuest(), monitor)

    assert commands[-1] == "sendkey spc"
    assert len([command for command in commands if command.startswith("screendump")]) == 2


@pytest.mark.windows_media
def test_answer_disk_is_fat_and_contains_no_account_credential(tmp_path):
    disk = tmp_path / "answer.img"

    windows_base_builder.create_answer_disk(disk)

    startup = windows_base_builder.read_answer_disk_file(disk, "startup.nsh")
    assert startup == windows_base_builder.startup_script()


@pytest.mark.windows_media
def test_setup_answer_is_on_separate_cdrom_without_account_credential(tmp_path):
    answer_iso = tmp_path / "answer.iso"
    extracted = tmp_path / "Autounattend.xml"

    windows_base_builder.create_answer_iso(answer_iso)
    visible_names = subprocess.run(
        ["xorriso", "-read_fs", "norock", "-indev", str(answer_iso), "-ls", "/"],
        check=True, capture_output=True, text=True,
    ).stdout
    subprocess.run(
        ["xorriso", "-indev", str(answer_iso), "-osirrox", "on", "-extract",
         "/Autounattend.xml", str(extracted)],
        check=True, capture_output=True, text=True,
    )

    assert "Autounattend.xml" in visible_names
    assert b"windowsPE" in extracted.read_bytes()
    assert b"Password" not in extracted.read_bytes()


def test_netkvm_staging_requires_signed_arm64_driver_files(tmp_path):
    driver_dir = tmp_path / "netkvm"
    driver_dir.mkdir()
    for filename in ("netkvm.inf", "netkvm.cat", "netkvm.sys"):
        (driver_dir / filename).write_bytes(b"synthetic")

    commands = windows_base_builder.netkvm_upload_commands(driver_dir)

    assert commands[:3] == ["run", "mount /dev/sda3 /", "mkdir-p /drivers/netkvm"]
    assert "upload /work/netkvm/netkvm.inf /drivers/netkvm/netkvm.inf" in commands
    assert commands[-1] == "is-file /drivers/netkvm/netkvm.inf"

    (driver_dir / "netkvm.cat").unlink()
    with pytest.raises(ValueError, match="incomplete NetKVM"):
        windows_base_builder.netkvm_upload_commands(driver_dir)
