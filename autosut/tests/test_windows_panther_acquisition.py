"""Offline acquisition must inspect the runtime backing chain without mutation."""

import io
import json
import subprocess
import sys
import tarfile
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))


@pytest.mark.parametrize("legacy_hashlib", [False, True])
def test_acquisition_mounts_complete_chain_readonly_and_reads_archive(tmp_path, monkeypatch, legacy_hashlib):
    from infra import windows_panther_acquisition
    if legacy_hashlib:
        monkeypatch.delattr(windows_panther_acquisition.hashlib, "file_digest", raising=False)

    overlay = tmp_path / "runtime.qcow2"
    base = tmp_path / "base.qcow2"
    overlay.touch()
    base.touch()
    output = tmp_path / "acquisition"
    calls = []

    def run(command, **kwargs):
        calls.append((command, kwargs))
        if command[0] == "qemu-img":
            return SimpleNamespace(stdout=json.dumps([{"filename": str(overlay)}, {"filename": str(base)}]))
        with tarfile.open(output / "panther.tar", "w") as archive:
            member = tarfile.TarInfo("./setupact.log")
            member.size = 5
            archive.addfile(member, io.BytesIO(b"clean"))
        return SimpleNamespace(stdout="")

    monkeypatch.setattr(windows_panther_acquisition.subprocess, "run", run)
    receipt = windows_panther_acquisition.collect_stopped_panther(overlay, output, "sha256:synthetic")
    docker_command, options = calls[1]
    assert f"{overlay}:{overlay}:ro" in docker_command
    assert f"{base}:{base}:ro" in docker_command
    assert "--ro" in docker_command
    assert "mount-ro /dev/sda3 /" in options["input"]
    assert receipt.regular_files == 1
    assert receipt.content_bytes == 5
    assert not receipt.secret_audit_performed
    assert len(receipt.archive_sha256) == 64


def test_successful_container_without_delivered_archive_fails(tmp_path, monkeypatch):
    from infra import windows_panther_acquisition

    overlay = tmp_path / "runtime.qcow2"
    overlay.touch()
    def run(command, **kwargs):
        return SimpleNamespace(stdout=json.dumps([{"filename": str(overlay)}]) if command[0] == "qemu-img" else "")
    monkeypatch.setattr(windows_panther_acquisition.subprocess, "run", run)
    with pytest.raises(FileNotFoundError):
        windows_panther_acquisition.collect_stopped_panther(overlay, tmp_path / "acquisition", "sha256:synthetic")


def test_failed_guestfish_retains_private_diagnostic_and_original_error(tmp_path, monkeypatch):
    from infra import windows_panther_acquisition

    overlay = tmp_path / "runtime.qcow2"
    overlay.touch()
    output = tmp_path / "acquisition"

    def run(command, **kwargs):
        if command[0] == "qemu-img":
            return SimpleNamespace(stdout=json.dumps([{"filename": str(overlay)}]))
        raise subprocess.CalledProcessError(
            1, command, stderr="libguestfs: mount failed: synthetic issue",
        )

    monkeypatch.setattr(windows_panther_acquisition.subprocess, "run", run)
    with pytest.raises(subprocess.CalledProcessError) as failure:
        windows_panther_acquisition.collect_stopped_panther(
            overlay, output, "sha256:synthetic", secret="Aa9!synthetic-only",
        )

    diagnostic = output / "guestfish.stderr.log"
    assert failure.value.returncode == 1
    assert "synthetic issue" in diagnostic.read_text(encoding="utf-8")
    assert diagnostic.stat().st_mode & 0o777 == 0o600


def test_failed_guestfish_does_not_retain_credential_in_diagnostic(tmp_path, monkeypatch):
    from infra import windows_panther_acquisition
    from infra.windows_secret_audit import SecretResidueDetected

    overlay = tmp_path / "runtime.qcow2"
    overlay.touch()
    output = tmp_path / "acquisition"
    secret = "Aa9!synthetic-only"

    def run(command, **kwargs):
        if command[0] == "qemu-img":
            return SimpleNamespace(stdout=json.dumps([{"filename": str(overlay)}]))
        raise subprocess.CalledProcessError(1, command, stderr=f"guestfish echoed {secret}")

    monkeypatch.setattr(windows_panther_acquisition.subprocess, "run", run)
    with pytest.raises(SecretResidueDetected):
        windows_panther_acquisition.collect_stopped_panther(
            overlay, output, "sha256:synthetic", secret=secret,
        )
    assert not (output / "guestfish.stderr.log").exists()


@pytest.mark.parametrize(
    ("answer", "expected_values"),
    [
        (b"<unattend><Password>synthetic</Password></unattend>", 1),
        (b"<unattend><Password><Value>synthetic</Value><PlainText>false</PlainText></Password></unattend>", 1),
        (b"<unattend><Password><Value></Value><PlainText>false</PlainText></Password></unattend>", 0),
    ],
)
def test_panther_receipt_counts_embedded_answer_passwords(tmp_path, answer, expected_values):
    from infra.windows_panther_acquisition import _inspect_acquisition

    archive_path = tmp_path / "panther.tar"
    with tarfile.open(archive_path, "w") as archive:
        member = tarfile.TarInfo("./unattend.xml")
        member.size = len(answer)
        archive.addfile(member, io.BytesIO(answer))

    receipt = _inspect_acquisition(archive_path)
    assert receipt.unattend_password_values == expected_values
    assert not receipt.secret_audit_performed


@pytest.mark.parametrize(
    ("member_name", "content", "expected_leak"),
    [
        ("./setupact.log", b"clean", False),
        ("./setupact.log", b"Aa9!synthetic-only", True),
        ("./unattend.xml", b"<unattend><Password>different</Password></unattend>", True),
    ],
)
def test_panther_secret_audit_binds_archive_and_reports_bounded_leaks(
    tmp_path, member_name, content, expected_leak,
):
    from infra.windows_panther_acquisition import (
        _inspect_acquisition,
        audit_acquired_panther,
    )

    acquisition = tmp_path / "acquisition"
    acquisition.mkdir()
    archive_path = acquisition / "panther.tar"
    with tarfile.open(archive_path, "w") as archive:
        member = tarfile.TarInfo(member_name)
        member.size = len(content)
        archive.addfile(member, io.BytesIO(content))
    receipt = _inspect_acquisition(archive_path)
    (acquisition / "acquisition.json").write_text(receipt.model_dump_json(), encoding="utf-8")

    audit = audit_acquired_panther(acquisition, "Aa9!synthetic-only")
    assert audit.archive_sha256 == receipt.archive_sha256
    assert audit.regular_files == 1
    assert audit.completed
    assert audit.leak_found is expected_leak
    assert "synthetic-only" not in audit.model_dump_json()


def test_panther_secret_audit_rejects_unbound_receipt(tmp_path):
    from infra.windows_panther_acquisition import (
        _inspect_acquisition,
        audit_acquired_panther,
    )

    acquisition = tmp_path / "acquisition"
    acquisition.mkdir()
    archive_path = acquisition / "panther.tar"
    with tarfile.open(archive_path, "w") as archive:
        member = tarfile.TarInfo("./setupact.log")
        member.size = 5
        archive.addfile(member, io.BytesIO(b"clean"))
    receipt = _inspect_acquisition(archive_path)
    (acquisition / "acquisition.json").write_text(
        receipt.model_copy(update={"archive_sha256": "0" * 64}).model_dump_json(), encoding="utf-8",
    )

    with pytest.raises(ValueError, match="does not match"):
        audit_acquired_panther(acquisition, "Aa9!synthetic-only")
