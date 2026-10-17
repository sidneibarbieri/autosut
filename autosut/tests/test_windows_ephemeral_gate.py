"""Per-clone Windows credentials must never depend on a private image or saved secret."""

from __future__ import annotations

import hashlib
import io
import json
import os
import secrets
import subprocess
import sys
import tarfile
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from infra import windows_ephemeral_gate
from infra.windows_panther_acquisition import _inspect_acquisition
from infra.windows_secret_audit import SecretResidueDetected
from infrastructure.revision import write_revision_stamp
from infrastructure.windows_surface_scan import verify_scan


def test_cli_help_runs_without_pythonpath():
    script = Path(__file__).resolve().parents[1] / "scripts/infra/windows_ephemeral_gate.py"
    result = subprocess.run(
        [sys.executable, str(script), "--help"],
        capture_output=True, text=True, check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "--guestfish-image" in result.stdout
    assert "--acquire-panther" in result.stdout
    assert "--clear-panther-answer" in result.stdout


@pytest.mark.parametrize("docker_exit", [0, 1])
def test_panther_preflight_requires_a_docker_visible_root(monkeypatch, tmp_path, docker_exit):
    observed = []

    def run(command, **kwargs):
        observed.append(command)
        assert Path(command[-1]).is_file()
        return SimpleNamespace(returncode=docker_exit)

    monkeypatch.setattr(windows_ephemeral_gate.subprocess, "run", run)
    if docker_exit:
        with pytest.raises(RuntimeError, match="directory shared with Docker Desktop"):
            windows_ephemeral_gate.require_docker_visible_evidence_root(
                tmp_path, "autosut-guestfish:bookworm",
            )
    else:
        windows_ephemeral_gate.require_docker_visible_evidence_root(
            tmp_path, "autosut-guestfish:bookworm",
        )

    assert len(observed) == 1
    assert observed[0][:3] == ["docker", "run", "--rm"]
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize(("password_values", "expected_exit"), [(0, 0), (2, 1)])
def test_cli_retains_panther_in_run_and_refuses_embedded_passwords(
    monkeypatch, tmp_path, capsys, password_values, expected_exit,
):
    evidence_root = tmp_path / "evidence"
    base = tmp_path / "base.qcow2"
    agent = tmp_path / "agent.exe"
    base.touch()
    agent.touch()

    def prepare(base_path, temporary, guestfish_image):
        overlay = temporary / "prepared.qcow2"
        overlay.touch()
        return windows_ephemeral_gate.PreparedClone(
            overlay=overlay, password="synthetic-only",
        )

    def collect(overlay, output, guestfish_image, *, secret):
        assert secret == "synthetic-only"
        output.mkdir(parents=True)
        (output / "acquisition.json").write_text("{}", encoding="utf-8")
        return SimpleNamespace(unattend_password_values=password_values)

    def run(prepared, agent_path, root, label, *, stopped_disk_observer_factory):
        run_dir = root / "run-01"
        (run_dir / "windows-qemu").mkdir(parents=True)
        stopped_disk_observer_factory(run_dir)(prepared.overlay)
        return True

    monkeypatch.setattr(windows_ephemeral_gate, "prepare_overlay", prepare)
    monkeypatch.setattr(windows_ephemeral_gate, "require_closed_provisioning_files", lambda *_: None)
    monkeypatch.setattr(windows_ephemeral_gate, "require_docker_visible_evidence_root", lambda *_: None)
    monkeypatch.setattr(windows_ephemeral_gate, "collect_stopped_panther", collect)
    monkeypatch.setattr(windows_ephemeral_gate, "run_prepared_gate", run)
    monkeypatch.setattr(sys, "argv", [
        "windows_ephemeral_gate.py", "--base", str(base), "--agent", str(agent),
        "--evidence-root", str(evidence_root), "--acquire-panther",
    ])

    assert windows_ephemeral_gate.main() == expected_exit
    assert (evidence_root / "run-01/windows-qemu/panther-acquisition/acquisition.json").is_file()
    assert not list(evidence_root.glob("windows-credential-*"))
    assert "synthetic-only" not in capsys.readouterr().out


def test_cli_requires_acquisition_for_panther_cleanup(monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "argv", [
        "windows_ephemeral_gate.py", "--base", str(tmp_path / "base.qcow2"),
        "--agent", str(tmp_path / "agent.exe"),
        "--evidence-root", str(tmp_path / "evidence"), "--clear-panther-answer",
    ])
    with pytest.raises(SystemExit) as error:
        windows_ephemeral_gate.main()
    assert error.value.code == 2
    assert not (tmp_path / "evidence").exists()


def test_cli_blocks_open_deleted_provisioning_before_creating_evidence(monkeypatch, tmp_path):
    base = tmp_path / "base.qcow2"
    base.touch()
    evidence_root = tmp_path / "evidence"

    def refuse_open_provisioning(_base_directory):
        raise RuntimeError("open provisioning inode")

    monkeypatch.setattr(
        windows_ephemeral_gate, "require_closed_provisioning_files",
        refuse_open_provisioning,
    )
    monkeypatch.setattr(sys, "argv", [
        "windows_ephemeral_gate.py", "--base", str(base),
        "--agent", str(tmp_path / "agent.exe"),
        "--evidence-root", str(evidence_root),
    ])

    with pytest.raises(RuntimeError, match="open provisioning inode"):
        windows_ephemeral_gate.main()
    assert not evidence_root.exists()


def test_cli_forwards_explicit_panther_cleanup(monkeypatch, tmp_path):
    evidence_root = tmp_path / "evidence"
    base = tmp_path / "base.qcow2"
    agent = tmp_path / "agent.exe"
    base.touch()
    agent.touch()
    observed = {}

    def prepare(base_path, temporary, guestfish_image):
        overlay = temporary / "prepared.qcow2"
        overlay.touch()
        return windows_ephemeral_gate.PreparedClone(overlay=overlay, password="synthetic-only")

    def collect(overlay, output, guestfish_image, *, secret):
        assert secret == "synthetic-only"
        output.mkdir(parents=True)
        (output / "acquisition.json").write_text("{}", encoding="utf-8")
        return SimpleNamespace(unattend_password_values=0)

    def run(prepared, agent_path, root, label, *, stopped_disk_observer_factory,
            clear_panther_answer):
        observed["clear_panther_answer"] = clear_panther_answer
        run_directory = root / "run-01"
        (run_directory / "windows-qemu").mkdir(parents=True)
        stopped_disk_observer_factory(run_directory)(prepared.overlay)
        return True

    monkeypatch.setattr(windows_ephemeral_gate, "prepare_overlay", prepare)
    monkeypatch.setattr(windows_ephemeral_gate, "require_closed_provisioning_files", lambda *_: None)
    monkeypatch.setattr(windows_ephemeral_gate, "require_docker_visible_evidence_root", lambda *_: None)
    monkeypatch.setattr(windows_ephemeral_gate, "collect_stopped_panther", collect)
    monkeypatch.setattr(windows_ephemeral_gate, "run_prepared_gate", run)
    monkeypatch.setattr(sys, "argv", [
        "windows_ephemeral_gate.py", "--base", str(base), "--agent", str(agent),
        "--evidence-root", str(evidence_root), "--acquire-panther",
        "--clear-panther-answer",
    ])
    assert windows_ephemeral_gate.main() == 0
    assert observed == {"clear_panther_answer": True}


def test_prepare_overlay_restricts_secret_and_removes_answer(monkeypatch, tmp_path):
    base = tmp_path / "base.qcow2"
    base.touch()
    workdir = tmp_path / "run"
    workdir.mkdir()
    calls = []

    def run(command, **kwargs):
        calls.append((command, kwargs))
        if command[0] == "qemu-img" and command[1] == "create":
            Path(command[-1]).touch()
        return SimpleNamespace(stdout="true\n", returncode=0)

    monkeypatch.setattr(windows_ephemeral_gate.subprocess, "run", run)
    monkeypatch.setattr(windows_ephemeral_gate, "new_password", lambda: "Aa9!synthetic-only")

    prepared = windows_ephemeral_gate.prepare_overlay(base, workdir, "autosut-guestfish:test")

    assert prepared.overlay.exists()
    assert prepared.base_image == base.resolve()
    assert prepared.password.get_secret_value() == "Aa9!synthetic-only"
    assert "synthetic-only" not in repr(prepared)
    assert not (workdir / "answer.xml").exists()
    assert len(calls) == 4
    assert all("Aa9!synthetic-only" not in str(command) for command, _ in calls)
    guestfish_command, guestfish_kwargs = next(
        (command, kwargs) for command, kwargs in calls if command[0] == "docker"
    )
    rebase_calls = [command for command, _ in calls if command[:2] == ["qemu-img", "rebase"]]
    assert rebase_calls[0][rebase_calls[0].index("-b") + 1] == str(
        windows_ephemeral_gate.GUEST_BASE_DIR / base.name
    )
    assert rebase_calls[1][rebase_calls[1].index("-b") + 1] == str(base)
    assert f"{base.parent}:{windows_ephemeral_gate.GUEST_BASE_DIR}:ro" in guestfish_command
    assert any(item.endswith(":/mnt/work:rw") for item in guestfish_command)
    assert guestfish_command[-1] == str(
        windows_ephemeral_gate.GUEST_WORK_DIR / "prepared.qcow2"
    )
    assert str(base.parent) not in guestfish_command[-1]
    assert f"upload {windows_ephemeral_gate.GUEST_WORK_DIR / 'answer.xml'}" in (
        guestfish_kwargs["input"]
    )
    assert str(workdir / "answer.xml") not in guestfish_kwargs["input"]


def test_prepared_overlay_is_not_the_container_opened_inode(monkeypatch, tmp_path):
    base = tmp_path / "base.qcow2"
    base.touch()
    workdir = tmp_path / "clone"
    workdir.mkdir()
    opened_sources = []

    def run(command, **kwargs):
        if command[:2] == ["qemu-img", "create"]:
            Path(command[-1]).write_bytes(b"synthetic overlay")
        if command[0] == "docker":
            work_mount = next(item for item in command if item.endswith(":/mnt/work:rw"))
            staging = Path(work_mount.split(":", maxsplit=1)[0]) / "prepared.qcow2"
            opened_sources.append(staging.open("rb"))
        return SimpleNamespace(stdout="true\n", returncode=0)

    monkeypatch.setattr(windows_ephemeral_gate.subprocess, "run", run)
    monkeypatch.setattr(windows_ephemeral_gate, "new_password", lambda: "Aa9!synthetic-only")

    try:
        prepared = windows_ephemeral_gate.prepare_overlay(base, workdir, "guestfish:test")
        assert len(opened_sources) == 1
        assert os.fstat(opened_sources[0].fileno()).st_ino != prepared.overlay.stat().st_ino
        assert prepared.overlay.read_bytes() == b"synthetic overlay"
    finally:
        for source in opened_sources:
            source.close()


def test_prepare_overlay_refuses_dangling_symlink_target(tmp_path):
    base = tmp_path / "base.qcow2"
    base.touch()
    workdir = tmp_path / "clone"
    workdir.mkdir()
    (workdir / "prepared.qcow2").symlink_to(tmp_path / "elsewhere.qcow2")

    with pytest.raises(FileExistsError, match="already contains"):
        windows_ephemeral_gate.prepare_overlay(base, workdir, "guestfish:test")


def test_prepare_overlay_assigns_optional_per_clone_hostname(monkeypatch, tmp_path):
    base = tmp_path / "base.qcow2"
    base.touch()
    workdir = tmp_path / "clone"
    workdir.mkdir()
    observed = {}

    def run(command, **kwargs):
        if command[0] == "qemu-img" and command[1] == "create":
            Path(command[-1]).touch()
        if command[0] == "docker":
            work_mount = next(item for item in command if item.endswith(":/mnt/work:rw"))
            answer_path = Path(work_mount.split(":", maxsplit=1)[0]) / "answer.xml"
            observed["answer"] = answer_path.read_text()
        return SimpleNamespace(stdout="true\n", returncode=0)

    monkeypatch.setattr(windows_ephemeral_gate.subprocess, "run", run)
    monkeypatch.setattr(windows_ephemeral_gate, "new_password", lambda: "Aa9!synthetic-only")

    windows_ephemeral_gate.prepare_overlay(
        base, workdir, "autosut-guestfish:test", computer_name="AUTOSUT-B",
    )

    assert "<ComputerName>AUTOSUT-B</ComputerName>" in observed["answer"]
    assert not (workdir / "answer.xml").exists()


def test_prepare_overlay_deletes_secret_files_on_guestfish_failure(monkeypatch, tmp_path):
    base = tmp_path / "base.qcow2"
    base.touch()
    workdir = tmp_path / "run"
    workdir.mkdir()

    def run(command, **kwargs):
        if command[0] == "qemu-img" and command[1] == "create":
            Path(command[-1]).touch()
            return SimpleNamespace(stdout="", returncode=0)
        if command[0] == "docker":
            raise RuntimeError("synthetic guestfish failure")
        return SimpleNamespace(stdout="true\n", returncode=0)

    monkeypatch.setattr(windows_ephemeral_gate.subprocess, "run", run)

    with pytest.raises(RuntimeError, match="synthetic guestfish failure"):
        windows_ephemeral_gate.prepare_overlay(base, workdir, "autosut-guestfish:test")

    assert not (workdir / "prepared.qcow2").exists()
    assert not (workdir / "answer.xml").exists()


def test_run_gate_scopes_password_and_removes_overlay(monkeypatch, tmp_path):
    immutable_base = tmp_path / "base.qcow2"
    immutable_base.write_bytes(b"synthetic image")
    secret = "Aa9!" + secrets.token_urlsafe(20)
    prepared = windows_ephemeral_gate.PreparedClone(
        overlay=tmp_path / "prepared.qcow2", password=secret,
        base_image=immutable_base,
    )
    prepared.overlay.touch()
    observed = {}

    def fake_gate(base, agent, evidence_root, label, *, immutable_base_image,
                  on_run_created):
        observed["password"] = os.environ.get("AUTOSUT_WIN_PASSWORD")
        observed["base"] = base
        observed["immutable_base"] = immutable_base_image
        run_dir = evidence_root / "run"
        run_dir.mkdir(parents=True)
        on_run_created(run_dir)
        (run_dir / "execution.log").write_text("clean", encoding="utf-8")
        (run_dir / "manifest.json").write_text("{}", encoding="utf-8")
        (run_dir / "bundle.json").write_text("{}", encoding="utf-8")
        return (
            SimpleNamespace(final_state=SimpleNamespace(value="clean"), evidence_dir=str(run_dir)),
            SimpleNamespace(science_passed=True),
            SimpleNamespace(classification=SimpleNamespace(evidence_role="integration")),
            SimpleNamespace(admissible=True),
        )

    monkeypatch.delenv("AUTOSUT_WIN_PASSWORD", raising=False)
    monkeypatch.setattr(windows_ephemeral_gate, "run_cyber_gate", fake_gate)
    original_scan = windows_ephemeral_gate.produce_scan

    def scan_after_cleanup(**arguments):
        assert "AUTOSUT_WIN_PASSWORD" not in os.environ
        assert not prepared.overlay.exists()
        return original_scan(**arguments)

    monkeypatch.setattr(windows_ephemeral_gate, "produce_scan", scan_after_cleanup)

    result = windows_ephemeral_gate.run_prepared_gate(
        prepared, tmp_path / "agent.exe", tmp_path / "evidence", "test-run",
    )

    assert result
    assert prepared.password.get_secret_value() == ""
    assert observed == {
        "password": secret, "base": prepared.overlay,
        "immutable_base": immutable_base,
    }
    assert "AUTOSUT_WIN_PASSWORD" not in os.environ
    assert not prepared.overlay.exists()
    audit_path = tmp_path / "evidence" / "run.secret-audit.json"
    audit = json.loads(audit_path.read_text(encoding="utf-8"))
    assert audit["scope"] == "retained-run-files"
    assert audit["file_representations"] == [
        "literal", "base64", "xml-escaped", "windows-unattend-obfuscated",
    ]
    assert audit["files_scanned"] == 4
    preparation = json.loads(
        (tmp_path / "evidence" / "run" / "preparation-link.json").read_text(encoding="utf-8")
    )
    assert preparation["run_id"] == "run"
    assert preparation["prepared_overlay_sha256"] == hashlib.sha256(b"").hexdigest()
    assert audit["manifest_sha256"] == hashlib.sha256(b"{}").hexdigest()
    assert audit["overlay_removed"]
    assert audit["environment_cleared"]
    disposal_path = tmp_path / "evidence" / "run.overlay-disposal.json"
    disposal = json.loads(disposal_path.read_text(encoding="utf-8"))
    assert disposal["scope"] == "prepared-overlay-only"
    assert disposal["overlay_sha256_before"] == hashlib.sha256(b"").hexdigest()
    assert disposal["removed"]
    assert disposal["manifest_sha256"] == hashlib.sha256(b"{}").hexdigest()
    assert disposal["run_id"] == "run"
    assert disposal["overlay_path"] == str(prepared.overlay)
    assert secret not in disposal_path.read_text(encoding="utf-8")
    assert secret not in audit_path.read_text(encoding="utf-8")
    scan_path = tmp_path / "evidence" / "run.run-logs-scan.json"
    scan = verify_scan(
        scan_path, expected_root=tmp_path / "evidence" / "run",
        run_id="run", surface="run_logs",
    )
    assert scan.files_scanned == 4
    bundle_scan = verify_scan(
        tmp_path / "evidence" / "run.evidence-bundle-scan.json",
        expected_root=tmp_path / "evidence" / "run" / "bundle.json",
        run_id="run", surface="evidence_bundle",
    )
    base_scan = verify_scan(
        tmp_path / "evidence" / "run.base-image-scan.json",
        expected_root=immutable_base, run_id="run", surface="base_image",
    )
    assert bundle_scan.files_scanned == base_scan.files_scanned == 1


@pytest.mark.parametrize(
    ("write_bundle", "base_has_secret", "expected_error"),
    [
        (False, False, FileNotFoundError),
        (True, True, SecretResidueDetected),
    ],
)
def test_run_gate_fails_closed_on_missing_bundle_or_base_residue(
    monkeypatch, tmp_path, write_bundle, base_has_secret, expected_error,
):
    secret = "Aa9!" + secrets.token_urlsafe(20)
    base = tmp_path / "base.qcow2"
    base.write_text(secret if base_has_secret else "safe image", encoding="utf-8")
    prepared = windows_ephemeral_gate.PreparedClone(
        overlay=tmp_path / "prepared.qcow2", password=secret, base_image=base,
    )
    prepared.overlay.touch()
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()

    def fake_gate(overlay, agent, root, label, *, immutable_base_image,
                  on_run_created):
        run_dir = root / "run"
        run_dir.mkdir()
        (run_dir / "manifest.json").write_text("{}", encoding="utf-8")
        if write_bundle:
            (run_dir / "bundle.json").write_text("{}", encoding="utf-8")
        return (
            SimpleNamespace(final_state=SimpleNamespace(value="clean"), evidence_dir=str(run_dir)),
            SimpleNamespace(science_passed=True),
            SimpleNamespace(classification=SimpleNamespace(evidence_role="integration")),
            SimpleNamespace(admissible=True),
        )

    monkeypatch.delenv("AUTOSUT_WIN_PASSWORD", raising=False)
    monkeypatch.setattr(windows_ephemeral_gate, "run_cyber_gate", fake_gate)
    with pytest.raises(expected_error):
        windows_ephemeral_gate.run_prepared_gate(
            prepared, tmp_path / "agent.exe", evidence_root, "test-run",
        )
    assert prepared.password.get_secret_value() == ""
    assert not prepared.overlay.exists()
    assert "AUTOSUT_WIN_PASSWORD" not in os.environ
    assert not (evidence_root / "run.base-image-scan.json").exists()


def test_run_gate_scans_stamped_source_package(monkeypatch, tmp_path):
    package_root = tmp_path / "candidate" / "autosut"
    package_root.mkdir(parents=True)
    (package_root / "src").mkdir()
    source_file = package_root / "src" / "runner.py"
    source_file.write_text("pass\n", encoding="utf-8")
    write_revision_stamp(package_root, "a" * 40)
    (package_root / ".venv" / "bin").mkdir(parents=True)
    (package_root / ".venv" / "bin" / "python").symlink_to(source_file)
    monkeypatch.setattr(windows_ephemeral_gate, "PROJECT_ROOT", package_root)
    prepared = windows_ephemeral_gate.PreparedClone(
        overlay=tmp_path / "prepared.qcow2", password="Aa9!synthetic-only",
    )
    prepared.overlay.touch()
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()

    def fake_gate(base, agent, root, label, **options):
        run_dir = root / "run"
        run_dir.mkdir()
        (run_dir / "manifest.json").write_text("{}", encoding="utf-8")
        (run_dir / "bundle.json").write_text("{}", encoding="utf-8")
        return (
            SimpleNamespace(final_state=SimpleNamespace(value="clean"), evidence_dir=str(run_dir)),
            SimpleNamespace(science_passed=True),
            SimpleNamespace(classification=SimpleNamespace(evidence_role="integration")),
            SimpleNamespace(admissible=True),
        )

    monkeypatch.delenv("AUTOSUT_WIN_PASSWORD", raising=False)
    monkeypatch.setattr(windows_ephemeral_gate, "run_cyber_gate", fake_gate)
    assert windows_ephemeral_gate.run_prepared_gate(
        prepared, tmp_path / "agent.exe", evidence_root, "test-run",
    )
    source_scan = verify_scan(
        evidence_root / "run.source-tree-scan.json",
        expected_root=package_root, run_id="run", surface="source_tree",
    )
    assert source_scan.files_scanned == 1


def test_run_gate_forwards_run_scoped_panther_observer(monkeypatch, tmp_path):
    prepared = windows_ephemeral_gate.PreparedClone(
        overlay=tmp_path / "prepared.qcow2", password="Aa9!" + secrets.token_urlsafe(20),
    )
    prepared.overlay.touch()
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    observed = {}

    def observer_factory(run_directory):
        observed["run_directory"] = run_directory

        def observe(overlay):
            observed["overlay"] = overlay
            acquisition = run_directory / "windows-qemu" / "panther-acquisition"
            acquisition.mkdir(parents=True)
            archive_path = acquisition / "panther.tar"
            with tarfile.open(archive_path, "w") as archive:
                member = tarfile.TarInfo("./setupact.log")
                member.size = len(b"clean")
                archive.addfile(member, io.BytesIO(b"clean"))
            receipt = _inspect_acquisition(archive_path)
            (acquisition / "acquisition.json").write_text(
                receipt.model_dump_json(), encoding="utf-8",
            )

        return observe

    def fake_gate(base, agent, root, label, *, stopped_disk_observer_factory,
                  clear_panther_answer, on_run_created):
        observed["clear_panther_answer"] = clear_panther_answer
        run_directory = root / "run"
        run_directory.mkdir()
        stopped_disk_observer_factory(run_directory)(base)
        (run_directory / "manifest.json").write_text("{}", encoding="utf-8")
        (run_directory / "bundle.json").write_text("{}", encoding="utf-8")
        return (
            SimpleNamespace(final_state=SimpleNamespace(value="clean"), evidence_dir=str(run_directory)),
            SimpleNamespace(science_passed=True),
            SimpleNamespace(classification=SimpleNamespace(evidence_role="integration")),
            SimpleNamespace(admissible=True),
        )

    monkeypatch.delenv("AUTOSUT_WIN_PASSWORD", raising=False)
    monkeypatch.setattr(windows_ephemeral_gate, "run_cyber_gate", fake_gate)
    assert windows_ephemeral_gate.run_prepared_gate(
        prepared, tmp_path / "agent.exe", evidence_root, "test-run",
        stopped_disk_observer_factory=observer_factory,
        clear_panther_answer=True,
    )
    assert observed == {
        "run_directory": evidence_root / "run", "overlay": prepared.overlay,
        "clear_panther_answer": True,
    }
    assert (evidence_root / "run/windows-qemu/panther-acquisition/acquisition.json").is_file()
    panther_audit_path = evidence_root / "run.panther-secret-audit.json"
    panther_audit = json.loads(panther_audit_path.read_text(encoding="utf-8"))
    assert panther_audit["completed"]
    assert not panther_audit["leak_found"]
    assert panther_audit["regular_files"] == 1
    assert "synthetic-only" not in panther_audit_path.read_text(encoding="utf-8")
    scan_path = evidence_root / "run.guest-panther-scan.json"
    scan = verify_scan(
        scan_path, expected_root=evidence_root / "run/windows-qemu/panther-acquisition",
        run_id="run", surface="guest_panther",
    )
    assert scan.files_scanned == 2


def test_run_gate_refuses_structural_panther_residue(monkeypatch, tmp_path):
    prepared = windows_ephemeral_gate.PreparedClone(
        overlay=tmp_path / "prepared.qcow2", password="Aa9!synthetic-only",
    )
    prepared.overlay.touch()
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()

    def fake_gate(base, agent, root, label, *, on_run_created):
        run_directory = root / "run"
        acquisition = run_directory / "windows-qemu" / "panther-acquisition"
        acquisition.mkdir(parents=True)
        archive_path = acquisition / "panther.tar"
        answer = b"<unattend><Password>different</Password></unattend>"
        with tarfile.open(archive_path, "w") as archive:
            member = tarfile.TarInfo("./unattend.xml")
            member.size = len(answer)
            archive.addfile(member, io.BytesIO(answer))
        receipt = _inspect_acquisition(archive_path)
        (acquisition / "acquisition.json").write_text(
            receipt.model_dump_json(), encoding="utf-8",
        )
        (run_directory / "manifest.json").write_text("{}", encoding="utf-8")
        (run_directory / "bundle.json").write_text("{}", encoding="utf-8")
        return (
            SimpleNamespace(final_state=SimpleNamespace(value="clean"), evidence_dir=str(run_directory)),
            SimpleNamespace(science_passed=True),
            SimpleNamespace(classification=SimpleNamespace(evidence_role="integration")),
            SimpleNamespace(admissible=True),
        )

    monkeypatch.delenv("AUTOSUT_WIN_PASSWORD", raising=False)
    monkeypatch.setattr(windows_ephemeral_gate, "run_cyber_gate", fake_gate)
    with pytest.raises(windows_ephemeral_gate.SecretResidueDetected):
        windows_ephemeral_gate.run_prepared_gate(
            prepared, tmp_path / "agent.exe", evidence_root, "test-run",
        )
    audit_path = evidence_root / "run.panther-secret-audit.json"
    audit = json.loads(audit_path.read_text(encoding="utf-8"))
    assert audit["completed"]
    assert audit["leak_found"]
    assert audit["answer_password_values"] == 1
    assert not (evidence_root / "run.guest-panther-scan.json").exists()
    assert prepared.password.get_secret_value() == ""
    assert not prepared.overlay.exists()
    assert "AUTOSUT_WIN_PASSWORD" not in os.environ


def test_run_gate_rejects_credential_in_retained_evidence(monkeypatch, tmp_path):
    secret = "Aa9!synthetic-only"
    prepared = windows_ephemeral_gate.PreparedClone(
        overlay=tmp_path / "prepared.qcow2", password=secret,
    )
    prepared.overlay.touch()

    def fake_gate(base, agent, evidence_root, label, *, on_run_created):
        run_dir = evidence_root / "run"
        run_dir.mkdir(parents=True)
        (run_dir / "execution.log").write_bytes(secret.encode("utf-16le"))
        (run_dir / "manifest.json").write_text("{}", encoding="utf-8")
        (run_dir / "bundle.json").write_text("{}", encoding="utf-8")
        return (
            SimpleNamespace(final_state=SimpleNamespace(value="clean"), evidence_dir=str(run_dir)),
            SimpleNamespace(science_passed=True),
            SimpleNamespace(classification=SimpleNamespace(evidence_role="integration")),
            SimpleNamespace(admissible=True),
        )

    monkeypatch.delenv("AUTOSUT_WIN_PASSWORD", raising=False)
    monkeypatch.setattr(windows_ephemeral_gate, "run_cyber_gate", fake_gate)

    with pytest.raises(RuntimeError, match="credential residue") as error:
        windows_ephemeral_gate.run_prepared_gate(
            prepared, tmp_path / "agent.exe", tmp_path / "evidence", "test-run",
        )

    assert secret not in str(error.value)
    assert prepared.password.get_secret_value() == ""
    assert "AUTOSUT_WIN_PASSWORD" not in os.environ
    assert not prepared.overlay.exists()
    assert not (tmp_path / "evidence" / "run.secret-audit.json").exists()


def test_run_gate_refuses_audit_receipt_without_manifest(monkeypatch, tmp_path):
    prepared = windows_ephemeral_gate.PreparedClone(
        overlay=tmp_path / "prepared.qcow2", password="Aa9!synthetic-only",
    )
    prepared.overlay.touch()

    def fake_gate(base, agent, evidence_root, label, *, on_run_created):
        run_dir = evidence_root / "run"
        run_dir.mkdir(parents=True)
        return (
            SimpleNamespace(final_state=SimpleNamespace(value="clean"), evidence_dir=str(run_dir)),
            SimpleNamespace(science_passed=True),
            SimpleNamespace(classification=SimpleNamespace(evidence_role="integration")),
            SimpleNamespace(admissible=True),
        )

    monkeypatch.delenv("AUTOSUT_WIN_PASSWORD", raising=False)
    monkeypatch.setattr(windows_ephemeral_gate, "run_cyber_gate", fake_gate)

    with pytest.raises(FileNotFoundError):
        windows_ephemeral_gate.run_prepared_gate(
            prepared, tmp_path / "agent.exe", tmp_path / "evidence", "test-run",
        )

    assert not prepared.overlay.exists()
    assert "AUTOSUT_WIN_PASSWORD" not in os.environ
    assert not (tmp_path / "evidence" / "run.secret-audit.json").exists()


def test_run_gate_refuses_unexpectedly_missing_overlay(monkeypatch, tmp_path):
    prepared = windows_ephemeral_gate.PreparedClone(
        overlay=tmp_path / "prepared.qcow2", password="Aa9!synthetic-only",
    )
    prepared.overlay.write_bytes(b"prepared image")
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()

    def fake_gate(base, agent, root, label, *, on_run_created):
        base.unlink()
        run_dir = root / "run"
        run_dir.mkdir()
        (run_dir / "manifest.json").write_text("{}", encoding="utf-8")
        (run_dir / "bundle.json").write_text("{}", encoding="utf-8")
        return (
            SimpleNamespace(final_state=SimpleNamespace(value="clean"), evidence_dir=str(run_dir)),
            SimpleNamespace(science_passed=True),
            SimpleNamespace(classification=SimpleNamespace(evidence_role="integration")),
            SimpleNamespace(admissible=True),
        )

    monkeypatch.delenv("AUTOSUT_WIN_PASSWORD", raising=False)
    monkeypatch.setattr(windows_ephemeral_gate, "run_cyber_gate", fake_gate)

    with pytest.raises(FileNotFoundError):
        windows_ephemeral_gate.run_prepared_gate(
            prepared, tmp_path / "agent.exe", evidence_root, "test-run",
        )

    assert "AUTOSUT_WIN_PASSWORD" not in os.environ
    assert not list(evidence_root.glob("*.overlay-disposal.json"))


def test_run_gate_rejects_ambient_password_and_removes_overlay(monkeypatch, tmp_path):
    prepared = windows_ephemeral_gate.PreparedClone(
        overlay=tmp_path / "prepared.qcow2", password="Aa9!synthetic-only",
    )
    prepared.overlay.touch()
    monkeypatch.setenv("AUTOSUT_WIN_PASSWORD", "ambient-synthetic")

    with pytest.raises(RuntimeError, match="unset AUTOSUT_WIN_PASSWORD"):
        windows_ephemeral_gate.run_prepared_gate(
            prepared, tmp_path / "agent.exe", tmp_path / "evidence", "test-run",
        )

    assert not prepared.overlay.exists()
    assert os.environ["AUTOSUT_WIN_PASSWORD"] == "ambient-synthetic"
