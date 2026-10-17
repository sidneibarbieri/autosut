"""Interrupted-run cleanup must stay explicit and fail closed."""

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from infra import recover_interrupted_windows_run as recovery_cli  # noqa: E402
from infrastructure import windows_crash_recovery as recovery  # noqa: E402


def _interrupted_run(root: Path) -> tuple[str, str, Path, Path]:
    run_id = "windows-ephemeral-integration_test"
    credential_directory = "windows-credential-test"
    run = root / run_id
    workdir = run / "windows-qemu"
    workdir.mkdir(parents=True)
    (run / "stage-starts.jsonl").write_text('{"stage":"materialize"}\n')
    prepared = root / credential_directory / "prepared.qcow2"
    prepared.parent.mkdir()
    prepared.write_bytes(b"prepared overlay")
    link = recovery.PreparationLink(
        run_id=run_id, credential_directory=credential_directory,
        prepared_overlay_sha256=hashlib.sha256(prepared.read_bytes()).hexdigest(),
    )
    (run / "preparation-link.json").write_text(link.model_dump_json())
    guest = workdir / "guest.qcow2"
    guest.write_bytes(b"guest overlay")
    return run_id, credential_directory, prepared, guest


def test_recovery_requires_explicit_disposal(tmp_path: Path, monkeypatch) -> None:
    run_id, credential_directory, prepared, guest = _interrupted_run(tmp_path)
    monkeypatch.setattr(recovery, "_assert_no_process_uses", lambda paths, root: None)

    preview = recovery.recover_interrupted_run(
        tmp_path, run_id, credential_directory, dispose=False,
    )
    assert prepared.exists() and guest.exists()
    assert not (tmp_path / f"{run_id}.crash-recovery.json").exists()
    assert {entry.sha256 for entry in preview.removed_overlays} == {
        hashlib.sha256(b"prepared overlay").hexdigest(),
        hashlib.sha256(b"guest overlay").hexdigest(),
    }

    receipt = recovery.recover_interrupted_run(
        tmp_path, run_id, credential_directory, dispose=True,
    )
    assert receipt == preview
    assert not prepared.exists() and not guest.exists()
    assert (tmp_path / f"{run_id}.crash-recovery.json").is_file()
    assert (tmp_path / run_id / "stage-starts.jsonl").is_file()


def test_cli_preview_shows_exact_overlay_paths_and_digests(monkeypatch, capsys, tmp_path):
    observed = {}
    receipt = recovery.CrashRecoveryReceipt(
        run_id="run-test", credential_directory="windows-credential-test",
        preparation_link_sha256="0" * 64,
        removed_overlays=[recovery.RemovedOverlay(
            path="windows-credential-test/prepared.qcow2", bytes=17, sha256="1" * 64,
        )],
    )

    def preview(evidence_root, run_id, credential_directory, *, dispose):
        observed.update(root=evidence_root, run_id=run_id,
                        credential_directory=credential_directory, dispose=dispose)
        return receipt

    monkeypatch.setattr(recovery_cli, "recover_interrupted_run", preview)
    monkeypatch.setattr(sys, "argv", [
        "recover_interrupted_windows_run.py", "--evidence-root", str(tmp_path),
        "--run-id", "run-test", "--credential-directory", "windows-credential-test",
    ])

    assert recovery_cli.main() == 0
    output = capsys.readouterr().out
    assert "would remove: 1 run-owned overlays" in output
    assert "windows-credential-test/prepared.qcow2" in output
    assert "1" * 64 in output
    assert observed == {
        "root": tmp_path, "run_id": "run-test",
        "credential_directory": "windows-credential-test", "dispose": False,
    }


def test_recovery_refuses_a_sealed_run(tmp_path: Path, monkeypatch) -> None:
    run_id, credential_directory, prepared, guest = _interrupted_run(tmp_path)
    (tmp_path / run_id / "manifest.json").write_text("{}")
    monkeypatch.setattr(recovery, "_assert_no_process_uses", lambda paths, root: None)

    with pytest.raises(ValueError, match="unsealed"):
        recovery.recover_interrupted_run(tmp_path, run_id, credential_directory, dispose=True)
    assert prepared.exists() and guest.exists()


def test_recovery_refuses_wrong_prepared_overlay(tmp_path: Path, monkeypatch) -> None:
    run_id, credential_directory, prepared, guest = _interrupted_run(tmp_path)
    prepared.write_bytes(b"another overlay")
    monkeypatch.setattr(recovery, "_assert_no_process_uses", lambda paths, root: None)

    with pytest.raises(ValueError, match="preparation link"):
        recovery.recover_interrupted_run(tmp_path, run_id, credential_directory, dispose=True)
    assert prepared.exists() and guest.exists()


def test_recovery_refuses_wrong_credential_directory(tmp_path: Path, monkeypatch) -> None:
    run_id, _unused_credential_directory, prepared, guest = _interrupted_run(tmp_path)
    other = tmp_path / "windows-credential-other"
    other.mkdir()
    (other / "prepared.qcow2").write_bytes(b"other overlay")
    monkeypatch.setattr(recovery, "_assert_no_process_uses", lambda paths, root: None)

    with pytest.raises(ValueError, match="not bound"):
        recovery.recover_interrupted_run(tmp_path, run_id, other.name, dispose=True)
    assert prepared.exists() and guest.exists()


def test_recovery_refuses_active_resources(tmp_path: Path, monkeypatch) -> None:
    run_id, credential_directory, prepared, guest = _interrupted_run(tmp_path)

    def active_resource(_paths: list[Path], _root: Path) -> None:
        raise RuntimeError("QEMU is active")

    monkeypatch.setattr(recovery, "_assert_no_process_uses", active_resource)
    with pytest.raises(RuntimeError, match="active"):
        recovery.recover_interrupted_run(tmp_path, run_id, credential_directory, dispose=True)
    assert prepared.exists() and guest.exists()


def test_recovery_refuses_symlinked_overlay(tmp_path: Path, monkeypatch) -> None:
    run_id, credential_directory, prepared, guest = _interrupted_run(tmp_path)
    guest.unlink()
    guest.symlink_to(prepared)
    monkeypatch.setattr(recovery, "_assert_no_process_uses", lambda paths, root: None)

    with pytest.raises(ValueError, match="regular file"):
        recovery.recover_interrupted_run(tmp_path, run_id, credential_directory, dispose=True)
    assert prepared.exists() and guest.is_symlink()


def test_recovery_refuses_symlinked_workdir(tmp_path: Path, monkeypatch) -> None:
    run_id, credential_directory, prepared, guest = _interrupted_run(tmp_path)
    workdir = guest.parent
    guest.unlink()
    workdir.rmdir()
    workdir.symlink_to(prepared.parent)
    monkeypatch.setattr(recovery, "_assert_no_process_uses", lambda paths, root: None)

    with pytest.raises(ValueError, match="workdir"):
        recovery.recover_interrupted_run(tmp_path, run_id, credential_directory, dispose=True)
    assert prepared.exists()


def test_recovery_refuses_active_docker_mount(tmp_path: Path, monkeypatch) -> None:
    run_id, credential_directory, prepared, guest = _interrupted_run(tmp_path)

    def probe(command: list[str], **_kwargs) -> subprocess.CompletedProcess[str]:
        if command[:2] == ["docker", "ps"]:
            return subprocess.CompletedProcess(command, 0, "container-1\n", "")
        if command[:2] == ["docker", "inspect"]:
            mounts = json.dumps([{"Source": str(tmp_path)}])
            return subprocess.CompletedProcess(command, 0, mounts, "")
        return subprocess.CompletedProcess(command, 1, "", "")

    monkeypatch.setattr(recovery.subprocess, "run", probe)
    with pytest.raises(RuntimeError, match="mounts the evidence root"):
        recovery.recover_interrupted_run(tmp_path, run_id, credential_directory, dispose=True)
    assert prepared.exists() and guest.exists()
