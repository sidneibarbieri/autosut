"""A Windows credential-surface receipt must bind the bytes it claims to scan."""

from pathlib import Path
import sys

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from infrastructure.windows_surface_scan import verify_scan  # noqa: E402
from scripts.infra.windows_surface_scan import produce_scan  # noqa: E402
from scripts.infra.windows_secret_audit import SecretResidueDetected  # noqa: E402


def test_scan_records_and_rechecks_actual_input_bytes(tmp_path: Path) -> None:
    input_root = tmp_path / "input"
    input_root.mkdir()
    (input_root / "panther.txt").write_text("safe fixture", encoding="utf-8")
    receipt = tmp_path / "audits" / "guest_panther.json"

    scan = produce_scan(
        surface="guest_panther", run_id="run-1", input_root=input_root,
        receipt_path=receipt, secret="Ephemeral-Secret-123!",
    )

    assert scan.files_scanned == 1
    assert scan.completed and not scan.leak_found
    assert verify_scan(receipt, expected_root=input_root, run_id="run-1",
                       surface="guest_panther") == scan
    (input_root / "panther.txt").write_text("changed fixture", encoding="utf-8")
    with pytest.raises(ValueError, match="inventory"):
        verify_scan(receipt, expected_root=input_root, run_id="run-1",
                    surface="guest_panther")


def test_scan_fails_closed_for_secret_and_does_not_write_receipt(tmp_path: Path) -> None:
    input_root = tmp_path / "input"
    input_root.mkdir()
    (input_root / "answer.xml").write_text("Ephemeral-Secret-123!", encoding="utf-8")
    receipt = tmp_path / "audits" / "guest_panther.json"

    with pytest.raises(SecretResidueDetected):
        produce_scan(
            surface="guest_panther", run_id="run-1", input_root=input_root,
            receipt_path=receipt, secret="Ephemeral-Secret-123!",
        )
    assert not receipt.exists()


def test_scan_rejects_symlinks_and_overlapping_output(tmp_path: Path) -> None:
    input_root = tmp_path / "input"
    (input_root / "src").mkdir(parents=True)
    (input_root / "src" / "actual.txt").write_text("safe", encoding="utf-8")
    (input_root / "src" / "link.txt").symlink_to(input_root / "src" / "actual.txt")
    with pytest.raises(RuntimeError, match="symlink"):
        produce_scan(
            surface="source_tree", run_id="run-1", input_root=input_root,
            receipt_path=tmp_path / "audits" / "source_tree.json", secret="secret",
        )
    (input_root / "src" / "link.txt").unlink()
    with pytest.raises(ValueError, match="outside"):
        produce_scan(
            surface="source_tree", run_id="run-1", input_root=input_root,
            receipt_path=input_root / "receipt.json", secret="secret",
        )


def test_source_tree_scan_excludes_reviewer_runtime_but_binds_source(tmp_path: Path) -> None:
    package_root = tmp_path / "package"
    (package_root / "src").mkdir(parents=True)
    source = package_root / "src" / "runner.py"
    source.write_text("pass\n", encoding="utf-8")
    runtime = package_root / ".venv" / "bin"
    runtime.mkdir(parents=True)
    (runtime / "python").symlink_to(source)
    receipt = tmp_path / "source-tree.json"

    scan = produce_scan(
        surface="source_tree", run_id="run-1", input_root=package_root,
        receipt_path=receipt, secret="Ephemeral-Secret-123!",
    )

    assert [file.path for file in scan.files] == ["src/runner.py"]
    assert verify_scan(
        receipt, expected_root=package_root, run_id="run-1", surface="source_tree",
    ) == scan
    source.write_text("changed\n", encoding="utf-8")
    with pytest.raises(ValueError, match="inventory"):
        verify_scan(receipt, expected_root=package_root, run_id="run-1", surface="source_tree")


def test_source_tree_scan_rejects_secret_in_included_source(tmp_path: Path) -> None:
    package_root = tmp_path / "package"
    (package_root / "scripts").mkdir(parents=True)
    (package_root / "scripts" / "runner.py").write_text(
        "Ephemeral-Secret-123!", encoding="utf-8",
    )
    receipt = tmp_path / "source-tree.json"

    with pytest.raises(SecretResidueDetected):
        produce_scan(
            surface="source_tree", run_id="run-1", input_root=package_root,
            receipt_path=receipt, secret="Ephemeral-Secret-123!",
        )
    assert not receipt.exists()


def test_scan_rejects_credential_in_file_name(tmp_path: Path) -> None:
    secret = "Ephemeral-Secret-123!"
    input_file = tmp_path / f"{secret}.txt"
    input_file.write_text("otherwise safe", encoding="utf-8")
    with pytest.raises(SecretResidueDetected):
        produce_scan(
            surface="run_logs", run_id="run-1", input_root=input_file,
            receipt_path=tmp_path / "audits" / "run_logs.json", secret=secret,
        )


def test_scan_rejects_changed_input_during_scan(tmp_path: Path, monkeypatch) -> None:
    from scripts.infra import windows_surface_scan

    input_root = tmp_path / "input"
    input_root.mkdir()
    target = input_root / "log.txt"
    target.write_text("before", encoding="utf-8")
    receipt = tmp_path / "audits" / "run_logs.json"

    def changed_scan(_root: Path, _secret: str) -> int:
        target.write_text("after", encoding="utf-8")
        return 1

    monkeypatch.setattr(windows_surface_scan, "assert_no_secret", changed_scan)
    with pytest.raises(RuntimeError, match="changed"):
        produce_scan(
            surface="run_logs", run_id="run-1", input_root=input_root,
            receipt_path=receipt, secret="Ephemeral-Secret-123!",
        )
    assert not receipt.exists()
