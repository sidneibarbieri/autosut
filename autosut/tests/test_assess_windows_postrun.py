"""Checks for the sealed Windows post-run assessment CLI."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest
from infrastructure.windows_postrun_qualification import PostRunQualification

ARTIFACT_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ARTIFACT_ROOT / "scripts/infra/assess_windows_postrun.py"
spec = importlib.util.spec_from_file_location("assess_windows_postrun", SCRIPT_PATH)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def test_retained_reports_bind_to_receipt_digest(tmp_path):
    run_dir = tmp_path / "run-1"
    run_dir.mkdir()
    receipt = tmp_path / "run-1.base-image-scan.json"
    receipt.write_text(json.dumps({
        "schema": "windows-surface-scan/v2",
        "surface": "base_image",
        "run_id": "run-1",
        "input_root": str(tmp_path / "base.qcow2"),
        "scanner_sha256": "a" * 64,
        "files": [],
        "inventory_sha256": "b" * 64,
        "files_scanned": 0,
        "completed": True,
        "leak_found": False,
    }), encoding="utf-8")

    reports = module.retained_reports(run_dir)

    assert len(reports) == 1
    assert reports[0].surface.value == "base_image"
    assert reports[0].receipt_path == receipt.name
    assert reports[0].receipt_sha256 == hashlib.sha256(receipt.read_bytes()).hexdigest()


def test_cli_rejects_symlink_run_directory(tmp_path, monkeypatch):
    run_dir = tmp_path / "run-1"
    run_dir.mkdir()
    linked_run = tmp_path / "linked-run"
    linked_run.symlink_to(run_dir, target_is_directory=True)
    monkeypatch.setattr(sys, "argv", [
        str(SCRIPT_PATH), "--run-dir", str(linked_run),
        "--base-image", str(tmp_path / "base.qcow2"),
        "--source-tree", str(tmp_path),
    ])

    with pytest.raises(ValueError, match="symlink"):
        module.main()


def test_cli_reports_ineligible_without_changing_run(tmp_path, monkeypatch, capsys):
    run_dir = tmp_path / "run-1"
    run_dir.mkdir()
    sentinel = run_dir / "bundle.json"
    sentinel.write_bytes(b"sealed")
    monkeypatch.setattr(sys, "argv", [
        str(SCRIPT_PATH), "--run-dir", str(run_dir),
        "--base-image", str(tmp_path / "base.qcow2"),
        "--source-tree", str(tmp_path),
    ])
    monkeypatch.setattr(module, "assess_sealed_windows_run", lambda *args, **kwargs:
                        PostRunQualification(
                            run_id="run-1", manifest_sha256="a" * 64,
                            bundle_sha256="b" * 64, admissible=False,
                            violations=["missing transient producer evidence"],
                        ))

    assert module.main() == 1
    assert json.loads(capsys.readouterr().out)["violations"] == [
        "missing transient producer evidence"
    ]
    assert sentinel.read_bytes() == b"sealed"
