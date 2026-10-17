"""Check fidelity accounting against preserved step records."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def batch_fixture(tmp_path, monkeypatch):
    specification = importlib.util.spec_from_file_location(
        "batch_values", PROJECT_ROOT / "scripts/build_orchestrated_batch_values.py"
    )
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    run = tmp_path / "run"
    run.mkdir()
    (run / "effect.log").write_text("synthetic fixture\n", encoding="utf-8")
    (run / "provenance.json").write_text(
        json.dumps({"implementation_revision": "synthetic"}), encoding="utf-8"
    )
    (run / "manifest.json").write_text(json.dumps({
        "campaign_id": "synthetic", "teardown_clean": True,
        "techniques": [{
            "status": "success", "executed_mode": "real_controlled",
            "executed_fidelity": fidelity, "evidence_files": ["effect.log"],
        } for fidelity in ("adapted", "inspired")],
    }), encoding="utf-8")
    report = tmp_path / "batch.json"
    report.write_text(json.dumps([{
        "campaign_id": "synthetic", "status": "PASS", "total": 2,
        "successful": 2, "evidence_backed_successful": 2,
        "marker_only_successful": 0, "caldera_driven_successful": 0,
        "final_namespace_clean": True, "elapsed_seconds": 1,
        "implementation_revision": "synthetic",
        "evidence_manifest": "run/manifest.json",
    }]), encoding="utf-8")
    output = tmp_path / "values.tex"
    monkeypatch.setattr(module, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(module, "WITNESS", report)
    monkeypatch.setattr(module, "OUTPUT", output)
    return module, output, run


def test_successful_execution_is_not_automatically_adapted(batch_fixture):
    module, output, _ = batch_fixture
    assert module.main() == 0
    values = output.read_text(encoding="utf-8")
    assert r"\newcommand{\batchAdapted}{1}" in values
    assert r"\newcommand{\batchEvidenceBacked}{2}" in values
    assert r"\newcommand{\batchInspiredExecutions}{1}" in values
    assert r"\newcommand{\batchFullyAdaptedCount}{0}" in values


def test_missing_step_evidence_blocks_macro_generation(batch_fixture):
    module, output, run = batch_fixture
    (run / "effect.log").unlink()
    with pytest.raises(ValueError, match="missing_execution_references"):
        module.main()
    assert not output.exists()


def test_summary_count_disagreement_blocks_macro_generation(batch_fixture):
    module, output, _ = batch_fixture
    rows = json.loads(module.WITNESS.read_text(encoding="utf-8"))
    rows[0]["successful"] = 1
    module.WITNESS.write_text(json.dumps(rows), encoding="utf-8")
    with pytest.raises(ValueError, match="count_mismatch:successful"):
        module.main()
    assert not output.exists()
