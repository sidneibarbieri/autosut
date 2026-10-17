"""Paper consequence values are bound to one checked experimental run."""

from __future__ import annotations

import importlib.util
import hashlib
import json
import shutil
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SOURCE_RUN = (
    PROJECT_ROOT
    / "release"
    / "experiments"
    / "consequence_study"
    / "runs"
    / "c0045-consequence-20261006T212539Z"
)


def _renderer():
    spec = importlib.util.spec_from_file_location(
        "render_review_evidence_macros", PROJECT_ROOT / "scripts" / "render_review_evidence_macros.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _copy_evidence(destination: Path) -> Path:
    run = destination / SOURCE_RUN.name
    run.mkdir(parents=True)
    shutil.copy2(SOURCE_RUN / "comparison.json", run / "comparison.json")
    for source in SOURCE_RUN.glob("*/arm-outcome.json"):
        target = run / source.parent.name
        shutil.copytree(source.parent, target)
    return run


def _select_historical_run(renderer, monkeypatch) -> None:
    monkeypatch.setattr(renderer, "PAPER_RUN_SELECTION", {
        "run_id": SOURCE_RUN.name,
        "experimental_unit": "C0045",
        "repetitions": 2,
    })


def test_selected_prepared_pair_run_matches_paper_macros():
    renderer = _renderer()

    assert renderer.PAPER_RUN_SELECTION["run_id"] == "c0045-guard-20261017"
    assert renderer.consequence_macros() == {
        "consequenceReachableSteps": "10",
        "consequenceGuardedSteps": "1",
        "consequenceStepDelta": "9",
        "consequenceGuardedStop": "T1190",
        "consequenceRepetitions": "2",
    }


def test_selected_run_rejects_wrong_implementation_revision(monkeypatch):
    renderer = _renderer()
    selection = {**renderer.PAPER_RUN_SELECTION, "implementation_revision": "0" * 40}
    monkeypatch.setattr(renderer, "PAPER_RUN_SELECTION", selection)

    with pytest.raises(ValueError, match="implementation revision mismatch"):
        renderer.consequence_macros()


def test_selected_run_rejects_escaping_source_path(monkeypatch):
    renderer = _renderer()
    selection = {**renderer.PAPER_RUN_SELECTION, "plan_path": "../outside.json"}
    monkeypatch.setattr(renderer, "PAPER_RUN_SELECTION", selection)

    with pytest.raises(ValueError, match="unsafe paper evidence path"):
        renderer.consequence_macros()


def test_new_run_cannot_change_the_selected_paper_result(tmp_path, monkeypatch):
    renderer = _renderer()
    runs = tmp_path / "runs"
    _copy_evidence(runs)
    monkeypatch.setattr(renderer, "CONSEQUENCE_RUNS", runs)
    monkeypatch.setattr(renderer, "PAPER_RUN_SELECTION", {"run_id": SOURCE_RUN.name, "experimental_unit": "C0045", "repetitions": 2})
    expected = renderer.consequence_macros()

    (runs / "exploratory-run").mkdir()

    assert renderer.consequence_macros() == expected


def test_comparison_must_match_the_recorded_arm_outcomes(tmp_path, monkeypatch):
    renderer = _renderer()
    runs = tmp_path / "runs"
    selected = _copy_evidence(runs)
    monkeypatch.setattr(renderer, "CONSEQUENCE_RUNS", runs)
    monkeypatch.setattr(renderer, "PAPER_RUN_SELECTION", {"run_id": SOURCE_RUN.name, "experimental_unit": "C0045", "repetitions": 2})
    comparison_path = selected / "comparison.json"
    comparison = json.loads(comparison_path.read_text(encoding="utf-8"))
    comparison["executed_step_delta"] = 0
    comparison_path.write_text(json.dumps(comparison), encoding="utf-8")

    with pytest.raises(ValueError, match="comparison"):
        renderer.consequence_macros()


def test_selected_run_cannot_escape_the_runs_directory(tmp_path, monkeypatch):
    renderer = _renderer()
    monkeypatch.setattr(renderer, "CONSEQUENCE_RUNS", tmp_path / "runs")
    monkeypatch.setattr(
        renderer,
        "PAPER_RUN_SELECTION",
        {"run_id": "../outside", "experimental_unit": "C0045", "repetitions": 2},
    )

    with pytest.raises(ValueError, match="run_id"):
        renderer.consequence_macros()


def test_arm_count_must_match_per_step_evidence(tmp_path, monkeypatch):
    renderer = _renderer()
    runs = tmp_path / "runs"
    selected = _copy_evidence(runs)
    monkeypatch.setattr(renderer, "CONSEQUENCE_RUNS", runs)
    monkeypatch.setattr(renderer, "PAPER_RUN_SELECTION", {"run_id": SOURCE_RUN.name, "experimental_unit": "C0045", "repetitions": 2})
    arm_path = selected / "ray_reachable-rep1" / "arm-outcome.json"
    arm = json.loads(arm_path.read_text(encoding="utf-8"))
    arm["executed_with_evidence_count"] = 1
    arm_path.write_text(json.dumps(arm), encoding="utf-8")

    with pytest.raises(ValueError, match="executed count"):
        renderer.consequence_macros()


def test_stale_published_macros_fail_the_check(tmp_path):
    renderer = _renderer()
    published = tmp_path / "review_evidence_macros.tex"
    published.write_text("stale\n", encoding="utf-8")

    with pytest.raises(ValueError, match="out of date"):
        renderer.check_output(published)


def test_equal_length_arms_must_use_the_same_technique_sequence(tmp_path, monkeypatch):
    renderer = _renderer()
    runs = tmp_path / "runs"
    selected = _copy_evidence(runs)
    monkeypatch.setattr(renderer, "CONSEQUENCE_RUNS", runs)
    monkeypatch.setattr(renderer, "PAPER_RUN_SELECTION", {
        "run_id": SOURCE_RUN.name, "experimental_unit": "C0045", "repetitions": 2,
    })
    for repetition in (1, 2):
        path = selected / f"ray_guarded-rep{repetition}" / "arm-outcome.json"
        arm = json.loads(path.read_text(encoding="utf-8"))
        arm["steps"][-1]["technique_id"] = "T9999"
        semantic = [
            {"technique_id": step["technique_id"], "status": step["status"]}
            for step in arm["steps"]
        ]
        arm["execution_semantic_sha256"] = hashlib.sha256(
            json.dumps(semantic, sort_keys=True).encode("utf-8")
        ).hexdigest()
        path.write_text(json.dumps(arm), encoding="utf-8")

    with pytest.raises(ValueError, match="different procedures"):
        renderer.consequence_macros()


def test_selected_run_requires_referenced_logs(tmp_path, monkeypatch):
    renderer = _renderer()
    _select_historical_run(renderer, monkeypatch)
    selected = _copy_evidence(tmp_path / "runs")
    monkeypatch.setattr(renderer, "CONSEQUENCE_RUNS", selected.parent)
    (selected / "ray_reachable-rep1" / "techniques" / "T1588.002_toolkit.log").unlink()

    with pytest.raises(FileNotFoundError):
        renderer.consequence_macros()


def test_selected_run_rejects_wrong_input_binding(tmp_path, monkeypatch):
    renderer = _renderer()
    _select_historical_run(renderer, monkeypatch)
    selected = _copy_evidence(tmp_path / "runs")
    monkeypatch.setattr(renderer, "CONSEQUENCE_RUNS", selected.parent)
    path = selected / "ray_guarded-rep1" / "campaign_state.json"
    state = json.loads(path.read_text(encoding="utf-8"))
    state["source_plan_sha256"] = "0" * 64
    path.write_text(json.dumps(state), encoding="utf-8")

    with pytest.raises(ValueError, match="input binding"):
        renderer.consequence_macros()


def test_selected_run_rejects_outcome_manifest_disagreement(tmp_path, monkeypatch):
    renderer = _renderer()
    _select_historical_run(renderer, monkeypatch)
    selected = _copy_evidence(tmp_path / "runs")
    monkeypatch.setattr(renderer, "CONSEQUENCE_RUNS", selected.parent)
    path = selected / "ray_reachable-rep1" / "manifest.json"
    manifest = json.loads(path.read_text(encoding="utf-8"))
    manifest["techniques"][0]["status"] = "failure"
    path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ValueError, match="manifest"):
        renderer.consequence_macros()


def test_selected_run_rejects_input_content_tampering(tmp_path, monkeypatch):
    renderer = _renderer()
    _select_historical_run(renderer, monkeypatch)
    path = tmp_path / "plan.json"
    payload = json.loads(renderer.CONSEQUENCE_PLAN.read_text(encoding="utf-8"))
    payload["content_sha256"] = "0" * 64
    path.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setattr(renderer, "CONSEQUENCE_PLAN", path)

    with pytest.raises(ValueError, match="input content hash"):
        renderer.consequence_macros()


@pytest.mark.parametrize("reference", ["../outside.log", "/tmp/outside.log"])
def test_selected_run_rejects_escaping_evidence_paths(tmp_path, monkeypatch, reference):
    renderer = _renderer()
    _select_historical_run(renderer, monkeypatch)
    selected = _copy_evidence(tmp_path / "runs")
    monkeypatch.setattr(renderer, "CONSEQUENCE_RUNS", selected.parent)
    folder = selected / "ray_reachable-rep1"
    for name, collection in (("manifest.json", "techniques"), ("campaign_state.json", "transitions")):
        path = folder / name
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload[collection][0]["evidence_files"] = [reference]
        path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="escapes"):
        renderer.consequence_macros()
