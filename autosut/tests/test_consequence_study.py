from __future__ import annotations

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
for root in (PROJECT_ROOT / "src", PROJECT_ROOT / "scripts"):
    sys.path.insert(0, str(root))

import run_consequence_study as study  # noqa: E402
from orchestrator.injector import RECIPES  # noqa: E402
from orchestrator.models import (  # noqa: E402
    AttackerProfile,
    ExecutionMode,
    FidelityLevel,
    Realization,
    RunResult,
    SUTProfile,
    TechniqueOutcome,
)

CHAIN = ["T1588.002", "T1190", "T1059.006", "T1105", "T1496.001"]


def _outcome(technique_id: str, status: str) -> TechniqueOutcome:
    return TechniqueOutcome(
        technique_id=technique_id,
        declared_fidelity=FidelityLevel.adapted,
        executed_fidelity=FidelityLevel.adapted,
        declared_mode=ExecutionMode.real_controlled,
        executed_mode=ExecutionMode.real_controlled,
        realization=Realization.surrogate,
        status=status,
        evidence_files=["techniques/evidence.log"] if status == "success" else [],
    )


def _result(statuses: list[str]) -> RunResult:
    return RunResult(
        campaign_id="0.shadowray",
        run_id="test",
        attacker=AttackerProfile(profile_id="a"),
        sut=SUTProfile(sut_id="0.shadowray", backend="docker", base_image="img"),
        techniques=[_outcome(tid, status) for tid, status in zip(CHAIN, statuses)],
        teardown_clean=True,
    )


def test_both_arm_recipes_are_registered() -> None:
    assert set(study.ARMS) == {"ray_reachable", "ray_guarded"}
    assert study.ARMS["ray_reachable"]().install_recipe in RECIPES
    assert study.ARMS["ray_guarded"]().install_recipe in RECIPES


def test_a_completed_chain_reports_every_step_executed() -> None:
    outcome = study.summarize_arm("ray_reachable", 1, _result(["success"] * 5))
    assert outcome.procedure_completed
    assert outcome.executed_with_evidence_count == 5
    assert outcome.failure_technique_id is None


def test_a_guarded_chain_stops_at_the_vulnerability_dependent_step() -> None:
    statuses = ["success", "failure", "failure", "failure", "failure"]
    outcome = study.summarize_arm("ray_guarded", 1, _result(statuses))
    assert not outcome.procedure_completed
    assert outcome.executed_with_evidence_count == 1
    assert outcome.failure_technique_id == "T1190"
    assert outcome.failure_step_index == 1


def test_primary_comparison_reports_the_consequence() -> None:
    reachable = [study.summarize_arm("ray_reachable", rep, _result(["success"] * 5)) for rep in (1, 2)]
    guarded_statuses = ["success", "failure", "failure", "failure", "failure"]
    guarded = [study.summarize_arm("ray_guarded", rep, _result(guarded_statuses)) for rep in (1, 2)]
    comparison = study.primary_comparison(reachable, guarded)
    assert comparison["executed_step_delta"] == 4
    assert comparison["guarded_stops_at_vulnerability_dependent_step"]
    assert comparison["consequence_observed"]
    assert comparison["reachable_repetitions_agree"]
    assert comparison["guarded_repetitions_agree"]


def test_identical_arms_show_no_consequence() -> None:
    reachable = [study.summarize_arm("ray_reachable", rep, _result(["success"] * 5)) for rep in (1, 2)]
    guarded = [study.summarize_arm("ray_guarded", rep, _result(["success"] * 5)) for rep in (1, 2)]
    comparison = study.primary_comparison(reachable, guarded)
    assert comparison["executed_step_delta"] == 0
    assert not comparison["consequence_observed"]


@pytest.mark.parametrize("run_id", ["../outside", "absolute", "nested/run", ".", "..", "bad name", "bad\nname"])
def test_invalid_run_identity_fails_before_creating_evidence(tmp_path, monkeypatch, run_id):
    root = tmp_path / "study"
    if run_id == "absolute":
        run_id = str(tmp_path / "absolute-output")
    monkeypatch.setattr(study, "CONSEQUENCE_ROOT", root)
    monkeypatch.setattr(sys, "argv", ["study", "--run-id", run_id])
    monkeypatch.setattr(study, "run_arm", lambda *args: pytest.fail("backend must not start"))

    with pytest.raises(ValueError):
        study.main()

    assert not root.exists()


@pytest.mark.parametrize("repetitions", [0, -1])
def test_nonpositive_repetitions_fail_before_creating_evidence(tmp_path, monkeypatch, repetitions):
    root = tmp_path / "study"
    monkeypatch.setattr(study, "CONSEQUENCE_ROOT", root)
    monkeypatch.setattr(sys, "argv", ["study", "--run-id", "new-run", "--repetitions", str(repetitions)])

    with pytest.raises(ValueError):
        study.main()

    assert not root.exists()


def test_symlinked_runs_directory_cannot_redirect_evidence(tmp_path, monkeypatch):
    root = tmp_path / "study"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (root / "runs").symlink_to(outside, target_is_directory=True)
    monkeypatch.setattr(study, "CONSEQUENCE_ROOT", root)
    monkeypatch.setattr(sys, "argv", ["study", "--run-id", "new-run"])
    monkeypatch.setattr(study, "run_arm", lambda *args: pytest.fail("backend must not start"))

    with pytest.raises(ValueError, match="symlink"):
        study.main()

    assert list(outside.iterdir()) == []


def test_existing_run_is_never_overwritten(tmp_path, monkeypatch):
    root = tmp_path / "study"
    existing = root / "runs" / "existing-run"
    existing.mkdir(parents=True)
    preserved = existing / "comparison.json"
    preserved.write_bytes(b"preserved result\n")
    monkeypatch.setattr(study, "CONSEQUENCE_ROOT", root)
    monkeypatch.setattr(sys, "argv", ["study", "--run-id", "existing-run"])
    monkeypatch.setattr(study, "run_arm", lambda *args: pytest.fail("backend must not start"))

    with pytest.raises(FileExistsError):
        study.main()

    assert preserved.read_bytes() == b"preserved result\n"


def test_valid_request_creates_one_distinct_run_directory(tmp_path, monkeypatch):
    monkeypatch.setattr(study, "CONSEQUENCE_ROOT", tmp_path / "study")
    request = study.ConsequenceRunRequest(pair=tmp_path, run_id="C0045-prospective_1", repetitions=2)

    created = study.create_run_directory(request)

    assert created == tmp_path / "study" / "runs" / request.run_id
    assert created.is_dir()
