import csv
import json

import pytest

from scripts.orchestrator.executor import _annotate_catalog_reference
from scripts.orchestrator.models import (
    AttackerProfile,
    ExecutionMode,
    FidelityLevel,
    Realization,
    RunResult,
    SUTProfile,
    TechniqueOutcome,
)
from scripts.run_all_orchestrated_campaigns import (
    ReplayRow,
    classify_replay,
    clean_stale_autosut_resources,
    stale_autosut_resources,
    write_reports,
)


def _outcome(technique_id: str, mode: ExecutionMode) -> TechniqueOutcome:
    return TechniqueOutcome(
        technique_id=technique_id,
        declared_fidelity=FidelityLevel.adapted,
        executed_fidelity=FidelityLevel.adapted,
        declared_mode=mode,
        executed_mode=mode,
        realization=Realization.surrogate,
        status="success",
        evidence_files=[f"techniques/{technique_id}.log"],
    )


def _result(*modes: ExecutionMode, teardown_clean: bool = True) -> RunResult:
    return RunResult(
        campaign_id="test",
        run_id="test-run",
        attacker=AttackerProfile(profile_id="test"),
        sut=SUTProfile(sut_id="test", base_image="alpine:3.19"),
        techniques=[_outcome(f"T{index}", mode) for index, mode in enumerate(modes)],
        teardown_clean=teardown_clean,
    )


def test_replay_pass_requires_complete_evidence_and_clean_lifecycle() -> None:
    result = _result(
        ExecutionMode.real_controlled,
        ExecutionMode.caldera_driven,
    )

    assert classify_replay(result, final_namespace_clean=True) == "PASS"
    assert classify_replay(result, final_namespace_clean=False) == "FAIL"


def test_replay_with_marker_is_partial_not_pass() -> None:
    result = _result(
        ExecutionMode.real_controlled,
        ExecutionMode.naive_simulated,
    )

    assert classify_replay(result, final_namespace_clean=True) == "PARTIAL"


def test_replay_with_failed_run_teardown_is_not_pass() -> None:
    result = _result(ExecutionMode.real_controlled, teardown_clean=False)

    assert classify_replay(result, final_namespace_clean=True) == "FAIL"


def test_catalog_annotation_does_not_change_execution_mode() -> None:
    outcome = _outcome("T1000", ExecutionMode.real_controlled)

    _annotate_catalog_reference(
        outcome,
        {"ability_id": "ability-1", "name": "Catalog ability"},
    )

    assert outcome.executed_mode == ExecutionMode.real_controlled
    assert outcome.caldera_ability_id == "ability-1"
    assert outcome.caldera_ability_name == "Catalog ability"


def test_container_inspection_fails_closed_without_docker(monkeypatch) -> None:
    monkeypatch.setattr(
        "scripts.run_all_orchestrated_campaigns.shutil.which",
        lambda _command: None,
    )

    with pytest.raises(RuntimeError, match="docker executable not found"):
        stale_autosut_resources()


def test_cleanup_waits_for_docker_auto_remove_race(monkeypatch) -> None:
    observations = iter([
        {"container:autosut-test-target", "network:autosut-test-network"},
        {"network:autosut-test-network"},
        set(),
    ])
    removals: list[str] = []
    monkeypatch.setattr(
        "scripts.run_all_orchestrated_campaigns.autosut_resources",
        lambda: next(observations),
    )
    monkeypatch.setattr(
        "scripts.run_all_orchestrated_campaigns.shutil.which",
        lambda _command: "/usr/local/bin/docker",
    )
    monkeypatch.setattr(
        "scripts.run_all_orchestrated_campaigns.force_remove",
        removals.append,
    )
    monkeypatch.setattr(
        "scripts.run_all_orchestrated_campaigns.time.sleep",
        lambda _seconds: None,
    )

    removed = clean_stale_autosut_resources(
        include_caldera=True,
        removal_timeout_seconds=1.0,
    )

    assert removed == [
        "container:autosut-test-target",
        "network:autosut-test-network",
    ]
    assert removals == [
        "container:autosut-test-target",
        "network:autosut-test-network",
        "network:autosut-test-network",
    ]


def test_persistent_caldera_is_only_excluded_outside_strict_isolation(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        "scripts.run_all_orchestrated_campaigns.shutil.which",
        lambda _command: "/usr/local/bin/docker",
    )
    monkeypatch.setattr(
        "scripts.run_all_orchestrated_campaigns.autosut_resources",
        lambda: {
            "container:autosut-caldera",
            "network:autosut-test-network",
        },
    )

    assert stale_autosut_resources() == ["network:autosut-test-network"]
    assert stale_autosut_resources(include_caldera=True) == [
        "container:autosut-caldera",
        "network:autosut-test-network",
    ]


def test_reports_expose_evidence_and_lifecycle_denominators(tmp_path) -> None:
    output_path = tmp_path / "replay.tsv"
    row = ReplayRow(
        campaign_id="test",
        implementation_revision="a" * 40,
        status="PARTIAL",
        successful=2,
        evidence_backed_successful=1,
        marker_only_successful=1,
        caldera_driven_successful=0,
        total=2,
        fidelity_distribution={"adapted": 1, "inspired": 1},
        final_namespace_clean=True,
        cleanup_removed_resources=["container:autosut-test-target"],
        elapsed_seconds=1.25,
        evidence_manifest="release/evidence/test/manifest.json",
        notes="test row",
    )

    write_reports([row], output_path)

    with output_path.open(encoding="utf-8") as handle:
        report = next(csv.DictReader(handle, delimiter="\t"))
    assert report["status_successful"] == "2"
    assert report["implementation_revision"] == "a" * 40
    assert report["evidence_backed_successful"] == "1"
    assert report["marker_only_successful"] == "1"
    assert report["caldera_driven_successful"] == "0"
    assert report["final_namespace_clean"] == "true"
    assert json.loads(report["cleanup_removed_resources"]) == [
        "container:autosut-test-target"
    ]
