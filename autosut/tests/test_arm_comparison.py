from __future__ import annotations

import shutil
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from evaluation.arm_comparison import (
    _effect,
    ArmMetrics,
    build_report,
    load_comparison_report,
    load_verified_input_set,
)


def _arm(arm_id: str, executable: int, evidence: int | None) -> ArmMetrics:
    return ArmMetrics(
        arm_id=arm_id,
        treatment="fixture",
        campaign_id="C9999",
        technique_count=10,
        verified_procedure_count=executable,
        precondition_resolved_count=executable,
        executable_step_count=executable,
        executed_with_evidence_count=evidence,
        resolver_output_verified=True,
        execution_attempted=evidence is not None,
        campaign_completed=evidence == 10 if evidence is not None else None,
        assumption_count=0,
        assumption_bearing_step_count=0,
        execution_semantic_sha256="0" * 64,
        interpretation="fixture",
    )


def test_effect_keeps_unexecuted_arm_distinct_from_zero_success() -> None:
    first = _arm("A", 0, 0)
    second = _arm("B", 1, None)
    effect = _effect(first, second)
    assert effect.executable_step_delta == 1
    assert effect.completed_with_evidence_delta is None


def test_c0045_inputs_are_self_contained_and_hash_bound() -> None:
    manifest = (
        PROJECT_ROOT / "release/inputs/sticks/c0045-v1/manifest.json"
    )
    inputs = load_verified_input_set(manifest)
    assert inputs.manifest.input_set_id == "sticks-c0045-v1"
    assert len(inputs.raw_plan.steps) == 0
    assert len(inputs.fixed_plan.steps) == 1
    assert len(inputs.autosut_plan.steps) == 10
    assert inputs.autosut_plan.planning_certificate.valid


def test_c0045_input_gate_fails_closed_on_tampering(tmp_path: Path) -> None:
    source = PROJECT_ROOT / "release/inputs/sticks/c0045-v1"
    copied = tmp_path / "c0045-v1"
    shutil.copytree(source, copied)
    action_catalog = copied / "action_templates.json"
    action_catalog.write_bytes(action_catalog.read_bytes() + b"\n")
    with pytest.raises(ValueError, match="byte hash mismatch"):
        load_verified_input_set(copied / "manifest.json")


def test_c0045_report_separates_planning_from_execution(tmp_path: Path) -> None:
    report = build_report(
        input_manifest_path=(
            PROJECT_ROOT / "release/inputs/sticks/c0045-v1/manifest.json"
        ),
        execution_validity_path=(
            PROJECT_ROOT / "release/experiments/execution_validity.json"
        ),
        local_campaign_id="0.shadowray",
        project_root=PROJECT_ROOT,
    )
    assert report.primary_gate_passed
    assert report.plan_synthesis_gate_passed
    assert report.execution_evidence_gate_passed
    assert not report.three_arm_execution_comparison_supported
    assert [arm.execution_attempted for arm in report.arms] == [False, False, True]
    assert report.arms[2].assumption_count == 6
    assert report.execution_audit.fidelity_overclaim_count == 0
    assert report.execution_audit.real_cve_attempted
    assert not report.execution_audit.real_cve_succeeded
    assert report.execution_audit.surrogate_succeeded

    output = tmp_path / "report.json"
    output.write_text(report.model_dump_json(indent=2) + "\n", encoding="utf-8")
    assert load_comparison_report(output).content_sha256 == report.content_sha256
