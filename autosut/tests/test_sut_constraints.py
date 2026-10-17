from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from planning.procedural_plan import (
    ProceduralPlanInput,
    ProceduralPlanSourceInput,
    ProcedureStepInput,
)
from planning.sut_constraints import resolve_sut_constraints


def _plan(steps: list[ProcedureStepInput]) -> ProceduralPlanInput:
    return ProceduralPlanInput(
        schema_version="1",
        compiler_version="1",
        campaign_id="C9999",
        campaign_name="Example",
        source=ProceduralPlanSourceInput(
            bundle_sha256="source-bundle",
            object_count=1,
            campaign_stix_id="campaign--source",
            campaign_external_id="C9999",
        ),
        ordering_policy="tactic_rank_then_technique_id",
        steps=steps,
        content_sha256="source-hash",
    )


def test_platform_solver_finds_minimum_cover() -> None:
    plan = _plan(
        [
            ProcedureStepInput(
                technique_id="T1",
                technique_stix_id="attack-pattern--T1",
                name="one",
                platforms=["Linux", "Windows"],
                relationship_ids=["relationship--T1"],
            ),
            ProcedureStepInput(
                technique_id="T2",
                technique_stix_id="attack-pattern--T2",
                name="two",
                platforms=["Windows"],
                relationship_ids=["relationship--T2"],
            ),
        ]
    )

    constraints = resolve_sut_constraints(plan, materializable_platforms={"Linux", "Windows"})

    assert constraints.platform_resolution.selected_platforms == ["Windows"]
    assert constraints.platform_resolution.complete


def test_platform_solver_reports_backend_gap() -> None:
    plan = _plan(
        [
            ProcedureStepInput(
                technique_id="T1",
                technique_stix_id="attack-pattern--T1",
                name="one",
                platforms=["Windows"],
                relationship_ids=["relationship--T1"],
            )
        ]
    )

    constraints = resolve_sut_constraints(plan, materializable_platforms={"Linux"})

    assert constraints.platform_resolution.unsupported_platforms == ["Windows"]
    assert constraints.platform_resolution.uncovered_technique_ids == ["T1"]
    assert not constraints.platform_resolution.complete


def test_attacker_pre_platform_does_not_constrain_target_sut() -> None:
    plan = _plan(
        [
            ProcedureStepInput(
                technique_id="T1588.002",
                technique_stix_id="attack-pattern--T1588.002",
                name="Tool",
                execution_domain="attacker",
                platforms=["PRE"],
                relationship_ids=["relationship--T1588.002"],
            ),
            ProcedureStepInput(
                technique_id="T1082",
                technique_stix_id="attack-pattern--T1082",
                name="System Information Discovery",
                execution_domain="target",
                platforms=["Linux"],
                relationship_ids=["relationship--T1082"],
            ),
        ]
    )

    constraints = resolve_sut_constraints(plan, materializable_platforms={"Linux"})

    assert constraints.platform_resolution.selected_platforms == ["Linux"]
    assert constraints.platform_resolution.complete


def test_available_platform_cover_is_preferred_to_smaller_unavailable_cover():
    plan = _plan([
        ProcedureStepInput(technique_id="T1", technique_stix_id="attack-pattern--T1", name="one", platforms=["Windows", "Linux"], relationship_ids=["r1"]),
        ProcedureStepInput(technique_id="T2", technique_stix_id="attack-pattern--T2", name="two", platforms=["Windows", "macOS"], relationship_ids=["r2"]),
    ])
    resolved = resolve_sut_constraints(plan, materializable_platforms={"Linux", "macOS"})
    assert resolved.platform_resolution.selected_platforms == ["Linux", "macOS"]
    assert resolved.platform_resolution.complete


def test_supported_subset_is_retained_when_other_steps_require_unavailable_backend():
    plan = _plan([
        ProcedureStepInput(technique_id="T1", technique_stix_id="attack-pattern--T1",
                           name="mixed", platforms=["Linux", "Windows"],
                           relationship_ids=["relationship--T1"]),
        ProcedureStepInput(technique_id="T2", technique_stix_id="attack-pattern--T2",
                           name="unsupported", platforms=["Windows"],
                           relationship_ids=["relationship--T2"]),
    ])
    resolution = resolve_sut_constraints(plan, materializable_platforms={"Linux"}).platform_resolution
    assert resolution.selected_platforms == ["Linux", "Windows"]
    assert resolution.unsupported_platforms == ["Windows"]
    assert resolution.uncovered_technique_ids == ["T2"]
    assert not resolution.complete


def test_partial_plan_preserves_uncovered_step_and_refuses_full_blueprint():
    from planning.sut_blueprint import synthesize_blueprint, synthesize_partial_plan
    import pytest

    plan = _plan([
        ProcedureStepInput(technique_id="T1", technique_stix_id="attack-pattern--T1",
                           name="linux", platforms=["Linux"], relationship_ids=["r1"]),
        ProcedureStepInput(technique_id="T2", technique_stix_id="attack-pattern--T2",
                           name="windows", platforms=["Windows"], relationship_ids=["r2"]),
    ])
    constraints = resolve_sut_constraints(plan, materializable_platforms={"Linux"})
    partial = synthesize_partial_plan(constraints)
    assert [host.platform for host in partial.hosts] == ["Linux"]
    assert partial.uncovered_technique_ids == ["T2"]
    assert not partial.executable
    with pytest.raises(ValueError, match="incomplete constraints"):
        synthesize_blueprint(constraints)
