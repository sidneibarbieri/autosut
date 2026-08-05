from __future__ import annotations

import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from planning.procedural_plan import ProceduralPlanInput, ProcedureStepInput
from planning.sut_constraints import resolve_sut_constraints


def _plan(steps: list[ProcedureStepInput]) -> ProceduralPlanInput:
    return ProceduralPlanInput(
        schema_version="1",
        compiler_version="1",
        campaign_id="C9999",
        campaign_name="Example",
        ordering_policy="tactic_rank_then_technique_id",
        steps=steps,
        content_sha256="source-hash",
    )


def test_platform_solver_finds_minimum_cover() -> None:
    plan = _plan(
        [
            ProcedureStepInput(
                technique_id="T1", name="one", platforms=["Linux", "Windows"]
            ),
            ProcedureStepInput(
                technique_id="T2", name="two", platforms=["Windows"]
            ),
        ]
    )

    constraints = resolve_sut_constraints(
        plan, materializable_platforms={"Linux", "Windows"}
    )

    assert constraints.platform_resolution.selected_platforms == ["Windows"]
    assert constraints.platform_resolution.complete


def test_platform_solver_reports_backend_gap() -> None:
    plan = _plan(
        [
            ProcedureStepInput(
                technique_id="T1", name="one", platforms=["Windows"]
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
                name="Tool",
                execution_domain="attacker",
                platforms=["PRE"],
            ),
            ProcedureStepInput(
                technique_id="T1082",
                name="System Information Discovery",
                execution_domain="target",
                platforms=["Linux"],
            ),
        ]
    )

    constraints = resolve_sut_constraints(plan, materializable_platforms={"Linux"})

    assert constraints.platform_resolution.selected_platforms == ["Linux"]
    assert constraints.platform_resolution.complete
