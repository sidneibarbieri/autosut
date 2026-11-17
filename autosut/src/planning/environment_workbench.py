"""Environment planning contract shared by user interfaces."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict

from .procedural_plan import (
    ProceduralPlanInput,
    load_procedural_plan,
    parse_procedural_plan,
)
from .sut_constraints import SUTConstraintSet, resolve_sut_constraints


class EnvironmentPlanningResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["autosut-environment-planning/v1"] = (
        "autosut-environment-planning/v1"
    )
    operational_status: Literal["not_run"] = "not_run"
    plan: ProceduralPlanInput
    constraints: SUTConstraintSet


def plan_environment(plan_path: Path) -> EnvironmentPlanningResult:
    """Verify a supplied plan and resolve requirements for the Linux backend."""
    plan = load_procedural_plan(plan_path)
    return _resolve_environment(plan)


def plan_environment_payload(payload: object) -> EnvironmentPlanningResult:
    """Verify interactive input before invoking the shared resolver."""
    return _resolve_environment(parse_procedural_plan(payload))


def _resolve_environment(plan: ProceduralPlanInput) -> EnvironmentPlanningResult:
    constraints = resolve_sut_constraints(plan, materializable_platforms={"Linux"})
    return EnvironmentPlanningResult(plan=plan, constraints=constraints)
