"""Consumer-side model for a verified STICKS concretized plan."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field


class ConcretizedStepInput(BaseModel):
    model_config = ConfigDict(extra="ignore")

    sequence: int
    technique_id: str
    template_id: str
    bindings: dict[str, str]
    requires: list[str]
    produces: list[str] = Field(min_length=1)
    evidence_predicates: list[str] = Field(min_length=1)
    fidelity_ceiling: str
    proposal_source: str
    assumption_count: int


class PlanningCertificateInput(BaseModel):
    model_config = ConfigDict(extra="ignore")

    initial_facts: list[str] = Field(default_factory=list)
    goal_facts: list[str] = Field(default_factory=list)
    valid: bool
    unresolved_goals: list[str] = Field(default_factory=list)
    transitions: list[dict] = Field(default_factory=list)
    content_sha256: str


class ConcretizedPlanInput(BaseModel):
    model_config = ConfigDict(extra="ignore")

    schema_version: str
    campaign_id: str
    source_plan_sha256: str
    binding_catalog_sha256: str
    action_catalog_sha256: str
    steps: list[ConcretizedStepInput] = Field(default_factory=list)
    unresolved_technique_ids: list[str] = Field(default_factory=list)
    planning_certificate: PlanningCertificateInput
    llm_call_sha256: str | None = None
    execution_semantic_sha256: str
    content_sha256: str


def load_concretized_plan(
    path: Path,
    *,
    require_complete: bool = True,
) -> ConcretizedPlanInput:
    payload = json.loads(path.read_text(encoding="utf-8"))
    expected = str(payload.get("content_sha256", ""))
    hash_payload = {
        key: value for key, value in payload.items() if key != "content_sha256"
    }
    actual = hashlib.sha256(
        json.dumps(hash_payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    if actual != expected:
        raise ValueError(f"concretized plan hash mismatch: {path}")
    plan = ConcretizedPlanInput.model_validate(payload)
    if require_complete and plan.unresolved_technique_ids:
        raise ValueError(
            "concretized plan has unresolved techniques: "
            + ", ".join(plan.unresolved_technique_ids)
        )
    if require_complete and not plan.planning_certificate.valid:
        raise ValueError("concretized plan has no valid reachability certificate")
    return plan
