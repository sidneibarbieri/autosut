"""Compile a procedural plan and declared bindings into an executable contract."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from pydantic import BaseModel, Field

from .procedural_plan import ProceduralPlanInput
from .concretized_plan import ConcretizedPlanInput


class BoundTransition(BaseModel):
    technique_id: str
    requires: list[str] = Field(default_factory=list)
    produces: list[str] = Field(min_length=1)
    evidence_policy: str = "successful_outcome_with_declared_evidence_files"
    template_id: str | None = None
    bindings: dict[str, str] = Field(default_factory=dict)
    evidence_predicates: list[str] = Field(default_factory=list)
    fidelity_ceiling: str | None = None


class ExecutableCampaignContract(BaseModel):
    schema_version: str = "1"
    campaign_id: str
    source_campaign_id: str
    source_plan_sha256: str
    concretized_plan_sha256: str | None = None
    binding_catalog_sha256: str | None = None
    planning_certificate_sha256: str | None = None
    scope: str
    initial_facts: list[str] = Field(min_length=1)
    transitions: list[BoundTransition] = Field(min_length=1)
    content_sha256: str = ""

    def finalize_hash(self) -> None:
        payload = self.model_dump(mode="json", exclude={"content_sha256"})
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        self.content_sha256 = hashlib.sha256(encoded).hexdigest()


def compile_executable_contract(
    plan: ProceduralPlanInput,
    campaign_spec_path: Path,
) -> ExecutableCampaignContract:
    spec = json.loads(campaign_spec_path.read_text(encoding="utf-8"))
    source_campaign_id = str(spec.get("source_campaign_id", ""))
    if source_campaign_id != plan.campaign_id:
        raise ValueError(
            f"source campaign mismatch: spec={source_campaign_id!r}, "
            f"plan={plan.campaign_id!r}"
        )
    raw_contract = spec.get("execution_contract")
    if not isinstance(raw_contract, dict):
        raise ValueError("campaign spec has no execution_contract")
    raw_transitions = raw_contract.get("techniques", [])
    declared_ids = [str(step["technique_id"]) for step in raw_transitions]
    plan_ids = [step.technique_id for step in plan.steps]
    if declared_ids != plan_ids:
        raise ValueError(
            "execution contract sequence does not exactly match the procedural plan"
        )
    transitions = [
        BoundTransition(
            technique_id=str(step["technique_id"]),
            requires=list(step.get("requires", [])),
            produces=list(step.get("produces", [])),
        )
        for step in raw_transitions
    ]
    produced_so_far = set(raw_contract.get("initial_facts", []))
    for transition in transitions:
        missing = [
            fact_id
            for fact_id in transition.requires
            if fact_id not in produced_so_far
        ]
        if missing:
            raise ValueError(
                f"{transition.technique_id} requires facts not previously "
                f"declared or produced: {', '.join(missing)}"
            )
        produced_so_far.update(transition.produces)
    contract = ExecutableCampaignContract(
        campaign_id=str(spec["campaign_id"]),
        source_campaign_id=source_campaign_id,
        source_plan_sha256=plan.content_sha256,
        scope=str(raw_contract["scope"]),
        initial_facts=list(raw_contract.get("initial_facts", [])),
        transitions=transitions,
    )
    contract.finalize_hash()
    return contract


def compile_verified_contract(
    plan: ConcretizedPlanInput,
    campaign_spec_path: Path,
) -> ExecutableCampaignContract:
    spec = json.loads(campaign_spec_path.read_text(encoding="utf-8"))
    source_campaign_id = str(spec.get("source_campaign_id", ""))
    if source_campaign_id != plan.campaign_id:
        raise ValueError(
            f"source campaign mismatch: spec={source_campaign_id!r}, "
            f"plan={plan.campaign_id!r}"
        )
    raw_contract = spec.get("execution_contract")
    if not isinstance(raw_contract, dict):
        raise ValueError("campaign spec has no execution_contract")
    expected_ids = [
        str(step["technique_id"])
        for step in raw_contract.get("techniques", [])
    ]
    generated_ids = [step.technique_id for step in plan.steps]
    if expected_ids != generated_ids:
        raise ValueError(
            "verified plan sequence does not match the declared campaign slice"
        )
    transitions = [
        BoundTransition(
            technique_id=step.technique_id,
            requires=step.requires,
            produces=step.produces,
            template_id=step.template_id,
            bindings=step.bindings,
            evidence_predicates=step.evidence_predicates,
            fidelity_ceiling=step.fidelity_ceiling,
        )
        for step in plan.steps
    ]
    produced_so_far = set(raw_contract.get("initial_facts", []))
    for transition in transitions:
        missing = sorted(set(transition.requires) - produced_so_far)
        if missing:
            raise ValueError(
                f"{transition.technique_id} has unsatisfied requirements: "
                + ", ".join(missing)
            )
        produced_so_far.update(transition.produces)
    contract = ExecutableCampaignContract(
        campaign_id=str(spec["campaign_id"]),
        source_campaign_id=source_campaign_id,
        source_plan_sha256=plan.source_plan_sha256,
        concretized_plan_sha256=plan.content_sha256,
        binding_catalog_sha256=plan.binding_catalog_sha256,
        planning_certificate_sha256=plan.planning_certificate.content_sha256,
        scope=str(raw_contract["scope"]),
        initial_facts=list(raw_contract.get("initial_facts", [])),
        transitions=transitions,
    )
    contract.finalize_hash()
    return contract
