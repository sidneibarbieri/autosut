"""Check a compiled campaign against evidence-backed pre-execution observations."""

from __future__ import annotations

import hashlib
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from .binding_catalog import BindingCatalog
from .executable_contract import ExecutableCampaignContract


class ObservationEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    path: str = Field(min_length=1)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    def verify(self, root: Path) -> None:
        resolved_root = root.resolve()
        path = (resolved_root / self.path).resolve()
        if Path(self.path).is_absolute() or not path.is_relative_to(resolved_root):
            raise ValueError("observation evidence must stay within its evidence root")
        if hashlib.sha256(path.read_bytes()).hexdigest() != self.sha256:
            raise ValueError("observation evidence hash mismatch")


class ObservedBinding(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    binding_id: str = Field(min_length=1)
    kind: str = Field(min_length=1)
    value: str = Field(min_length=1)
    present: bool


class ScenarioObservation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = "autosut-scenario-observation/v2"
    run_id: str = Field(min_length=1)
    contract_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    bindings: tuple[ObservedBinding, ...]
    observed_facts: tuple[str, ...]
    absent_facts: tuple[str, ...]
    evidence: tuple[ObservationEvidence, ...] = Field(min_length=1)


def admit_scenario(
    contract: ExecutableCampaignContract,
    catalog: BindingCatalog,
    observation: ScenarioObservation,
    *,
    run_id: str,
    goal_facts: tuple[str, ...],
    evidence_root: Path,
) -> None:
    """Raise on disagreement; admission is not evidence of campaign execution.

    Observations must be supplied by the experiment's independent collector.
    File hashes protect integrity, not the truth of a collector's assertions.
    """
    contract_copy = contract.model_copy(deep=True)
    contract_copy.finalize_hash()
    if contract_copy.content_sha256 != contract.content_sha256:
        raise ValueError("contract hash mismatch")
    catalog_copy = catalog.model_copy(deep=True)
    catalog_copy.finalize_hash()
    if catalog_copy.content_sha256 != catalog.content_sha256:
        raise ValueError("catalog hash mismatch")
    if contract.binding_catalog_sha256 != catalog.content_sha256:
        raise ValueError("contract/catalog mismatch")
    if catalog.sut_id != contract.campaign_id:
        raise ValueError("campaign/SUT identity mismatch")
    if observation.run_id != run_id or observation.contract_sha256 != contract.content_sha256:
        raise ValueError("observation belongs to another run or contract")
    if not goal_facts or set(goal_facts) != set(catalog.goal_facts):
        raise ValueError("goals must match the frozen catalog")
    for evidence in observation.evidence:
        evidence.verify(evidence_root)
    declared = {binding.binding_id: binding for binding in catalog.bindings}
    observed = {binding.binding_id: binding for binding in observation.bindings}
    if len(declared) != len(catalog.bindings) or len(observed) != len(observation.bindings):
        raise ValueError("duplicate binding identity")
    for transition in contract.transitions:
        for binding_id in transition.bindings.values():
            expected = declared.get(binding_id)
            actual = observed.get(binding_id)
            if expected is None or actual is None or not actual.present:
                raise ValueError("required binding is absent")
            if (expected.kind, expected.value) != (actual.kind, actual.value):
                raise ValueError("observed binding differs from the declared binding")
            if expected.secret_reference and not expected.value.startswith("secret://"):
                raise ValueError("credentials must use secret references")
    state = set(observation.observed_facts)
    if not set(contract.initial_facts).issubset(state):
        raise ValueError("initial preconditions were not observed")
    if set(goal_facts) & state:
        raise ValueError("campaign goal already satisfied before execution")
    if not set(goal_facts).issubset(observation.absent_facts):
        raise ValueError("campaign goal absence was not established before execution")
    # Only declared initial facts may support the compiled causal chain.
    planned_state = set(contract.initial_facts)
    for transition in contract.transitions:
        if not set(transition.requires).issubset(planned_state):
            raise ValueError("missing causal predecessor")
        planned_state.update(transition.produces)
    if not set(goal_facts).issubset(planned_state):
        raise ValueError("campaign cannot reach the frozen goal")
