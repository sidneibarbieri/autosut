"""Typed, evidence-backed state for one campaign execution.

The ledger is deliberately independent of planning or language-model retrieval.
It records only facts declared by a campaign contract or observed in execution.
"""

from __future__ import annotations

import hashlib
import json
from contextlib import contextmanager
from contextvars import ContextVar
from enum import Enum
from pathlib import Path

from pydantic import BaseModel, Field

from .models import ExecutionMode, RunResult

_active_contract: ContextVar[Path | None] = ContextVar("active_contract", default=None)
_active_campaign_spec: ContextVar[Path | None] = ContextVar("active_campaign_spec", default=None)


@contextmanager
def use_verified_contract(path: Path, campaign_spec: Path | None = None):
    """Scope a prepared contract to one replay without modifying release evidence."""
    token = _active_contract.set(path)
    spec_token = _active_campaign_spec.set(campaign_spec)
    try:
        yield
    finally:
        _active_contract.reset(token)
        _active_campaign_spec.reset(spec_token)


class FactSource(str, Enum):
    catalog = "catalog"
    execution = "execution"


class StateFact(BaseModel):
    """One scoped fact with an evidence trail."""

    fact_id: str
    subject: str
    predicate: str
    value: str
    source: FactSource
    evidence_files: list[str] = Field(default_factory=list)


class TransitionContract(BaseModel):
    """Declared state requirements and effects for one technique."""

    technique_id: str
    requires: list[str] = Field(default_factory=list)
    produces: list[StateFact] = Field(default_factory=list)


class ExecutionContract(BaseModel):
    """Declarative state contract for one bounded executable campaign slice."""

    scope: str
    initial_facts: list[str] = Field(min_length=1)
    techniques: list[TransitionContract] = Field(min_length=1)

    def technique_ids(self) -> tuple[str, ...]:
        return tuple(step.technique_id for step in self.techniques)


class StateTransition(BaseModel):
    """Result of applying one contract to an observed technique outcome."""

    sequence: int
    technique_id: str
    status: str
    missing_requirements: list[str] = Field(default_factory=list)
    produced_fact_ids: list[str] = Field(default_factory=list)
    evidence_files: list[str] = Field(default_factory=list)


class ContextObservation(BaseModel):
    """One declared non-attack activity executed before campaign steps."""

    activity_id: str
    source_host: str
    destination_host: str
    protocol: str
    port: int
    purpose: str
    status: str
    evidence_files: list[str] = Field(default_factory=list)


class CampaignStateLedger(BaseModel):
    """Portable state record for a concrete campaign run."""

    schema_version: str = "1"
    campaign_id: str
    run_id: str
    initial_facts: list[StateFact]
    transitions: list[StateTransition]
    facts: list[StateFact]
    context_observations: list[ContextObservation] = Field(default_factory=list)
    contract_coverage: str
    declared_technique_ids: list[str] = Field(default_factory=list)
    executed_technique_ids: list[str] = Field(default_factory=list)
    source_plan_sha256: str | None = None
    executable_contract_sha256: str | None = None
    content_sha256: str = ""

    def finalize_hash(self) -> None:
        payload = self.model_dump(mode="json", exclude={"content_sha256"})
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        self.content_sha256 = hashlib.sha256(encoded).hexdigest()


def _fact_from_id(fact_id: str) -> StateFact:
    """Create a normalized execution fact from its declared identifier."""

    subject, _, predicate = fact_id.partition(".")
    return StateFact(
        fact_id=fact_id,
        subject=subject or "campaign",
        predicate=predicate or "state",
        value="observed",
        source=FactSource.execution,
    )


def _campaign_spec(campaign_id: str) -> dict:
    path = _active_campaign_spec.get() or (Path(__file__).resolve().parents[2] / "campaigns" / f"{campaign_id}.json")
    spec = json.loads(path.read_text(encoding="utf-8"))
    if spec.get("campaign_id") != campaign_id:
        raise ValueError("campaign specification identity differs from execution")
    return spec


def _verified_contract_payload(campaign_id: str) -> dict | None:
    campaign_spec = _campaign_spec(campaign_id)
    source_campaign_id = campaign_spec.get("source_campaign_id")
    if not source_campaign_id:
        return None
    path = _active_contract.get() or (
        Path(__file__).resolve().parents[2]
        / "release"
        / "plans"
        / f"{source_campaign_id}.verified-executable-contract.json"
    )
    if not path.exists():
        return None
    payload = json.loads(path.read_text(encoding="utf-8"))
    expected_hash = str(payload.get("content_sha256", ""))
    hash_payload = {
        key: value for key, value in payload.items() if key != "content_sha256"
    }
    actual_hash = hashlib.sha256(
        json.dumps(hash_payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    if actual_hash != expected_hash:
        raise ValueError(f"verified execution contract hash mismatch: {path}")
    if payload.get("campaign_id") != campaign_id:
        raise ValueError(
            f"verified execution contract campaign mismatch: {path}"
        )
    if payload.get("source_campaign_id") != source_campaign_id:
        raise ValueError(
            f"verified execution contract source mismatch: {path}"
        )
    return payload


def execution_contract_for_campaign(campaign_id: str) -> ExecutionContract | None:
    """Load and validate the executable state contract for one campaign."""

    verified = _verified_contract_payload(campaign_id)
    raw_contract = (
        {
            "scope": verified["scope"],
            "initial_facts": verified["initial_facts"],
            "techniques": verified["transitions"],
        }
        if verified is not None
        else _campaign_spec(campaign_id).get("execution_contract")
    )
    if raw_contract is None:
        return None
    techniques = [
        TransitionContract(
            technique_id=step["technique_id"],
            requires=list(step.get("requires", [])),
            produces=[_fact_from_id(fact_id) for fact_id in step.get("produces", [])],
        )
        for step in raw_contract.get("techniques", [])
    ]
    contract = ExecutionContract(
        scope=raw_contract["scope"],
        initial_facts=list(raw_contract.get("initial_facts", [])),
        techniques=techniques,
    )
    if len(set(contract.technique_ids())) != len(contract.technique_ids()):
        raise ValueError(f"duplicate technique id in contract for {campaign_id}")
    return contract


def initial_facts_for_campaign(contract: ExecutionContract | None) -> list[StateFact]:
    """Return the declared initial state for a controlled execution slice."""

    if contract is None:
        return [
            StateFact(
                fact_id="sut.ready",
                subject="sut",
                predicate="state",
                value="ready",
                source=FactSource.catalog,
            )
        ]
    return [
        StateFact(
            fact_id=fact_id,
            subject=fact_id.split(".", maxsplit=1)[0],
            predicate=fact_id.split(".", maxsplit=1)[-1],
            value="ready",
            source=FactSource.catalog,
        )
        for fact_id in contract.initial_facts
    ]


def build_ledger(result: RunResult) -> CampaignStateLedger:
    """Build and validate a ledger from a completed campaign result."""

    campaign_spec = _campaign_spec(result.campaign_id)
    execution_contract = execution_contract_for_campaign(result.campaign_id)
    source_campaign_id = campaign_spec.get("source_campaign_id")
    verified_contract_path = (
        Path(__file__).resolve().parents[2]
        / "release"
        / "plans"
        / f"{source_campaign_id}.verified-executable-contract.json"
        if source_campaign_id
        else None
    )
    legacy_contract_path = (
        Path(__file__).resolve().parents[2]
        / "release"
        / "plans"
        / f"{source_campaign_id}.executable-contract.json"
        if source_campaign_id
        else None
    )
    executable_contract_path = (
        verified_contract_path
        if verified_contract_path is not None and verified_contract_path.exists()
        else legacy_contract_path
    )
    executable_contract_payload = _verified_contract_payload(result.campaign_id) or (
        json.loads(executable_contract_path.read_text(encoding="utf-8"))
        if executable_contract_path is not None
        and executable_contract_path.exists()
        else None
    )
    context_path = (
        Path(result.manifest_path).parent / "context" / "context_observations.json"
        if result.manifest_path
        else None
    )
    context_observations = (
        [
            ContextObservation.model_validate(item)
            for item in json.loads(context_path.read_text(encoding="utf-8"))
        ]
        if context_path is not None and context_path.exists()
        else []
    )
    contracts = (
        {step.technique_id: step for step in execution_contract.techniques}
        if execution_contract is not None
        else {}
    )
    initial_facts = initial_facts_for_campaign(execution_contract)

    known_facts = {fact.fact_id for fact in initial_facts}
    facts = list(initial_facts)
    transitions: list[StateTransition] = []
    for sequence, outcome in enumerate(result.techniques, start=1):
        contract = contracts.get(outcome.technique_id)
        missing = [] if contract is None else [
            fact_id for fact_id in contract.requires if fact_id not in known_facts
        ]
        produced: list[str] = []
        if (
            outcome.status == "success"
            and outcome.executed_mode != ExecutionMode.naive_simulated
            and contract is not None
            and not missing
        ):
            for fact in contract.produces:
                observed_fact = fact.model_copy(
                    update={"evidence_files": list(outcome.evidence_files)}
                )
                facts.append(observed_fact)
                known_facts.add(observed_fact.fact_id)
                produced.append(observed_fact.fact_id)
        transitions.append(
            StateTransition(
                sequence=sequence,
                technique_id=outcome.technique_id,
                status=(
                    "marker_only"
                    if outcome.status == "success"
                    and outcome.executed_mode == ExecutionMode.naive_simulated
                    else outcome.status
                ),
                missing_requirements=missing,
                produced_fact_ids=produced,
                evidence_files=list(outcome.evidence_files),
            )
        )

    coverage = "declared" if execution_contract is not None else "not_declared"
    ledger = CampaignStateLedger(
        campaign_id=result.campaign_id,
        run_id=result.run_id,
        initial_facts=initial_facts,
        transitions=transitions,
        facts=facts,
        context_observations=context_observations,
        contract_coverage=coverage,
        declared_technique_ids=(
            list(execution_contract.technique_ids())
            if execution_contract is not None
            else []
        ),
        executed_technique_ids=[outcome.technique_id for outcome in result.techniques],
        source_plan_sha256=(
            str(executable_contract_payload["source_plan_sha256"])
            if executable_contract_payload is not None
            else None
        ),
        executable_contract_sha256=(
            str(executable_contract_payload["content_sha256"])
            if executable_contract_payload is not None
            else None
        ),
    )
    ledger.finalize_hash()
    return ledger


def validate_ledger(ledger: CampaignStateLedger) -> list[str]:
    """Return integrity or state-admissibility violations for one ledger."""

    expected_hash = ledger.content_sha256
    ledger.finalize_hash()
    violations: list[str] = []
    if ledger.content_sha256 != expected_hash:
        violations.append("content_sha256 does not match ledger content")
    if ledger.contract_coverage == "declared":
        if ledger.executed_technique_ids != ledger.declared_technique_ids:
            violations.append(
                "executed technique sequence does not match the declared contract"
            )
        for transition in ledger.transitions:
            if transition.status != "success":
                violations.append(
                    f"declared transition {transition.technique_id} "
                    f"has status {transition.status}"
                )
            if transition.status == "success" and transition.missing_requirements:
                violations.append(
                    f"{transition.technique_id} succeeded without "
                    f"{', '.join(transition.missing_requirements)}"
                )
        if (
            ledger.source_plan_sha256 is None
            and ledger.campaign_id == "0.shadowray"
        ):
            violations.append("source plan hash is missing for 0.shadowray")
        if (
            ledger.executable_contract_sha256 is None
            and ledger.campaign_id == "0.shadowray"
        ):
            violations.append(
                "executable contract hash is missing for 0.shadowray"
            )
    for observation in ledger.context_observations:
        if observation.status != "success":
            violations.append(
                f"context activity {observation.activity_id} did not complete"
            )
    return violations
