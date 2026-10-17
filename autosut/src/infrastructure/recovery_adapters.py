"""Provider-neutral revision and executable-contract admission adapters."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from .failure_recovery import (
    AdmissionDecision,
    FailureClassification,
    RevisionProposal,
    sha256_text,
)

SHA256_PATTERN = r"^[0-9a-f]{64}$"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RevisedTransition(StrictModel):
    technique_id: str = Field(min_length=1)
    requires: tuple[str, ...] = ()
    produces: tuple[str, ...] = Field(min_length=1)
    evidence_policy: str = "successful_outcome_with_declared_evidence_files"
    template_id: str = Field(min_length=1)
    bindings: dict[str, str]
    evidence_predicates: tuple[str, ...] = Field(min_length=1)
    fidelity_ceiling: str = Field(min_length=1)

    @model_validator(mode="after")
    def _values_are_closed(self) -> "RevisedTransition":
        for label, values in (
            ("requires", self.requires),
            ("produces", self.produces),
            ("evidence predicates", self.evidence_predicates),
        ):
            if len(values) != len(set(values)):
                raise ValueError(f"transition {label} must be unique")
            if any(not value for value in values):
                raise ValueError(f"transition {label} cannot contain an empty value")
        if any(not key or not value for key, value in self.bindings.items()):
            raise ValueError("transition bindings must have non-empty keys and values")
        return self


class RevisedExecutableContract(StrictModel):
    schema_version: str = "1"
    campaign_id: str = Field(min_length=1)
    source_campaign_id: str = Field(min_length=1)
    source_plan_sha256: str = Field(pattern=SHA256_PATTERN)
    concretized_plan_sha256: str = Field(pattern=SHA256_PATTERN)
    binding_catalog_sha256: str = Field(pattern=SHA256_PATTERN)
    planning_certificate_sha256: str = Field(pattern=SHA256_PATTERN)
    scope: str = Field(min_length=1)
    initial_facts: tuple[str, ...] = Field(min_length=1)
    transitions: tuple[RevisedTransition, ...] = Field(min_length=1)
    content_sha256: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def _hash_and_graph_are_valid(self) -> "RevisedExecutableContract":
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"content_sha256"}))
        if self.content_sha256 != expected:
            raise ValueError("revised executable contract hash mismatch")
        if len(self.initial_facts) != len(set(self.initial_facts)):
            raise ValueError("initial facts must be unique")
        technique_ids = [transition.technique_id for transition in self.transitions]
        if len(technique_ids) != len(set(technique_ids)):
            raise ValueError("revised executable contract has duplicate techniques")
        reachable = set(self.initial_facts)
        for transition in self.transitions:
            missing = sorted(set(transition.requires) - reachable)
            if missing:
                raise ValueError(
                    f"{transition.technique_id} has unreachable requirements: " + ", ".join(missing)
                )
            reachable.update(transition.produces)
        return self


class TemplateAdmissionRule(StrictModel):
    template_id: str = Field(min_length=1)
    binding_patterns: dict[str, str] = Field(min_length=1)
    evidence_predicates: frozenset[str] = Field(min_length=1)

    @model_validator(mode="after")
    def _patterns_compile(self) -> "TemplateAdmissionRule":
        if any(not name or not pattern for name, pattern in self.binding_patterns.items()):
            raise ValueError("template binding rules require non-empty names and patterns")
        for pattern in self.binding_patterns.values():
            re.compile(pattern)
        return self


class ExecutableContractAdmissionPolicy(StrictModel):
    policy_version: str = Field(min_length=1)
    campaign_id: str = Field(min_length=1)
    source_campaign_id: str = Field(min_length=1)
    source_plan_sha256: str = Field(pattern=SHA256_PATTERN)
    concretized_plan_sha256: str = Field(pattern=SHA256_PATTERN)
    binding_catalog_sha256: str = Field(pattern=SHA256_PATTERN)
    planning_certificate_sha256: str = Field(pattern=SHA256_PATTERN)
    scope: str = Field(min_length=1)
    template_rules: tuple[TemplateAdmissionRule, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def _template_rules_are_unique(self) -> "ExecutableContractAdmissionPolicy":
        template_ids = [rule.template_id for rule in self.template_rules]
        if len(template_ids) != len(set(template_ids)):
            raise ValueError("template admission rules must have unique identifiers")
        return self


def build_revision_proposal(
    *,
    parent_artifact: str,
    response_json: str,
    classification: FailureClassification,
    proposer_id: str,
    proposer_version: str,
    rationale: str,
) -> RevisionProposal:
    """Convert one provider response into canonical JSON without admitting its content."""
    payload = json.loads(response_json)
    if not isinstance(payload, dict):
        raise ValueError("revision response must be one JSON object")
    artifact = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return RevisionProposal(
        parent_sha256=sha256_text(parent_artifact),
        artifact=artifact,
        artifact_sha256=sha256_text(artifact),
        failure_kind=classification.kind,
        proposer_id=proposer_id,
        proposer_version=proposer_version,
        rationale=rationale,
    )


def admit_executable_contract_revision(
    proposal: RevisionProposal,
    policy: ExecutableContractAdmissionPolicy,
) -> AdmissionDecision:
    """Reject any revision that changes provenance or leaves the closed execution policy."""
    try:
        contract = RevisedExecutableContract.model_validate_json(proposal.artifact)
        _enforce_policy(contract, policy)
    except (ValidationError, ValueError) as failure:
        return AdmissionDecision(
            proposal_sha256=proposal.proposal_sha256,
            policy_version=policy.policy_version,
            admitted=False,
            reasons=(str(failure),),
        )
    return AdmissionDecision(
        proposal_sha256=proposal.proposal_sha256,
        policy_version=policy.policy_version,
        admitted=True,
    )


def _enforce_policy(
    contract: RevisedExecutableContract,
    policy: ExecutableContractAdmissionPolicy,
) -> None:
    immutable_fields = (
        "campaign_id",
        "source_campaign_id",
        "source_plan_sha256",
        "concretized_plan_sha256",
        "binding_catalog_sha256",
        "planning_certificate_sha256",
        "scope",
    )
    changed = [
        field_name
        for field_name in immutable_fields
        if getattr(contract, field_name) != getattr(policy, field_name)
    ]
    if changed:
        raise ValueError("revision changed immutable fields: " + ", ".join(changed))
    rules = {rule.template_id: rule for rule in policy.template_rules}
    for transition in contract.transitions:
        if transition.template_id not in rules:
            raise ValueError(f"template is outside the admission catalog: {transition.template_id}")
        rule = rules[transition.template_id]
        expected_binding_keys = set(rule.binding_patterns)
        observed_binding_keys = set(transition.bindings)
        if observed_binding_keys != expected_binding_keys:
            raise ValueError(
                f"template {transition.template_id} binding schema mismatch: "
                f"expected {sorted(expected_binding_keys)}, "
                f"observed {sorted(observed_binding_keys)}"
            )
        for binding_name, binding_value in transition.bindings.items():
            if len(binding_value) > 4096:
                raise ValueError(f"binding exceeds the size limit: {binding_name}")
            if re.fullmatch(rule.binding_patterns[binding_name], binding_value) is None:
                raise ValueError(f"binding violates the frozen policy: {binding_name}")
        if set(transition.evidence_predicates) != set(rule.evidence_predicates):
            raise ValueError(
                f"template {transition.template_id} evidence predicate schema mismatch"
            )


def canonical_sha256(payload: Any) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )
    return hashlib.sha256(encoded).hexdigest()
