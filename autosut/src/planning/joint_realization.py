"""Validate STICKS realization graphs against one declared AutoSUT contract."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from .binding_catalog import BindingCatalog
from .concretized_plan import ConcretizedPlanInput
from .sut_blueprint import SUTBlueprint


class InputModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CausalLinkInput(InputModel):
    fact_id: str
    producer_sequence: int
    consumer_sequence: int


class CausalGraphNodeInput(InputModel):
    sequence: int
    source_step_index: int
    technique_id: str
    template_id: str


class CausalRealizationGraphInput(InputModel):
    graph_kind: str
    initial_facts: list[str] = Field(default_factory=list)
    goal_facts: list[str] = Field(default_factory=list)
    source_step_order: list[int] = Field(default_factory=list)
    nodes: list[CausalGraphNodeInput] = Field(default_factory=list)
    edges: list[CausalLinkInput] = Field(default_factory=list)
    causal_structure_sha256: str
    content_sha256: str


class RealizationCandidateInput(InputModel):
    rank: int
    source_step_order: list[int] = Field(default_factory=list)
    total_assumption_count: int
    minimum_fidelity_ceiling: str
    proposal_sources: list[str] = Field(default_factory=list)
    plan: ConcretizedPlanInput
    graph: CausalRealizationGraphInput
    content_sha256: str


class RealizationSpaceInput(InputModel):
    schema_version: Literal["1"]
    campaign_id: str
    source_plan_sha256: str
    binding_catalog_sha256: str
    enumeration_status: str
    action_catalog_sha256: str
    source_ordering_policy: str
    source_limitations: list[str] = Field(default_factory=list)
    generation_policy: str
    candidate_universe: str
    template_overlay_sha256: str | None = None
    operational_status: str
    source_step_count: int
    maximum_realizations: int
    maximum_search_states: int
    search_states_explored: int
    procedure_assignments_explored: int
    ordering_search_states_explored: int
    seeded_realization_count: int
    search_exhausted: bool
    truncation_reason: str | None = None
    dead_end_count: int
    maximal_realized_steps: int
    dead_end_technique_ids: list[str] = Field(default_factory=list)
    candidate_inventory: list[dict] = Field(default_factory=list)
    retrieval_traces: list[dict] = Field(default_factory=list)
    step_realization_coverage: list[dict] = Field(default_factory=list)
    blocker_counts: list[dict] = Field(default_factory=list)
    realization_count: int
    ordering_variant_count: int
    procedure_assignment_variant_count: int
    behavior_contract_variant_count: int
    causal_structure_variant_count: int
    graph_variant_count: int
    realizations: list[RealizationCandidateInput] = Field(default_factory=list)
    content_sha256: str


class PairingIssue(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    code: str
    message: str
    sequence: int | None = None


class JointRealizationAssessment(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    rank: int
    realization_sha256: str
    execution_semantic_sha256: str
    compatible: bool
    used_binding_count: int = Field(ge=0)
    issues: tuple[PairingIssue, ...] = ()


class JointRealizationCertificate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "1"
    campaign_id: str
    sut_id: str
    realization_space_sha256: str
    sut_blueprint_sha256: str
    binding_catalog_sha256: str
    enumeration_status: str
    compatibility_scope: Literal["declared_sut_contract_only"] = "declared_sut_contract_only"
    operational_status: Literal["not_run"] = "not_run"
    compatible_realization_count: int = Field(ge=0)
    selected_realization_sha256: str | None = None
    assessments: tuple[JointRealizationAssessment, ...] = ()
    content_sha256: str = ""

    def finalize_hash(self) -> None:
        self.content_sha256 = _model_hash(self)


def _payload_hash(payload: dict, *, excluded_field: str = "content_sha256") -> str:
    canonical = {key: value for key, value in payload.items() if key != excluded_field}
    encoded = json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _model_hash(model: BaseModel) -> str:
    return _payload_hash(model.model_dump(mode="json"))


def _require_payload_hash(payload: dict, label: str) -> None:
    expected = str(payload.get("content_sha256", ""))
    if not expected or _payload_hash(payload) != expected:
        raise ValueError(f"{label} hash mismatch")


def _execution_semantic_hash(plan: dict) -> str:
    semantic_payload = {
        "campaign_id": plan["campaign_id"],
        "ordering_policy": plan["ordering_policy"],
        "source_plan_sha256": plan["source_plan_sha256"],
        "binding_catalog_sha256": plan["binding_catalog_sha256"],
        "steps": [
            {
                "sequence": step["sequence"],
                "technique_id": step["technique_id"],
                "template_id": step["template_id"],
                "bindings": step["bindings"],
                "requires": step["requires"],
                "produces": step["produces"],
                "evidence_predicates": step["evidence_predicates"],
                "fidelity_ceiling": step["fidelity_ceiling"],
            }
            for step in plan["steps"]
        ],
        "unresolved_technique_ids": plan["unresolved_technique_ids"],
    }
    encoded = json.dumps(semantic_payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def load_realization_space(path: Path) -> RealizationSpaceInput:
    payload = json.loads(path.read_text(encoding="utf-8"))
    raw_realizations = payload.get("realizations", [])
    if not isinstance(raw_realizations, list):
        raise ValueError("realizations must be a list")
    for index, realization in enumerate(raw_realizations):
        if not isinstance(realization, dict):
            raise ValueError(f"realization {index} must be an object")
        plan = realization.get("plan")
        graph = realization.get("graph")
        if not isinstance(plan, dict) or not isinstance(graph, dict):
            raise ValueError(f"realization {index} has no plan or graph")
        certificate = plan.get("planning_certificate")
        if not isinstance(certificate, dict):
            raise ValueError(f"realization {index} has no planning certificate")
        _require_payload_hash(certificate, f"realization {index} planning certificate")
        if _execution_semantic_hash(plan) != plan.get("execution_semantic_sha256"):
            raise ValueError(f"realization {index} execution semantic hash mismatch")
        _require_payload_hash(plan, f"realization {index} plan")
        _require_payload_hash(graph, f"realization {index} graph")
        _require_payload_hash(realization, f"realization {index}")

    _require_payload_hash(payload, "realization space")

    result = RealizationSpaceInput.model_validate(payload)
    if result.realization_count != len(result.realizations):
        raise ValueError("realization count does not match payload")
    expected_ranks = list(range(1, len(result.realizations) + 1))
    if [item.rank for item in result.realizations] != expected_ranks:
        raise ValueError("realization ranks are not contiguous")
    return result


def _validate_declared_hash(model: BaseModel, label: str) -> None:
    expected = str(getattr(model, "content_sha256", ""))
    if not expected or _model_hash(model) != expected:
        raise ValueError(f"{label} hash mismatch")


def _global_issues(
    space: RealizationSpaceInput,
    blueprint: SUTBlueprint,
    catalog: BindingCatalog,
) -> list[PairingIssue]:
    issues: list[PairingIssue] = []
    if space.campaign_id != blueprint.campaign_id:
        issues.append(
            PairingIssue(
                code="CAMPAIGN_BLUEPRINT_MISMATCH",
                message="realization space and SUT blueprint identify different campaigns",
            )
        )
    if space.binding_catalog_sha256 != catalog.content_sha256:
        issues.append(
            PairingIssue(
                code="BINDING_CATALOG_MISMATCH",
                message="realization space was generated against another binding catalog",
            )
        )
    if not blueprint.hosts:
        issues.append(PairingIssue(code="NO_TARGET_HOST", message="SUT blueprint has no host"))
    policy = blueprint.network_policy
    if policy.host_network_access or policy.internet_egress or not policy.lab_private_network:
        issues.append(
            PairingIssue(
                code="NON_ISOLATED_NETWORK_POLICY",
                message="SUT blueprint does not enforce the declared isolated laboratory",
            )
        )
    binding_ids = [binding.binding_id for binding in catalog.bindings]
    duplicates = sorted(
        binding_id for binding_id, count in Counter(binding_ids).items() if count > 1
    )
    if duplicates:
        issues.append(
            PairingIssue(
                code="DUPLICATE_BINDING_ID",
                message="duplicate binding identifiers: " + ", ".join(duplicates),
            )
        )
    return issues


def _expected_causal_edges(
    plan: ConcretizedPlanInput,
) -> tuple[list[tuple[str, int, int]], list[PairingIssue]]:
    facts = set(plan.planning_certificate.initial_facts)
    producers = {fact_id: 0 for fact_id in facts}
    edges: list[tuple[str, int, int]] = []
    issues: list[PairingIssue] = []
    for step in plan.steps:
        missing = sorted(set(step.requires) - facts)
        if missing:
            issues.append(
                PairingIssue(
                    code="UNSATISFIED_CAUSAL_PRECONDITION",
                    message="missing facts: " + ", ".join(missing),
                    sequence=step.sequence,
                )
            )
        for fact_id in step.requires:
            if fact_id in producers:
                edges.append((fact_id, producers[fact_id], step.sequence))
        facts.update(step.produces)
        for fact_id in step.produces:
            producers[fact_id] = step.sequence
    unresolved = sorted(set(plan.planning_certificate.goal_facts) - facts)
    if unresolved:
        issues.append(
            PairingIssue(
                code="UNRESOLVED_GOAL",
                message="unresolved goal facts: " + ", ".join(unresolved),
            )
        )
    return edges, issues


def _binding_issues(
    realization: RealizationCandidateInput,
    blueprint: SUTBlueprint,
    catalog: BindingCatalog,
) -> tuple[set[str], list[PairingIssue]]:
    binding_index = {binding.binding_id: binding for binding in catalog.bindings}
    target_host_ids = {host.host_id for host in blueprint.hosts}
    used_binding_ids: set[str] = set()
    issues: list[PairingIssue] = []
    for step in realization.plan.steps:
        for binding_id in step.bindings.values():
            used_binding_ids.add(binding_id)
            binding = binding_index.get(binding_id)
            if binding is None:
                issues.append(
                    PairingIssue(
                        code="UNKNOWN_BINDING",
                        message=f"unknown binding {binding_id}",
                        sequence=step.sequence,
                    )
                )
                continue
            if binding.scope != "lab":
                issues.append(
                    PairingIssue(
                        code="EXTERNAL_BINDING",
                        message=f"binding {binding_id} is outside the laboratory",
                        sequence=step.sequence,
                    )
                )
            if binding.kind == "credential_source" and (
                not binding.secret_reference or not binding.value.startswith("secret://")
            ):
                issues.append(
                    PairingIssue(
                        code="PLAINTEXT_CREDENTIAL_BINDING",
                        message=(
                            f"credential binding {binding_id} is not an opaque " "secret reference"
                        ),
                        sequence=step.sequence,
                    )
                )
            if binding.kind == "target_host":
                host_id = binding.value.removeprefix("lab://").split("/", maxsplit=1)[0]
                if not binding.value.startswith("lab://") or host_id not in target_host_ids:
                    issues.append(
                        PairingIssue(
                            code="UNKNOWN_BLUEPRINT_HOST",
                            message=f"binding {binding_id} does not resolve to a blueprint host",
                            sequence=step.sequence,
                        )
                    )
    return used_binding_ids, issues


def _realization_issues(
    realization: RealizationCandidateInput,
    space: RealizationSpaceInput,
    blueprint: SUTBlueprint,
    catalog: BindingCatalog,
    global_issues: list[PairingIssue],
) -> tuple[set[str], list[PairingIssue]]:
    issues = list(global_issues)
    plan = realization.plan
    if plan.campaign_id != space.campaign_id or plan.source_plan_sha256 != space.source_plan_sha256:
        issues.append(
            PairingIssue(
                code="SOURCE_PLAN_MISMATCH",
                message="realization does not belong to the declared source plan",
            )
        )
    if plan.binding_catalog_sha256 != catalog.content_sha256:
        issues.append(
            PairingIssue(
                code="PLAN_BINDING_CATALOG_MISMATCH",
                message="realization plan was verified against another binding catalog",
            )
        )
    if plan.unresolved_technique_ids:
        issues.append(
            PairingIssue(
                code="UNRESOLVED_TECHNIQUES",
                message="realization contains unresolved techniques",
            )
        )
    if not plan.planning_certificate.valid:
        issues.append(
            PairingIssue(
                code="INVALID_PLANNING_CERTIFICATE",
                message="realization planning certificate is not valid",
            )
        )
    if sorted(plan.planning_certificate.initial_facts) != sorted(catalog.initial_facts):
        issues.append(
            PairingIssue(
                code="INITIAL_FACT_MISMATCH",
                message="realization and SUT catalog declare different initial facts",
            )
        )
    expected_source_indices = list(range(space.source_step_count))
    if sorted(realization.source_step_order) != expected_source_indices:
        issues.append(
            PairingIssue(
                code="INCOMPLETE_SOURCE_STEP_COVERAGE",
                message="realization does not cover every source step exactly once",
            )
        )
    if realization.graph.source_step_order != realization.source_step_order:
        issues.append(
            PairingIssue(
                code="GRAPH_ORDER_MISMATCH",
                message="causal graph and realization declare different source orders",
            )
        )
    if len(realization.graph.nodes) != len(plan.steps):
        issues.append(
            PairingIssue(
                code="GRAPH_NODE_COUNT_MISMATCH",
                message="causal graph node count does not match the realized plan",
            )
        )
    else:
        for graph_node, step, source_step_index in zip(
            realization.graph.nodes,
            plan.steps,
            realization.source_step_order,
        ):
            if (
                graph_node.sequence != step.sequence
                or graph_node.source_step_index != source_step_index
                or graph_node.technique_id != step.technique_id
                or graph_node.template_id != step.template_id
            ):
                issues.append(
                    PairingIssue(
                        code="GRAPH_NODE_PLAN_MISMATCH",
                        message="causal graph node does not match the realized plan",
                        sequence=step.sequence,
                    )
                )
    expected_edges, causal_issues = _expected_causal_edges(plan)
    issues.extend(causal_issues)
    observed_edges = [
        (edge.fact_id, edge.producer_sequence, edge.consumer_sequence)
        for edge in realization.graph.edges
    ]
    if observed_edges != expected_edges:
        issues.append(
            PairingIssue(
                code="CAUSAL_EDGE_MISMATCH",
                message="causal graph edges do not match an independent reachability replay",
            )
        )
    used_binding_ids, binding_issues = _binding_issues(realization, blueprint, catalog)
    issues.extend(binding_issues)
    return used_binding_ids, issues


def certify_joint_realizations(
    space: RealizationSpaceInput,
    blueprint: SUTBlueprint,
    catalog: BindingCatalog,
) -> JointRealizationCertificate:
    """Certify declared compatibility without making an execution-success claim."""

    _validate_declared_hash(blueprint, "SUT blueprint")
    _validate_declared_hash(catalog, "binding catalog")
    global_issues = _global_issues(space, blueprint, catalog)
    assessments: list[JointRealizationAssessment] = []
    for realization in space.realizations:
        used_binding_ids, issues = _realization_issues(
            realization,
            space,
            blueprint,
            catalog,
            global_issues,
        )
        assessments.append(
            JointRealizationAssessment(
                rank=realization.rank,
                realization_sha256=realization.content_sha256,
                execution_semantic_sha256=realization.plan.execution_semantic_sha256,
                compatible=not issues,
                used_binding_count=len(used_binding_ids),
                issues=tuple(issues),
            )
        )
    compatible = [assessment for assessment in assessments if assessment.compatible]
    result = JointRealizationCertificate(
        campaign_id=space.campaign_id,
        sut_id=catalog.sut_id,
        realization_space_sha256=space.content_sha256,
        sut_blueprint_sha256=blueprint.content_sha256,
        binding_catalog_sha256=catalog.content_sha256,
        enumeration_status=space.enumeration_status,
        compatible_realization_count=len(compatible),
        selected_realization_sha256=(compatible[0].realization_sha256 if compatible else None),
        assessments=tuple(assessments),
    )
    result.finalize_hash()
    return result
