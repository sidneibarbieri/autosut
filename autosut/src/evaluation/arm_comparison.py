"""Fail-closed C0045 planning comparison with bounded execution evidence.

The three arms are resolver outputs.  Only the AutoSUT-witness arm has a
campaign execution record in this artifact.  Keeping those two evidence types
separate prevents a planning ablation from being reported as a three-arm
execution experiment.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from planning.concretized_plan import ConcretizedPlanInput, load_concretized_plan
from planning.procedural_plan import ProceduralPlanInput, load_procedural_plan


FIDELITY_RANK = {"inspired": 0, "adapted": 1, "faithful": 2}


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _semantic_hash(payload: Any) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return _sha256_bytes(encoded)


def _json_object(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"expected one JSON object: {path}")
    return payload


def _validate_internal_hash(path: Path, payload: dict[str, Any]) -> str:
    expected = str(payload.get("content_sha256", ""))
    if not expected:
        raise ValueError(f"missing content_sha256: {path}")
    actual = _semantic_hash(
        {key: value for key, value in payload.items() if key != "content_sha256"}
    )
    if actual != expected:
        raise ValueError(f"internal content hash mismatch: {path}")
    return expected


class InputFileRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: str
    path: str
    sha256: str
    source_path: str | None = None
    internal_content_sha256: str | None = None
    semantic_sha256: str | None = None


class InputManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str
    input_set_id: str
    campaign_id: str
    upstream_project: str
    upstream_git_revision: str
    scope: str
    files: list[InputFileRecord] = Field(min_length=1)
    content_sha256: str


class InputAudit(BaseModel):
    model_config = ConfigDict(extra="forbid")

    input_set_id: str
    manifest_path: str
    manifest_sha256: str
    manifest_content_sha256: str
    upstream_project: str
    upstream_git_revision: str
    verified_file_count: int
    verified_roles: list[str]


@dataclass(frozen=True)
class VerifiedInputSet:
    manifest: InputManifest
    audit: InputAudit
    procedural_plan: ProceduralPlanInput
    raw_plan: ConcretizedPlanInput
    fixed_plan: ConcretizedPlanInput
    autosut_plan: ConcretizedPlanInput
    repetitions: tuple[ConcretizedPlanInput, ConcretizedPlanInput]


class ExecutionAudit(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run_id: str
    execution_timestamp: str
    execution_validity_path: str
    execution_validity_sha256: str
    manifest_path: str
    manifest_sha256: str
    summary_path: str
    summary_sha256: str
    campaign_state_path: str
    campaign_state_sha256: str
    fidelity_report_path: str
    fidelity_report_sha256: str
    evidence_file_sha256: dict[str, str]
    technique_count: int
    evidence_backed_success_count: int
    fidelity_distribution: dict[str, int]
    realization_distribution: dict[str, int]
    fidelity_rubric_mismatch_count: int
    fidelity_overclaim_count: int
    real_cve_attempted: bool
    real_cve_succeeded: bool
    surrogate_succeeded: bool
    contract_valid: bool
    teardown_clean: bool


class ArmMetrics(BaseModel):
    model_config = ConfigDict(extra="forbid")

    arm_id: str
    treatment: str
    campaign_id: str
    technique_count: int
    verified_procedure_count: int
    precondition_resolved_count: int
    executable_step_count: int
    executed_with_evidence_count: int | None
    resolver_output_verified: bool
    execution_attempted: bool
    campaign_completed: bool | None
    unresolved_technique_ids: list[str] = Field(default_factory=list)
    assumption_count: int
    assumption_bearing_step_count: int
    plan_fidelity_ceiling_distribution: dict[str, int] = Field(default_factory=dict)
    execution_fidelity_distribution: dict[str, int] = Field(default_factory=dict)
    realization_distribution: dict[str, int] = Field(default_factory=dict)
    execution_semantic_sha256: str
    evidence_manifest_path: str | None = None
    evidence_manifest_sha256: str | None = None
    interpretation: str


class TreatmentEffect(BaseModel):
    model_config = ConfigDict(extra="forbid")

    comparison: str
    executable_step_delta: int
    verified_procedure_delta: int
    completed_with_evidence_delta: int | None


class ComparisonReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "2"
    generated_at: str
    experimental_unit: str
    comparison_kind: str
    execution_claim_scope: str
    controls: list[str]
    input_audit: InputAudit
    execution_audit: ExecutionAudit
    arms: list[ArmMetrics]
    treatment_effects: list[TreatmentEffect]
    repeated_execution_semantic_hashes: list[str]
    semantically_identical_across_repetitions: bool
    plan_synthesis_gate_passed: bool
    execution_evidence_gate_passed: bool
    three_arm_execution_comparison_supported: bool
    primary_gate_passed: bool
    content_sha256: str = ""

    def finalize_hash(self) -> None:
        payload = self.model_dump(mode="json", exclude={"content_sha256"})
        self.content_sha256 = _semantic_hash(payload)


def _safe_manifest_file(base: Path, relative_path: str) -> Path:
    candidate = (base / relative_path).resolve()
    try:
        candidate.relative_to(base.resolve())
    except ValueError as exc:
        raise ValueError(f"input path escapes manifest directory: {relative_path}") from exc
    if not candidate.is_file():
        raise FileNotFoundError(f"versioned input missing: {candidate}")
    return candidate


def _role_index(
    manifest_path: Path,
    project_root: Path | None = None,
) -> tuple[InputManifest, dict[str, Path], InputAudit]:
    payload = _json_object(manifest_path)
    _validate_internal_hash(manifest_path, payload)
    manifest = InputManifest.model_validate(payload)
    roles: dict[str, Path] = {}
    for record in manifest.files:
        if record.role in roles:
            raise ValueError(f"duplicate input role: {record.role}")
        path = _safe_manifest_file(manifest_path.parent, record.path)
        observed_sha256 = _sha256_bytes(path.read_bytes())
        if observed_sha256 != record.sha256:
            raise ValueError(f"vendored input byte hash mismatch: {path}")
        if record.internal_content_sha256 is not None:
            internal = _validate_internal_hash(path, _json_object(path))
            if internal != record.internal_content_sha256:
                raise ValueError(f"vendored input semantic hash mismatch: {path}")
        if record.semantic_sha256 is not None:
            action_payload = _json_object(path)
            observed_semantic = _semantic_hash(action_payload.get("templates", []))
            if observed_semantic != record.semantic_sha256:
                raise ValueError(f"action catalog semantic hash mismatch: {path}")
        roles[record.role] = path
    display_path = manifest_path.name
    if project_root is not None:
        try:
            display_path = str(manifest_path.relative_to(project_root.resolve()))
        except ValueError as exc:
            raise ValueError("input manifest is outside the artifact root") from exc
    audit = InputAudit(
        input_set_id=manifest.input_set_id,
        manifest_path=display_path,
        manifest_sha256=_sha256_bytes(manifest_path.read_bytes()),
        manifest_content_sha256=manifest.content_sha256,
        upstream_project=manifest.upstream_project,
        upstream_git_revision=manifest.upstream_git_revision,
        verified_file_count=len(roles),
        verified_roles=sorted(roles),
    )
    return manifest, roles, audit


def load_verified_input_set(
    manifest_path: Path,
    *,
    project_root: Path | None = None,
) -> VerifiedInputSet:
    manifest_path = manifest_path.resolve()
    manifest, roles, audit = _role_index(manifest_path, project_root)
    required_roles = {
        "action_catalog",
        "procedural_plan",
        "raw_binding_catalog",
        "raw_resolver_output",
        "fixed_reference_sut",
        "fixed_reference_binding_catalog",
        "fixed_reference_resolver_output",
        "autosut_binding_catalog",
        "autosut_resolver_output",
        "autosut_repetition_1",
        "autosut_repetition_2",
    }
    missing = sorted(required_roles - set(roles))
    if missing:
        raise ValueError("input manifest is missing roles: " + ", ".join(missing))

    procedural = load_procedural_plan(roles["procedural_plan"])
    raw = load_concretized_plan(roles["raw_resolver_output"], require_complete=False)
    fixed = load_concretized_plan(
        roles["fixed_reference_resolver_output"], require_complete=False
    )
    autosut = load_concretized_plan(roles["autosut_resolver_output"])
    repetitions = (
        load_concretized_plan(roles["autosut_repetition_1"]),
        load_concretized_plan(roles["autosut_repetition_2"]),
    )
    plans = (raw, fixed, autosut, *repetitions)
    if procedural.campaign_id != manifest.campaign_id:
        raise ValueError("procedural plan campaign does not match input manifest")
    if any(plan.campaign_id != manifest.campaign_id for plan in plans):
        raise ValueError("resolver output campaign does not match input manifest")
    if any(plan.source_plan_sha256 != procedural.content_sha256 for plan in plans):
        raise ValueError("resolver output is not bound to the vendored procedural plan")

    action_record = next(
        record for record in manifest.files if record.role == "action_catalog"
    )
    if not action_record.semantic_sha256:
        raise ValueError("action catalog lacks a semantic hash")
    if any(plan.action_catalog_sha256 != action_record.semantic_sha256 for plan in plans):
        raise ValueError("resolver output is not bound to the vendored action catalog")

    binding_roles = {
        "raw_resolver_output": (raw, "raw_binding_catalog"),
        "fixed_reference_resolver_output": (
            fixed,
            "fixed_reference_binding_catalog",
        ),
        "autosut_resolver_output": (autosut, "autosut_binding_catalog"),
        "autosut_repetition_1": (repetitions[0], "autosut_binding_catalog"),
        "autosut_repetition_2": (repetitions[1], "autosut_binding_catalog"),
    }
    for _, (plan, binding_role) in binding_roles.items():
        binding_payload = _json_object(roles[binding_role])
        binding_hash = _validate_internal_hash(roles[binding_role], binding_payload)
        if plan.binding_catalog_sha256 != binding_hash:
            raise ValueError(
                f"resolver output is not bound to {binding_role}"
            )
    fixed_descriptor_sha = _sha256_bytes(roles["fixed_reference_sut"].read_bytes())
    fixed_catalog = _json_object(roles["fixed_reference_binding_catalog"])
    if fixed_catalog.get("source_sha256") != fixed_descriptor_sha:
        raise ValueError("fixed-reference catalog is not bound to its SUT descriptor")

    source_techniques = [step.technique_id for step in procedural.steps]
    source_set = set(source_techniques)
    for plan in plans:
        represented = [step.technique_id for step in plan.steps]
        represented.extend(plan.unresolved_technique_ids)
        if len(represented) != len(source_techniques) or set(represented) != source_set:
            raise ValueError("resolver output loses or invents campaign techniques")
    if raw.steps or set(raw.unresolved_technique_ids) != source_set:
        raise ValueError("raw arm must preserve every technique as unresolved")
    if not fixed.steps or not fixed.unresolved_technique_ids:
        raise ValueError("fixed reference arm must be a genuine partial resolution")
    if autosut.unresolved_technique_ids or not autosut.planning_certificate.valid:
        raise ValueError("AutoSUT witness arm is not a complete certified plan")
    if any(plan.llm_call_sha256 is not None for plan in plans):
        raise ValueError("C0045 deterministic gate cannot include online LLM output")
    if any(step.assumption_count < 0 for plan in plans for step in plan.steps):
        raise ValueError("negative assumption count in resolver output")
    if any(
        repetition.content_sha256 != autosut.content_sha256
        for repetition in repetitions
    ):
        raise ValueError("repeated deterministic resolver outputs differ")
    return VerifiedInputSet(
        manifest=manifest,
        audit=audit,
        procedural_plan=procedural,
        raw_plan=raw,
        fixed_plan=fixed,
        autosut_plan=autosut,
        repetitions=repetitions,
    )


def _execution_row(path: Path, campaign_id: str) -> tuple[dict[str, Any], str]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError("execution-validity input must be a JSON array")
    rows = [row for row in payload if row.get("campaign_id") == campaign_id]
    if len(rows) != 1:
        raise ValueError(
            f"expected exactly one execution-validity row for {campaign_id}"
        )
    return rows[0], _sha256_bytes(path.read_bytes())


def _resolve_evidence_path(project_root: Path, value: str) -> Path:
    relative = Path(value)
    if relative.is_absolute():
        raise ValueError("execution evidence path must be repository-relative")
    resolved = (project_root / relative).resolve()
    try:
        resolved.relative_to(project_root.resolve())
    except ValueError as exc:
        raise ValueError("execution evidence path escapes artifact root") from exc
    if not resolved.is_file():
        raise FileNotFoundError(f"execution evidence manifest missing: {resolved}")
    return resolved


def audit_execution(
    *,
    execution_validity_path: Path,
    project_root: Path,
    local_campaign_id: str,
    source_campaign_id: str,
    plan: ConcretizedPlanInput,
) -> ExecutionAudit:
    execution_validity_path = execution_validity_path.resolve()
    try:
        validity_display_path = str(
            execution_validity_path.relative_to(project_root.resolve())
        )
    except ValueError as exc:
        raise ValueError("execution-validity table is outside the artifact root") from exc
    row, validity_sha256 = _execution_row(
        execution_validity_path, local_campaign_id
    )
    if row.get("source_campaign_id") != source_campaign_id:
        raise ValueError("execution row is not bound to the source campaign")
    manifest_path = _resolve_evidence_path(project_root, str(row["evidence_path"]))
    manifest = _json_object(manifest_path)
    if manifest.get("campaign_id") != local_campaign_id:
        raise ValueError("execution manifest campaign mismatch")
    if manifest.get("run_id") != row.get("run_id"):
        raise ValueError("execution-validity row points to a different run")
    support_paths: dict[str, Path] = {}
    for key in ("manifest_path", "summary_path", "campaign_state_path"):
        value = str(manifest.get(key, ""))
        if not value or Path(value).is_absolute():
            raise ValueError(f"execution manifest has non-portable {key}")
        support_paths[key] = _resolve_evidence_path(manifest_path.parent, value)
    if support_paths["manifest_path"] != manifest_path:
        raise ValueError("execution manifest self-path does not resolve to itself")
    summary = _json_object(support_paths["summary_path"])
    campaign_state = _json_object(support_paths["campaign_state_path"])
    techniques = manifest.get("techniques", [])
    if not isinstance(techniques, list) or not techniques:
        raise ValueError("execution manifest has no techniques")
    plan_ids = [step.technique_id for step in plan.steps]
    observed_ids = [str(item.get("technique_id", "")) for item in techniques]
    if observed_ids != plan_ids:
        raise ValueError("execution sequence differs from the verified plan")
    if any(item.get("status") != "success" for item in techniques):
        raise ValueError("execution manifest contains unsuccessful techniques")
    if int(row.get("total_steps", -1)) != len(techniques):
        raise ValueError("execution-validity total does not match manifest")
    if int(row.get("evidence_backed_success", -1)) != len(techniques):
        raise ValueError("not every successful technique is evidence-backed")
    if int(row.get("marker_only", -1)) != 0:
        raise ValueError("C0045 bounded gate rejects marker-only successes")
    expected_summary = {
        "campaign_id": local_campaign_id,
        "total_techniques": len(techniques),
        "successful": len(techniques),
        "evidence_backed_successful": len(techniques),
        "marker_only_successful": 0,
    }
    for key, expected_value in expected_summary.items():
        if summary.get(key) != expected_value:
            raise ValueError(f"execution summary mismatch for {key}")
    state_transitions = campaign_state.get("transitions", [])
    if [item.get("technique_id") for item in state_transitions] != observed_ids:
        raise ValueError("campaign-state sequence differs from the execution manifest")
    if any(item.get("status") != "success" for item in state_transitions):
        raise ValueError("campaign-state ledger contains an unsuccessful transition")
    if row.get("contract_valid") is not True:
        raise ValueError("C0045 campaign contract is not valid")
    if row.get("teardown_clean") is not True or manifest.get("teardown_clean") is not True:
        raise ValueError("C0045 execution did not record clean teardown")

    plan_by_id = {step.technique_id: step for step in plan.steps}
    evidence_hashes: dict[str, str] = {}
    fidelity_distribution: Counter[str] = Counter()
    realization_distribution: Counter[str] = Counter()
    for outcome in techniques:
        technique_id = str(outcome["technique_id"])
        declared = str(outcome.get("declared_fidelity", ""))
        executed = str(outcome.get("executed_fidelity", ""))
        if declared not in FIDELITY_RANK or executed not in FIDELITY_RANK:
            raise ValueError(f"unknown fidelity tier for {technique_id}")
        if declared != executed:
            raise ValueError(f"declared/executed fidelity mismatch for {technique_id}")
        ceiling = plan_by_id[technique_id].fidelity_ceiling
        if ceiling not in FIDELITY_RANK or FIDELITY_RANK[executed] > FIDELITY_RANK[ceiling]:
            raise ValueError(f"execution exceeds verified fidelity ceiling: {technique_id}")
        evidence_files = outcome.get("evidence_files", [])
        if not evidence_files:
            raise ValueError(f"successful technique lacks evidence files: {technique_id}")
        for relative_value in evidence_files:
            evidence_path = _resolve_evidence_path(
                manifest_path.parent, str(relative_value)
            )
            relative_key = str(evidence_path.relative_to(manifest_path.parent))
            evidence_hashes[relative_key] = _sha256_bytes(evidence_path.read_bytes())
        fidelity_distribution[executed] += 1
        realization_distribution[str(outcome.get("realization", "unknown"))] += 1

    injections = manifest.get("cves_injected", [])
    real_attempted = any(item.get("realization") == "real_cve" for item in injections)
    real_succeeded = any(
        item.get("realization") == "real_cve" and item.get("success") is True
        for item in injections
    )
    surrogate_succeeded = any(
        item.get("realization") == "surrogate" and item.get("success") is True
        for item in injections
    )
    if not real_attempted or real_succeeded or not surrogate_succeeded:
        raise ValueError(
            "C0045 evidence must record failed real-CVE preflight and successful surrogate fallback"
        )
    if set(realization_distribution) != {"surrogate"}:
        raise ValueError("C0045 technique evidence is not uniformly surrogate-scoped")

    fidelity_path = manifest_path.parent / "fidelity_report.json"
    if not fidelity_path.is_file():
        raise FileNotFoundError("C0045 fidelity report missing")
    fidelity = _json_object(fidelity_path)
    rubric_rows = fidelity.get("techniques", [])
    if len(rubric_rows) != len(techniques):
        raise ValueError("fidelity rubric does not cover every technique")
    rubric_by_id = {str(item.get("technique_id")): item for item in rubric_rows}
    overclaims = 0
    mismatches = 0
    for outcome in techniques:
        technique_id = str(outcome["technique_id"])
        rubric = rubric_by_id.get(technique_id)
        if rubric is None:
            raise ValueError(f"fidelity rubric missing {technique_id}")
        computed = str(rubric.get("computed_fidelity", ""))
        executed = str(outcome["executed_fidelity"])
        if computed not in FIDELITY_RANK:
            raise ValueError(f"unknown computed fidelity for {technique_id}")
        if computed != executed:
            mismatches += 1
        if FIDELITY_RANK[executed] > FIDELITY_RANK[computed]:
            overclaims += 1
    if overclaims:
        raise ValueError("execution fidelity exceeds the independently computed rubric")

    return ExecutionAudit(
        run_id=str(manifest["run_id"]),
        execution_timestamp=str(manifest["timestamp"]),
        execution_validity_path=validity_display_path,
        execution_validity_sha256=validity_sha256,
        manifest_path=str(manifest_path.relative_to(project_root)),
        manifest_sha256=_sha256_bytes(manifest_path.read_bytes()),
        summary_path=str(support_paths["summary_path"].relative_to(project_root)),
        summary_sha256=_sha256_bytes(support_paths["summary_path"].read_bytes()),
        campaign_state_path=str(
            support_paths["campaign_state_path"].relative_to(project_root)
        ),
        campaign_state_sha256=_sha256_bytes(
            support_paths["campaign_state_path"].read_bytes()
        ),
        fidelity_report_path=str(fidelity_path.relative_to(project_root)),
        fidelity_report_sha256=_sha256_bytes(fidelity_path.read_bytes()),
        evidence_file_sha256=dict(sorted(evidence_hashes.items())),
        technique_count=len(techniques),
        evidence_backed_success_count=len(techniques),
        fidelity_distribution=dict(sorted(fidelity_distribution.items())),
        realization_distribution=dict(sorted(realization_distribution.items())),
        fidelity_rubric_mismatch_count=mismatches,
        fidelity_overclaim_count=overclaims,
        real_cve_attempted=real_attempted,
        real_cve_succeeded=real_succeeded,
        surrogate_succeeded=surrogate_succeeded,
        contract_valid=True,
        teardown_clean=True,
    )


def _plan_metrics(
    plan: ConcretizedPlanInput,
    *,
    arm_id: str,
    treatment: str,
    technique_count: int,
    interpretation: str,
    execution: ExecutionAudit | None = None,
) -> ArmMetrics:
    execution_attempted = execution is not None
    completed = (
        execution.evidence_backed_success_count == technique_count
        if execution is not None
        else None
    )
    return ArmMetrics(
        arm_id=arm_id,
        treatment=treatment,
        campaign_id=plan.campaign_id,
        technique_count=technique_count,
        verified_procedure_count=len(plan.steps),
        precondition_resolved_count=len(plan.planning_certificate.transitions),
        executable_step_count=len(plan.steps),
        executed_with_evidence_count=(
            execution.evidence_backed_success_count if execution is not None else None
        ),
        resolver_output_verified=True,
        execution_attempted=execution_attempted,
        campaign_completed=completed,
        unresolved_technique_ids=plan.unresolved_technique_ids,
        assumption_count=sum(step.assumption_count for step in plan.steps),
        assumption_bearing_step_count=sum(
            1 for step in plan.steps if step.assumption_count > 0
        ),
        plan_fidelity_ceiling_distribution=dict(
            sorted(Counter(step.fidelity_ceiling for step in plan.steps).items())
        ),
        execution_fidelity_distribution=(
            execution.fidelity_distribution if execution is not None else {}
        ),
        realization_distribution=(
            execution.realization_distribution if execution is not None else {}
        ),
        execution_semantic_sha256=plan.execution_semantic_sha256,
        evidence_manifest_path=(execution.manifest_path if execution is not None else None),
        evidence_manifest_sha256=(
            execution.manifest_sha256 if execution is not None else None
        ),
        interpretation=interpretation,
    )


def _effect(first: ArmMetrics, second: ArmMetrics) -> TreatmentEffect:
    completed_delta = None
    if (
        first.executed_with_evidence_count is not None
        and second.executed_with_evidence_count is not None
    ):
        completed_delta = (
            second.executed_with_evidence_count - first.executed_with_evidence_count
        )
    return TreatmentEffect(
        comparison=f"{first.arm_id}_to_{second.arm_id}",
        executable_step_delta=second.executable_step_count - first.executable_step_count,
        verified_procedure_delta=(
            second.verified_procedure_count - first.verified_procedure_count
        ),
        completed_with_evidence_delta=completed_delta,
    )


def build_report(
    *,
    input_manifest_path: Path,
    execution_validity_path: Path,
    local_campaign_id: str,
    project_root: Path,
) -> ComparisonReport:
    inputs = load_verified_input_set(
        input_manifest_path,
        project_root=project_root,
    )
    execution = audit_execution(
        execution_validity_path=execution_validity_path,
        project_root=project_root.resolve(),
        local_campaign_id=local_campaign_id,
        source_campaign_id=inputs.manifest.campaign_id,
        plan=inputs.autosut_plan,
    )
    technique_count = len(inputs.procedural_plan.steps)
    raw = _plan_metrics(
        inputs.raw_plan,
        arm_id="A",
        treatment="raw_stix_plan_with_empty_binding_catalog",
        technique_count=technique_count,
        interpretation=(
            "Verified deterministic resolver output: all source techniques remain "
            "unresolved without environment bindings. This arm was not executed."
        ),
    )
    fixed = _plan_metrics(
        inputs.fixed_plan,
        arm_id="B",
        treatment="sticks_plan_on_fixed_non_campaign_reference_sut",
        technique_count=technique_count,
        interpretation=(
            "Verified deterministic resolver output: the fixed reference admits "
            "only steps supported by its declared initial facts. This arm was not executed."
        ),
    )
    enriched = _plan_metrics(
        inputs.autosut_plan,
        arm_id="C",
        treatment="sticks_plan_with_autosut_campaign_conditioned_witness",
        technique_count=technique_count,
        execution=execution,
        interpretation=(
            "Verified deterministic plan plus a separate surrogate-backed execution "
            "record. It is not evidence of real-Ray exploitation or historical replay."
        ),
    )
    repeated_hashes = [
        plan.execution_semantic_sha256 for plan in inputs.repetitions
    ]
    identical = (
        len(repeated_hashes) == 2
        and len(set(repeated_hashes)) == 1
        and repeated_hashes[0] == inputs.autosut_plan.execution_semantic_sha256
    )
    planning_gate = bool(
        raw.executable_step_count == 0
        and 0 < fixed.executable_step_count < technique_count
        and enriched.executable_step_count == technique_count
        and not enriched.unresolved_technique_ids
        and identical
    )
    execution_gate = bool(
        enriched.campaign_completed
        and execution.evidence_backed_success_count == technique_count
        and execution.fidelity_overclaim_count == 0
        and execution.surrogate_succeeded
        and not execution.real_cve_succeeded
        and execution.contract_valid
        and execution.teardown_clean
    )
    report = ComparisonReport(
        generated_at=execution.execution_timestamp,
        experimental_unit=(
            "one C0045 technique sequence under a frozen action catalog, resolver "
            "policy, and campaign-conditioned surrogate laboratory"
        ),
        comparison_kind="deterministic_plan_synthesis_ablation_with_arm_c_execution",
        execution_claim_scope=(
            "Arms A and B are verified resolver outputs only. Arm C alone has "
            "step-level execution evidence; therefore this is not a three-arm "
            "execution comparison."
        ),
        controls=[
            "same vendored procedural plan",
            "same vendored action-template catalog",
            "same finite-domain resolver policy",
            "same campaign technique sequence",
            "no online LLM proposals",
        ],
        input_audit=inputs.audit,
        execution_audit=execution,
        arms=[raw, fixed, enriched],
        treatment_effects=[_effect(raw, fixed), _effect(fixed, enriched)],
        repeated_execution_semantic_hashes=repeated_hashes,
        semantically_identical_across_repetitions=identical,
        plan_synthesis_gate_passed=planning_gate,
        execution_evidence_gate_passed=execution_gate,
        three_arm_execution_comparison_supported=False,
        primary_gate_passed=planning_gate and execution_gate,
    )
    report.finalize_hash()
    return report


def load_comparison_report(path: Path) -> ComparisonReport:
    payload = _json_object(path)
    expected = str(payload.get("content_sha256", ""))
    actual = _semantic_hash(
        {key: value for key, value in payload.items() if key != "content_sha256"}
    )
    if not expected or actual != expected:
        raise ValueError(f"comparison report hash mismatch: {path}")
    return ComparisonReport.model_validate(payload)
