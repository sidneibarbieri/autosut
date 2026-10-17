"""Prepare paired planning inputs through the published STICKS compiler."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from .binding_catalog import BindingCatalog, build_binding_catalog
from .concretized_plan import load_concretized_plan
from .executable_contract import compile_verified_contract
from .execution_admission import has_reviewed_sequence, validate_template_adapters
from .joint_realization import (
    JointRealizationCertificate,
    certify_joint_realizations,
    load_realization_space,
)
from .procedural_plan import load_procedural_plan
from .sut_blueprint import SUTBlueprint, synthesize_blueprint
from .sut_constraints import SUTConstraintSet, resolve_sut_constraints


class PairPreparation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    campaign_id: str
    source_campaign_id: str | None = None
    source_plan_sha256: str | None = None
    status: Literal["blocked", "prepared"] = "blocked"
    reasons: tuple[str, ...] = ()
    source_steps: int = 0
    planned_steps: int = 0
    unresolved_technique_ids: tuple[str, ...] = ()
    unsupported_procedure_technique_ids: tuple[str, ...] = ()
    contract_sha256: str | None = None
    realization_space_sha256: str | None = None
    joint_certificate_sha256: str | None = None
    compatible_realization_count: int = 0
    selected_realization_sha256: str | None = None
    enumeration_status: str | None = None
    files: dict[str, str] = Field(default_factory=dict)
    execution_status: Literal["not_run"] = "not_run"


class ProcedurePlatformRequirement(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    technique_id: str = Field(min_length=1)
    platform: str = Field(min_length=1)


def unsupported_procedure_platforms(
    spec: dict[str, Any], materializable_platforms: set[str]
) -> tuple[str, ...]:
    """Check declared procedure platforms independently of CTI alternatives."""
    available = {platform.casefold() for platform in materializable_platforms}
    unsupported = set()
    for technique in spec.get("techniques", []):
        if "platform" not in technique:
            continue
        requirement = ProcedurePlatformRequirement(
            technique_id=technique["technique_id"], platform=technique["platform"]
        )
        platform = requirement.platform.casefold()
        if platform != "any" and platform not in available:
            unsupported.add(requirement.technique_id)
    return tuple(sorted(unsupported))


def _write_model(path: Path, model: BaseModel) -> None:
    with path.open("x", encoding="utf-8") as output:
        output.write(model.model_dump_json(indent=2) + "\n")


def _run_sticks_compiler(
    command: list[str],
    sticks_root: Path,
    label: str,
) -> subprocess.CompletedProcess[str]:
    """Run one STICKS compiler and preserve its diagnostic output on failure."""
    completed = subprocess.run(
        command,
        cwd=sticks_root,
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "no compiler output"
        raise RuntimeError(f"{label}: {detail}")
    return completed


def prepare_campaign_pair(
    *,
    campaign_path: Path,
    plan_path: Path,
    sticks_root: Path,
    output_dir: Path,
    python_executable: str,
    source_campaign_id: str | None = None,
) -> PairPreparation:
    """Produce a blueprint, bindings and causal contract without provisioning."""
    spec = json.loads(campaign_path.read_text(encoding="utf-8"))
    plan = load_procedural_plan(plan_path)
    declared_source = spec.get("source_campaign_id")
    if declared_source and source_campaign_id and declared_source != source_campaign_id:
        raise ValueError("declared and inventory CTI identities disagree")
    effective_source = declared_source or source_campaign_id
    if effective_source != plan.campaign_id:
        raise ValueError("campaign specification and CTI plan disagree")
    output_dir.mkdir(parents=True, exist_ok=False)
    (output_dir / "campaign-source.json").write_bytes(campaign_path.read_bytes())
    normalized_spec = dict(spec)
    normalized_spec["source_campaign_id"] = effective_source
    (output_dir / "campaign.json").write_text(
        json.dumps(normalized_spec, indent=2) + "\n", encoding="utf-8"
    )
    (output_dir / "procedural-plan.json").write_bytes(plan_path.read_bytes())
    materializable_platforms = {"Linux"}
    constraints = resolve_sut_constraints(plan, materializable_platforms=materializable_platforms)
    unsupported_procedures = unsupported_procedure_platforms(spec, materializable_platforms)
    _write_model(output_dir / "sut-constraints.json", constraints)
    base = {
        "campaign_id": spec["campaign_id"],
        "source_campaign_id": plan.campaign_id,
        "source_plan_sha256": plan.content_sha256,
        "source_steps": len(plan.steps),
    }
    reasons = []
    if not constraints.platform_resolution.complete:
        reasons.append("unsupported_platform_requirements")
    if unsupported_procedures:
        reasons.append("unsupported_procedure_platform_requirements")
    if not spec.get("execution_contract"):
        reasons.append("missing_execution_contract")
    if reasons:
        result = PairPreparation(
            **base,
            reasons=tuple(reasons),
            unresolved_technique_ids=tuple(constraints.platform_resolution.uncovered_technique_ids),
            unsupported_procedure_technique_ids=unsupported_procedures,
        )
    else:
        result = _compile_pair(
            normalized_spec,
            base,
            constraints,
            sticks_root,
            output_dir,
            python_executable,
        )
    files = {
        path.relative_to(output_dir).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(output_dir.rglob("*"))
        if path.is_file()
    }
    result = result.model_copy(update={"files": files})
    _write_model(output_dir / "pair.json", result)
    return result


def _declared_services(spec: dict[str, Any]) -> set[str]:
    services: set[str] = set()
    for vulnerability in spec.get("vulnerabilities", []):
        declared = vulnerability.get("config", {}).get("services", [])
        if not isinstance(declared, list) or any(not isinstance(name, str) for name in declared):
            raise ValueError("vulnerability services must be a list of names")
        services.update(declared)
    return services


def _compile_pair(
    spec: dict[str, Any],
    base: dict[str, Any],
    constraints: SUTConstraintSet,
    sticks_root: Path,
    output_dir: Path,
    python_executable: str,
) -> PairPreparation:
    blueprint = synthesize_blueprint(constraints, services=_declared_services(spec))
    _write_model(output_dir / "sut-blueprint.json", blueprint)
    catalog = build_binding_catalog(blueprint, output_dir / "campaign.json")
    _write_model(output_dir / "binding-catalog.json", catalog)
    template_path = sticks_root / "data/concretization/action_templates.json"
    (output_dir / "action_templates.json").write_bytes(template_path.read_bytes())
    command = [
        python_executable,
        str(sticks_root / "scripts/concretize_procedural_plan.py"),
        "--plan",
        str(output_dir / "procedural-plan.json"),
        "--bindings",
        str(output_dir / "binding-catalog.json"),
        "--templates",
        str(output_dir / "action_templates.json"),
        "--output",
        str(output_dir / "concretized-plan.json"),
        "--allow-unresolved",
    ]
    completed = _run_sticks_compiler(
        command,
        sticks_root,
        f"STICKS concretization failed for {spec['campaign_id']}",
    )
    # Paths in compiler output depend on the local checkout and are not evidence.
    (output_dir / "compiler-receipt.json").write_text(
        json.dumps(
            {
                "entrypoint": "scripts/concretize_procedural_plan.py",
                "entrypoint_sha256": hashlib.sha256(Path(command[1]).read_bytes()).hexdigest(),
                "returncode": completed.returncode,
                "llm_calls": 0,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    concrete = load_concretized_plan(output_dir / "concretized-plan.json", require_complete=False)
    if concrete.unresolved_technique_ids or not concrete.planning_certificate.valid:
        return PairPreparation(
            **base,
            planned_steps=len(concrete.steps),
            reasons=("unresolved_procedures_or_goals",),
            unresolved_technique_ids=tuple(concrete.unresolved_technique_ids),
        )
    joint_certificate = _enumerate_and_certify_realizations(
        sticks_root=sticks_root,
        output_dir=output_dir,
        python_executable=python_executable,
        blueprint=blueprint,
        catalog=catalog,
    )
    if not joint_certificate.compatible_realization_count:
        return PairPreparation(
            **base,
            planned_steps=len(concrete.steps),
            reasons=("no_jointly_compatible_realization",),
            realization_space_sha256=joint_certificate.realization_space_sha256,
            joint_certificate_sha256=joint_certificate.content_sha256,
            compatible_realization_count=joint_certificate.compatible_realization_count,
            selected_realization_sha256=joint_certificate.selected_realization_sha256,
            enumeration_status=joint_certificate.enumeration_status,
        )
    declared = [step["technique_id"] for step in spec["execution_contract"]["techniques"]]
    if declared != [step.technique_id for step in concrete.steps]:
        return PairPreparation(
            **base,
            planned_steps=len(concrete.steps),
            reasons=("campaign_sequence_mismatch",),
            realization_space_sha256=joint_certificate.realization_space_sha256,
            joint_certificate_sha256=joint_certificate.content_sha256,
            compatible_realization_count=joint_certificate.compatible_realization_count,
            selected_realization_sha256=joint_certificate.selected_realization_sha256,
            enumeration_status=joint_certificate.enumeration_status,
        )
    contract = compile_verified_contract(concrete, output_dir / "campaign.json")
    _write_model(output_dir / "executable-contract.json", contract)
    if not has_reviewed_sequence(contract):
        return PairPreparation(
            **base,
            planned_steps=len(concrete.steps),
            reasons=("missing_reviewed_execution_adapter",),
            contract_sha256=contract.content_sha256,
            realization_space_sha256=joint_certificate.realization_space_sha256,
            joint_certificate_sha256=joint_certificate.content_sha256,
            compatible_realization_count=joint_certificate.compatible_realization_count,
            selected_realization_sha256=joint_certificate.selected_realization_sha256,
            enumeration_status=joint_certificate.enumeration_status,
        )
    validate_template_adapters(contract)
    return PairPreparation(
        **base,
        status="prepared",
        planned_steps=len(concrete.steps),
        contract_sha256=contract.content_sha256,
        realization_space_sha256=joint_certificate.realization_space_sha256,
        joint_certificate_sha256=joint_certificate.content_sha256,
        compatible_realization_count=joint_certificate.compatible_realization_count,
        selected_realization_sha256=joint_certificate.selected_realization_sha256,
        enumeration_status=joint_certificate.enumeration_status,
    )


def _enumerate_and_certify_realizations(
    *,
    sticks_root: Path,
    output_dir: Path,
    python_executable: str,
    blueprint: SUTBlueprint,
    catalog: BindingCatalog,
) -> JointRealizationCertificate:
    entrypoint = sticks_root / "scripts/enumerate_realization_space.py"
    realization_path = output_dir / "realization-space.json"
    command = [
        python_executable,
        str(entrypoint),
        "--plan",
        str(output_dir / "procedural-plan.json"),
        "--bindings",
        str(output_dir / "binding-catalog.json"),
        "--templates",
        str(output_dir / "action_templates.json"),
        "--output",
        str(realization_path),
        "--maximum-realizations",
        "64",
        "--maximum-search-states",
        "10000",
        "--require-realization",
    ]
    completed = _run_sticks_compiler(
        command,
        sticks_root,
        "STICKS realization enumeration failed",
    )
    space = load_realization_space(realization_path)
    certificate = certify_joint_realizations(space, blueprint, catalog)
    _write_model(output_dir / "joint-realization-certificate.json", certificate)
    (output_dir / "realization-compiler-receipt.json").write_text(
        json.dumps(
            {
                "entrypoint": "scripts/enumerate_realization_space.py",
                "entrypoint_sha256": hashlib.sha256(entrypoint.read_bytes()).hexdigest(),
                "returncode": completed.returncode,
                "llm_calls": 0,
                "maximum_realizations": 64,
                "maximum_search_states": 10000,
                "realization_space_sha256": space.content_sha256,
                "joint_certificate_sha256": certificate.content_sha256,
                "operational_status": certificate.operational_status,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return certificate
