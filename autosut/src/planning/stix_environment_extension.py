"""Attach auditable SUT semantics to a STICKS-enriched STIX campaign."""

from __future__ import annotations

import copy
import hashlib
import json
import re
from enum import Enum
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from .binding_catalog import BindingCatalog
from .concretized_plan import ConcretizedPlanInput
from .procedural_plan import ProceduralPlanInput
from .sut_blueprint import SUTBlueprint
from .sut_constraints import SUTConstraintSet


PROCEDURE_PROPERTY = "x_sticks_procedure"
ENVIRONMENT_PROPERTY = "x_autosut_environment"
CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ResolutionStatus(str, Enum):
    resolved = "resolved"
    unresolved = "unresolved"
    not_applicable = "not_applicable"


class FieldProvenance(StrictModel):
    source_kind: str
    source_ids: list[str] = Field(min_length=1)
    source_sha256: str
    method: str


class ResolvedField(StrictModel):
    status: ResolutionStatus
    values: list[str] = Field(default_factory=list)
    provenance: FieldProvenance | None = None

    @model_validator(mode="after")
    def validate_resolution(self) -> "ResolvedField":
        if self.status == ResolutionStatus.resolved:
            if not self.values or self.provenance is None:
                raise ValueError("resolved fields require values and provenance")
        elif self.values:
            raise ValueError("non-resolved fields cannot carry values")
        return self


class SoftwareBinding(StrictModel):
    cve_id: str
    product: str
    package_name: ResolvedField
    candidate_versions: ResolvedField
    version_range: ResolvedField
    cpe23_uri: ResolvedField
    install_channel: ResolvedField


class RequirementBinding(StrictModel):
    requirement_id: str
    kind: str
    acceptable_values: list[str] = Field(min_length=1)
    source: str


class EnvironmentSemantics(StrictModel):
    schema_version: str = "1"
    technique_id: str
    selected_platform: ResolvedField
    backend_cue: ResolvedField
    requirements: list[RequirementBinding] = Field(default_factory=list)
    parameter_bindings: dict[str, str] = Field(default_factory=dict)
    software: list[SoftwareBinding] = Field(default_factory=list)
    unresolved_applicable_fields: list[str] = Field(default_factory=list)
    provenance: FieldProvenance
    content_sha256: str = ""

    def finalize_hash(self) -> None:
        payload = self.model_dump(mode="json", exclude={"content_sha256"})
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        self.content_sha256 = hashlib.sha256(encoded).hexdigest()

    def validate_hash(self) -> bool:
        expected = self.content_sha256
        self.finalize_hash()
        return self.content_sha256 == expected


def _provenance(
    *,
    source_kind: str,
    source_ids: list[str],
    source_sha256: str,
    method: str,
) -> FieldProvenance:
    return FieldProvenance(
        source_kind=source_kind,
        source_ids=source_ids,
        source_sha256=source_sha256,
        method=method,
    )


def _resolved(
    values: list[str],
    *,
    source_kind: str,
    source_ids: list[str],
    source_sha256: str,
    method: str,
) -> ResolvedField:
    unique_values = sorted(set(str(value) for value in values if str(value)))
    if not unique_values:
        return ResolvedField(status=ResolutionStatus.unresolved)
    return ResolvedField(
        status=ResolutionStatus.resolved,
        values=unique_values,
        provenance=_provenance(
            source_kind=source_kind,
            source_ids=source_ids,
            source_sha256=source_sha256,
            method=method,
        ),
    )


def _unresolved() -> ResolvedField:
    return ResolvedField(status=ResolutionStatus.unresolved)


def _not_applicable() -> ResolvedField:
    return ResolvedField(status=ResolutionStatus.not_applicable)


def _load_cve_rules(path: Path) -> dict[str, dict[str, Any]]:
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    rules = payload.get("rules", []) if isinstance(payload, dict) else []
    return {
        str(rule["cve"]).upper(): rule
        for rule in rules
        if isinstance(rule, dict) and rule.get("cve")
    }


def _software_binding(
    cve_id: str,
    rule: dict[str, Any] | None,
    *,
    rule_sha256: str,
) -> SoftwareBinding:
    if rule is None:
        return SoftwareBinding(
            cve_id=cve_id,
            product="",
            package_name=_unresolved(),
            candidate_versions=_unresolved(),
            version_range=_unresolved(),
            cpe23_uri=_unresolved(),
            install_channel=_unresolved(),
        )
    source_ids = [cve_id, *[str(item) for item in rule.get("evidence_sources", [])]]
    common = {
        "source_kind": "curated_cve_resolution_rule",
        "source_ids": source_ids,
        "source_sha256": rule_sha256,
        "method": "exact CVE identifier lookup in a frozen rule table",
    }
    return SoftwareBinding(
        cve_id=cve_id,
        product=str(rule.get("product", "")),
        package_name=_resolved([str(rule.get("package_name", ""))], **common),
        candidate_versions=_resolved(
            [str(item) for item in rule.get("candidate_versions", [])],
            **common,
        ),
        version_range=_unresolved(),
        cpe23_uri=_unresolved(),
        install_channel=_resolved([str(rule.get("install_channel", ""))], **common),
    )


def attach_environment_semantics(
    *,
    sticks_bundle: dict[str, Any],
    procedural_plan: ProceduralPlanInput,
    concretized_plan: ConcretizedPlanInput,
    constraints: SUTConstraintSet,
    blueprint: SUTBlueprint,
    binding_catalog: BindingCatalog,
    cve_rules_path: Path,
) -> dict[str, Any]:
    if procedural_plan.content_sha256 != concretized_plan.source_plan_sha256:
        raise ValueError("concretized plan is not bound to the procedural plan")
    if constraints.source_plan_sha256 != procedural_plan.content_sha256:
        raise ValueError("constraint set is not bound to the procedural plan")
    if blueprint.source_constraint_sha256 != constraints.content_sha256:
        raise ValueError("blueprint is not bound to the constraint set")
    if concretized_plan.binding_catalog_sha256 != binding_catalog.content_sha256:
        raise ValueError("concretized plan is not bound to the binding catalog")

    cve_rules = _load_cve_rules(cve_rules_path)
    rule_sha256 = hashlib.sha256(cve_rules_path.read_bytes()).hexdigest()
    constraint_by_technique: dict[str, list[RequirementBinding]] = {}
    for requirement in constraints.requirements:
        for technique_id in requirement.technique_ids:
            constraint_by_technique.setdefault(technique_id, []).append(
                RequirementBinding(
                    requirement_id=requirement.requirement_id,
                    kind=requirement.kind,
                    acceptable_values=list(requirement.acceptable_values),
                    source=requirement.source.value,
                )
            )
    concrete_steps = {
        step.technique_id: step for step in concretized_plan.steps
    }
    plan_steps = {step.technique_id: step for step in procedural_plan.steps}
    known_binding_ids = {binding.binding_id for binding in binding_catalog.bindings}
    host = blueprint.hosts[0] if blueprint.hosts else None
    output = copy.deepcopy(sticks_bundle)
    enriched_count = 0

    for relationship in output.get("objects", []):
        procedure = relationship.get(PROCEDURE_PROPERTY)
        if not isinstance(procedure, dict):
            continue
        technique_id = str(procedure.get("technique_id", ""))
        plan_step = plan_steps.get(technique_id)
        concrete_step = concrete_steps.get(technique_id)
        if plan_step is None or concrete_step is None:
            raise ValueError(f"missing bound step for {technique_id}")
        unknown_bindings = sorted(
            set(concrete_step.bindings.values()) - known_binding_ids
        )
        if unknown_bindings:
            raise ValueError(
                f"{technique_id} refers to unknown bindings: "
                + ", ".join(unknown_bindings)
            )

        is_attacker_step = plan_step.execution_domain == "attacker"
        platform = (
            _not_applicable()
            if is_attacker_step
            else _resolved(
                [host.platform] if host else [],
                source_kind="autosut_blueprint",
                source_ids=[blueprint.campaign_id],
                source_sha256=blueprint.content_sha256,
                method="selected materializable platform from the constraint intersection",
            )
        )
        backend = (
            _not_applicable()
            if is_attacker_step
            else _resolved(
                [host.recipe.backend] if host else [],
                source_kind="autosut_blueprint",
                source_ids=[blueprint.campaign_id],
                source_sha256=blueprint.content_sha256,
                method="backend selected by the frozen blueprint recipe",
            )
        )
        description = str(relationship.get("description", ""))
        cve_ids = sorted({item.upper() for item in CVE_PATTERN.findall(description)})
        software = [
            _software_binding(cve_id, cve_rules.get(cve_id), rule_sha256=rule_sha256)
            for cve_id in cve_ids
        ]
        unresolved_fields = sorted(
            {
                field_name
                for item in software
                for field_name, field_value in (
                    ("package_name", item.package_name),
                    ("candidate_versions", item.candidate_versions),
                    ("version_range", item.version_range),
                    ("cpe23_uri", item.cpe23_uri),
                    ("install_channel", item.install_channel),
                )
                if field_value.status == ResolutionStatus.unresolved
            }
        )
        extension = EnvironmentSemantics(
            technique_id=technique_id,
            selected_platform=platform,
            backend_cue=backend,
            requirements=sorted(
                constraint_by_technique.get(technique_id, []),
                key=lambda item: item.requirement_id,
            ),
            parameter_bindings=dict(concrete_step.bindings),
            software=software,
            unresolved_applicable_fields=unresolved_fields,
            provenance=_provenance(
                source_kind="autosut_verified_contract",
                source_ids=[
                    constraints.campaign_id,
                    blueprint.campaign_id,
                    binding_catalog.sut_id,
                ],
                source_sha256=concretized_plan.content_sha256,
                method="typed constraints, blueprint synthesis, and binding verification",
            ),
        )
        extension.finalize_hash()
        relationship[ENVIRONMENT_PROPERTY] = extension.model_dump(mode="json")
        enriched_count += 1

    if enriched_count != len(concretized_plan.steps):
        raise ValueError(
            f"enriched {enriched_count} relationships for "
            f"{len(concretized_plan.steps)} concrete steps"
        )
    output["x_autosut_export"] = {
        "schema_version": "1",
        "campaign_id": procedural_plan.campaign_id,
        "constraint_sha256": constraints.content_sha256,
        "blueprint_sha256": blueprint.content_sha256,
        "binding_catalog_sha256": binding_catalog.content_sha256,
        "concretized_plan_sha256": concretized_plan.content_sha256,
        "cve_rules_sha256": rule_sha256,
    }
    return output


def parse_environment_property(
    relationship: dict[str, Any],
) -> EnvironmentSemantics | None:
    payload = relationship.get(ENVIRONMENT_PROPERTY)
    if payload is None:
        return None
    extension = EnvironmentSemantics.model_validate(payload)
    if not extension.validate_hash():
        raise ValueError(
            f"environment extension hash mismatch: {relationship.get('id', '<unknown>')}"
        )
    return extension

