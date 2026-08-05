"""Measure representational closure from raw STIX through both extensions."""

from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from planning.stix_environment_extension import (
    ENVIRONMENT_PROPERTY,
    PROCEDURE_PROPERTY,
    EnvironmentSemantics,
    ResolutionStatus,
)


CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
PROCEDURAL_DIMENSIONS = {
    "sequence",
    "action_template",
    "preconditions",
    "effects",
    "parameter_schema",
    "evidence_policy",
    "fidelity_ceiling",
}
ENVIRONMENT_DIMENSIONS = {
    "selected_platform",
    "backend_cue",
    "environment_requirements",
    "parameter_bindings",
}
SOFTWARE_DIMENSIONS = {
    "cve_relationship",
    "package_name",
    "candidate_versions",
    "version_range",
    "cpe23_uri",
    "install_channel",
}


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class DimensionCell(StrictModel):
    technique_id: str
    dimension: str
    applicable: bool
    resolved: bool
    source: str


class ArmClosure(StrictModel):
    arm_id: str
    treatment: str
    applicable_cells: int
    resolved_cells: int
    closure_rate: float
    unresolved_cells: int
    resolved_by_dimension: dict[str, int]


class AblationEffect(StrictModel):
    removed_dimension: str
    resolved_cell_drop: int
    closure_rate_drop: float


class ExtensionEffectivenessReport(StrictModel):
    schema_version: str = "1"
    generated_at: str
    campaign_id: str
    experimental_unit: str
    controls: list[str]
    arms: list[ArmClosure]
    ablations: list[AblationEffect]
    full_arm_cells: list[DimensionCell]
    unresolved_full_arm_cells: list[DimensionCell]
    scope_statement: str
    content_sha256: str = ""

    def finalize_hash(self) -> None:
        payload = self.model_dump(mode="json", exclude={"content_sha256"})
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        self.content_sha256 = hashlib.sha256(encoded).hexdigest()


def _cell(
    technique_id: str,
    dimension: str,
    *,
    applicable: bool,
    resolved: bool,
    source: str,
) -> DimensionCell:
    return DimensionCell(
        technique_id=technique_id,
        dimension=dimension,
        applicable=applicable,
        resolved=resolved if applicable else False,
        source=source,
    )


def _procedure_cells(
    relationship: dict[str, Any],
    technique: dict[str, Any],
) -> tuple[list[DimensionCell], list[DimensionCell], list[DimensionCell]]:
    procedure = relationship.get(PROCEDURE_PROPERTY)
    environment_payload = relationship.get(ENVIRONMENT_PROPERTY)
    technique_id = (
        str(procedure.get("technique_id", ""))
        if isinstance(procedure, dict)
        else str(technique.get("id", ""))
    )
    description_present = bool(str(relationship.get("description", "")).strip())
    platform_present = bool(technique.get("x_mitre_platforms"))
    base_dimensions = [
        _cell(
            technique_id,
            "technique_identifier",
            applicable=True,
            resolved=bool(technique_id),
            source="stix_relationship_and_attack_pattern",
        ),
        _cell(
            technique_id,
            "procedure_description",
            applicable=True,
            resolved=description_present,
            source="stix_relationship",
        ),
        _cell(
            technique_id,
            "platform_options",
            applicable=True,
            resolved=platform_present,
            source="stix_attack_pattern",
        ),
    ]
    cve_ids = CVE_PATTERN.findall(str(relationship.get("description", "")))
    software_applicable = bool(cve_ids)
    is_attacker_step = (
        isinstance(procedure, dict)
        and str(procedure.get("sequence", ""))
        and technique.get("x_mitre_platforms") == ["PRE"]
    )
    applicability = {
        **{name: True for name in PROCEDURAL_DIMENSIONS},
        **{
            name: not is_attacker_step
            for name in ENVIRONMENT_DIMENSIONS
        },
        **{name: software_applicable for name in SOFTWARE_DIMENSIONS},
    }

    raw = [
        *base_dimensions,
        *[
            _cell(
                technique_id,
                dimension,
                applicable=applicable,
                resolved=False,
                source="absent_from_structured_stix",
            )
            for dimension, applicable in sorted(applicability.items())
        ],
    ]
    text_mined = [cell.model_copy(deep=True) for cell in raw]
    for cell in text_mined:
        if cell.dimension == "cve_relationship" and cell.applicable:
            cell.resolved = True
            cell.source = "deterministic_cve_regex"

    full = [cell.model_copy(deep=True) for cell in text_mined]
    if isinstance(procedure, dict):
        procedure_values = {
            "sequence": procedure.get("sequence"),
            "action_template": procedure.get("action_template_id"),
            "preconditions": procedure.get("requires"),
            "effects": procedure.get("produces"),
            "parameter_schema": procedure.get("parameter_kinds"),
            "evidence_policy": procedure.get("evidence_predicates"),
            "fidelity_ceiling": procedure.get("fidelity_ceiling"),
        }
        for cell in full:
            if cell.dimension in procedure_values:
                cell.resolved = bool(procedure_values[cell.dimension]) or (
                    cell.dimension == "preconditions"
                    and procedure_values[cell.dimension] == []
                )
                cell.source = PROCEDURE_PROPERTY

    if isinstance(environment_payload, dict):
        environment = EnvironmentSemantics.model_validate(environment_payload)
        if not environment.validate_hash():
            raise ValueError(f"environment extension hash mismatch for {technique_id}")
        environment_values = {
            "selected_platform": (
                environment.selected_platform.status == ResolutionStatus.resolved
            ),
            "backend_cue": (
                environment.backend_cue.status == ResolutionStatus.resolved
            ),
            "environment_requirements": bool(environment.requirements),
            "parameter_bindings": bool(environment.parameter_bindings),
        }
        software_values = {
            "package_name": any(
                item.package_name.status == ResolutionStatus.resolved
                for item in environment.software
            ),
            "candidate_versions": any(
                item.candidate_versions.status == ResolutionStatus.resolved
                for item in environment.software
            ),
            "version_range": any(
                item.version_range.status == ResolutionStatus.resolved
                for item in environment.software
            ),
            "cpe23_uri": any(
                item.cpe23_uri.status == ResolutionStatus.resolved
                for item in environment.software
            ),
            "install_channel": any(
                item.install_channel.status == ResolutionStatus.resolved
                for item in environment.software
            ),
        }
        for cell in full:
            if cell.dimension in environment_values:
                cell.resolved = environment_values[cell.dimension]
                cell.source = ENVIRONMENT_PROPERTY
            elif cell.dimension in software_values:
                cell.resolved = software_values[cell.dimension]
                cell.source = ENVIRONMENT_PROPERTY
    return raw, text_mined, full


def _arm(arm_id: str, treatment: str, cells: list[DimensionCell]) -> ArmClosure:
    applicable = [cell for cell in cells if cell.applicable]
    resolved = [cell for cell in applicable if cell.resolved]
    by_dimension: dict[str, int] = defaultdict(int)
    for cell in resolved:
        by_dimension[cell.dimension] += 1
    count = len(applicable)
    return ArmClosure(
        arm_id=arm_id,
        treatment=treatment,
        applicable_cells=count,
        resolved_cells=len(resolved),
        closure_rate=round(len(resolved) / count, 6) if count else 0.0,
        unresolved_cells=count - len(resolved),
        resolved_by_dimension=dict(sorted(by_dimension.items())),
    )


def build_extension_effectiveness_report(
    bundle: dict[str, Any],
) -> ExtensionEffectivenessReport:
    metadata = bundle.get("x_autosut_export")
    if not isinstance(metadata, dict):
        raise ValueError("bundle has no AutoSUT export metadata")
    campaign_id = str(metadata.get("campaign_id", ""))
    objects = {
        item["id"]: item
        for item in bundle.get("objects", [])
        if isinstance(item, dict) and item.get("id")
    }
    relationships = [
        item
        for item in bundle.get("objects", [])
        if isinstance(item, dict) and PROCEDURE_PROPERTY in item
    ]
    if not relationships:
        raise ValueError("bundle contains no enriched campaign relationships")

    raw_cells: list[DimensionCell] = []
    text_cells: list[DimensionCell] = []
    full_cells: list[DimensionCell] = []
    for relationship in relationships:
        technique = objects.get(str(relationship.get("target_ref", "")))
        if technique is None:
            raise ValueError(f"missing target technique for {relationship.get('id')}")
        raw, text_mined, full = _procedure_cells(relationship, technique)
        raw_cells.extend(raw)
        text_cells.extend(text_mined)
        full_cells.extend(full)

    sticks_cells = [cell.model_copy(deep=True) for cell in text_cells]
    for source, target in zip(full_cells, sticks_cells):
        if source.dimension in PROCEDURAL_DIMENSIONS:
            target.resolved = source.resolved
            target.source = source.source

    arms = [
        _arm("A", "native_stix_structured_fields", raw_cells),
        _arm("B", "native_stix_plus_bounded_text_mining", text_cells),
        _arm("C", "sticks_procedure_extension", sticks_cells),
        _arm("D", "sticks_plus_autosut_environment_extension", full_cells),
    ]
    full_arm = arms[-1]
    ablations: list[AblationEffect] = []
    for dimension in sorted(
        PROCEDURAL_DIMENSIONS | ENVIRONMENT_DIMENSIONS | SOFTWARE_DIMENSIONS
    ):
        ablated = [
            cell.model_copy(update={"resolved": False})
            if cell.dimension == dimension
            else cell.model_copy(deep=True)
            for cell in full_cells
        ]
        ablated_arm = _arm("ablation", dimension, ablated)
        ablations.append(
            AblationEffect(
                removed_dimension=dimension,
                resolved_cell_drop=(
                    full_arm.resolved_cells - ablated_arm.resolved_cells
                ),
                closure_rate_drop=round(
                    full_arm.closure_rate - ablated_arm.closure_rate,
                    6,
                ),
            )
        )

    report = ExtensionEffectivenessReport(
        generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        campaign_id=campaign_id,
        experimental_unit="one applicable semantic field on one campaign procedure",
        controls=[
            "same campaign and relationship set",
            "same ATT&CK snapshot",
            "same dimension applicability policy",
            "same parser and closure metric",
        ],
        arms=arms,
        ablations=ablations,
        full_arm_cells=full_cells,
        unresolved_full_arm_cells=[
            cell for cell in full_cells if cell.applicable and not cell.resolved
        ],
        scope_statement=(
            "This experiment measures representational closure for one campaign. "
            "It does not establish corpus-wide inference accuracy or historical "
            "replay fidelity."
        ),
    )
    report.finalize_hash()
    return report

