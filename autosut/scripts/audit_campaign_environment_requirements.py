#!/usr/bin/env python3
"""Derive non-decisive environment-audit inputs from pinned ATT&CK STIX.

This is an audit input for backend-scope decisions, not a Windows-capability claim.  ATT&CK
platform labels establish that a technique is documented for a platform; they do not by themselves
prove that a campaign needs native AD, Kerberos, SMB, WinRM, or other operating-system semantics.
Those requirements remain ``requires_external_evidence`` until a hash-bound source supports them.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.planning.procedural_plan import (  # noqa: E402
    ProceduralPlanInput,
    load_procedural_plan,
)

STIX_PATH = PROJECT_ROOT / "data" / "stix" / "enterprise-attack.json"
REGISTRY_PATH = PROJECT_ROOT / "src" / "executors" / "campaign_registry.yml"
PLAN_INPUT_ROOT = PROJECT_ROOT / "release" / "inputs" / "sticks"
OUTPUT_PATH = PROJECT_ROOT / "release" / "experiments" / "campaign_environment_requirements.json"


class RequirementProvenance(BaseModel):
    """Why a requirement was emitted, without conflating policy and corpus evidence."""

    model_config = ConfigDict(extra="forbid")

    kind: str
    source: str
    source_sha256: str
    detail: str


class TechniqueRequirement(BaseModel):
    """Platform and semantic boundary for one declared ATT&CK technique."""

    model_config = ConfigDict(extra="forbid")

    technique_id: str
    technique_name: str | None = None
    attack_object_id: str | None = None
    attck_platforms: list[str] = Field(default_factory=list)
    windows_documented: bool = False
    linux_documented: bool = False
    windows_only_platform_label: bool = False
    native_windows_semantics: str = "requires_external_evidence"
    provenance: list[RequirementProvenance] = Field(default_factory=list)


class ProcedureProvenanceSummary(BaseModel):
    """Structural evidence retained from a hash-verified STICKS plan.

    The summary deliberately stores references and counts rather than attempting
    to infer operating-system semantics from natural-language procedure text.
    """

    model_config = ConfigDict(extra="forbid")

    plan_path: str
    plan_content_sha256: str
    source_bundle_sha256: str
    source_object_count: int
    source_campaign_stix_id: str
    source_campaign_external_id: str
    technique_ids: list[str]
    technique_stix_ids: list[str]
    relationship_count: int
    procedure_description_count: int
    structural_validation: str = "verified_against_pinned_stix"
    semantic_interpretation: str = "not_performed"
    non_decisive_reason: str


class CampaignEnvironmentRequirement(BaseModel):
    """The auditable environment boundary for one declared or source-verified campaign."""

    model_config = ConfigDict(extra="forbid")

    campaign_id: str
    declaration_source: str
    declared_classification: str
    declared_techniques: list[str]
    techniques: list[TechniqueRequirement]
    windows_platform_label_present: bool
    linux_platform_label_present: bool
    native_windows_backend_decision: str
    missing_evidence: list[str]
    provenance: list[RequirementProvenance]
    procedural_provenance: ProcedureProvenanceSummary | None = None


class CampaignEnvironmentAudit(BaseModel):
    """A pinned-corpus input to the later Windows-scope decision."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = "campaign-environment-audit/v2"
    stix_path: str
    stix_sha256: str
    registry_path: str
    registry_sha256: str
    plan_input_root: str
    campaigns: list[CampaignEnvironmentRequirement]
    non_claim: str


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _display_path(path: Path) -> str:
    return str(path.resolve().relative_to(PROJECT_ROOT.resolve()))


def _attack_patterns(stix: dict[str, Any]) -> dict[str, dict[str, Any]]:
    by_external_id: dict[str, dict[str, Any]] = {}
    for obj in stix.get("objects", []):
        if (
            obj.get("type") != "attack-pattern"
            or obj.get("revoked")
            or obj.get("x_mitre_deprecated")
        ):
            continue
        for reference in obj.get("external_references", []):
            external_id = reference.get("external_id", "")
            if external_id.startswith("T"):
                by_external_id[external_id] = obj
    return by_external_id


def _stix_objects(stix: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(item["id"]): item
        for item in stix.get("objects", [])
        if isinstance(item, dict) and item.get("id")
    }


def _procedure_provenance_summary(
    *,
    plan_path: Path,
    plan: ProceduralPlanInput,
    stix_objects: dict[str, dict[str, Any]],
    stix_hash: str,
    stix_object_count: int,
) -> ProcedureProvenanceSummary:
    """Verify that each retained procedure text belongs to its STIX uses-link."""

    if plan.source.bundle_sha256 != stix_hash:
        raise ValueError(f"procedural plan source bundle does not match pinned STIX: {plan_path}")
    if plan.source.object_count != stix_object_count:
        raise ValueError(f"procedural plan object count does not match pinned STIX: {plan_path}")
    if plan.source.campaign_external_id != plan.campaign_id:
        raise ValueError(f"procedural plan campaign external ID mismatch: {plan_path}")
    campaign = stix_objects.get(plan.source.campaign_stix_id)
    if campaign is None or campaign.get("type") != "campaign":
        raise ValueError(f"source campaign object is absent: {plan_path}")

    relationship_count = 0
    procedure_description_count = 0
    technique_ids: list[str] = []
    technique_stix_ids: list[str] = []
    for step in plan.steps:
        technique = stix_objects.get(step.technique_stix_id)
        if technique is None or technique.get("type") != "attack-pattern":
            raise ValueError(
                f"source technique object is absent for {step.technique_id}: {plan_path}"
            )
        relationship_descriptions: list[str] = []
        for relationship_id in step.relationship_ids:
            relationship = stix_objects.get(relationship_id)
            if relationship is None:
                raise ValueError(
                    f"source relationship object is absent for {step.technique_id}: {plan_path}"
                )
            if (
                relationship.get("type") != "relationship"
                or relationship.get("relationship_type") != "uses"
                or relationship.get("source_ref") != plan.source.campaign_stix_id
                or relationship.get("target_ref") != step.technique_stix_id
            ):
                raise ValueError(
                    f"relationship provenance does not bind {step.technique_id}: {plan_path}"
                )
            description = relationship.get("description")
            if description:
                relationship_descriptions.append(str(description))
        if step.procedure_descriptions != relationship_descriptions:
            raise ValueError(
                f"procedure descriptions do not match source relationships for "
                f"{step.technique_id}: {plan_path}"
            )
        technique_ids.append(step.technique_id)
        technique_stix_ids.append(step.technique_stix_id)
        relationship_count += len(step.relationship_ids)
        procedure_description_count += len(step.procedure_descriptions)

    return ProcedureProvenanceSummary(
        plan_path=_display_path(plan_path),
        plan_content_sha256=plan.content_sha256,
        source_bundle_sha256=plan.source.bundle_sha256,
        source_object_count=plan.source.object_count,
        source_campaign_stix_id=plan.source.campaign_stix_id,
        source_campaign_external_id=plan.source.campaign_external_id,
        technique_ids=technique_ids,
        technique_stix_ids=technique_stix_ids,
        relationship_count=relationship_count,
        procedure_description_count=procedure_description_count,
        non_decisive_reason=(
            "The audit verifies STIX identifiers and copied procedure text, but it does not "
            "interpret that text as an operating-system, credential, or backend requirement."
        ),
    )


def _load_procedure_plans(
    *,
    plan_input_root: Path,
    stix_objects: dict[str, dict[str, Any]],
    stix_hash: str,
    stix_object_count: int,
) -> dict[str, ProcedureProvenanceSummary]:
    summaries: dict[str, ProcedureProvenanceSummary] = {}
    if not plan_input_root.exists():
        return summaries
    for plan_path in sorted(plan_input_root.rglob("*.procedural-plan.json")):
        plan = load_procedural_plan(plan_path)
        if plan.campaign_id in summaries:
            raise ValueError(f"duplicate procedural-plan input for campaign {plan.campaign_id}")
        summaries[plan.campaign_id] = _procedure_provenance_summary(
            plan_path=plan_path,
            plan=plan,
            stix_objects=stix_objects,
            stix_hash=stix_hash,
            stix_object_count=stix_object_count,
        )
    return summaries


def _technique_requirement(
    technique_id: str,
    patterns: dict[str, dict[str, Any]],
    stix_hash: str,
    stix_path: Path,
) -> TechniqueRequirement:
    pattern = patterns.get(technique_id)
    if pattern is None:
        return TechniqueRequirement(
            technique_id=technique_id,
            provenance=[
                RequirementProvenance(
                    kind="corpus_lookup_miss",
                    source=_display_path(stix_path),
                    source_sha256=stix_hash,
                    detail="declared technique was absent from the pinned active ATT&CK attack-pattern index",
                )
            ],
        )
    platforms = sorted(pattern.get("x_mitre_platforms", []))
    normalized = {platform.lower() for platform in platforms}
    windows = "windows" in normalized
    linux = "linux" in normalized
    return TechniqueRequirement(
        technique_id=technique_id,
        technique_name=pattern.get("name"),
        attack_object_id=pattern.get("id"),
        attck_platforms=platforms,
        windows_documented=windows,
        linux_documented=linux,
        windows_only_platform_label=windows and not linux,
        provenance=[
            RequirementProvenance(
                kind="corpus_supported",
                source=_display_path(stix_path),
                source_sha256=stix_hash,
                detail="ATT&CK attack-pattern x_mitre_platforms label",
            )
        ],
    )


def _campaign_requirement(
    campaign_id: str,
    config: dict[str, Any] | None,
    procedural_provenance: ProcedureProvenanceSummary | None,
    patterns: dict[str, dict[str, Any]],
    stix_hash: str,
    registry_hash: str,
    stix_path: Path,
    registry_path: Path,
) -> CampaignEnvironmentRequirement:
    registered_techniques = list(config.get("techniques", [])) if config else []
    plan_techniques = (
        list(procedural_provenance.technique_ids) if procedural_provenance is not None else []
    )
    if registered_techniques and plan_techniques and registered_techniques != plan_techniques:
        raise ValueError(
            f"registry and procedural-plan technique sequences differ for {campaign_id}"
        )
    technique_ids = registered_techniques or plan_techniques
    techniques = [
        _technique_requirement(technique_id, patterns, stix_hash, stix_path)
        for technique_id in technique_ids
    ]
    windows_present = any(technique.windows_documented for technique in techniques)
    linux_present = any(technique.linux_documented for technique in techniques)
    windows_only = [
        technique.technique_id for technique in techniques if technique.windows_only_platform_label
    ]
    missing: list[str] = []
    if config is None:
        missing.append(
            "no executable campaign declaration or fidelity classification is present in the campaign registry"
        )
    if procedural_provenance is not None:
        missing.append(
            "verified procedure descriptions are retained as provenance but are not interpreted into backend requirements by this audit"
        )
    if windows_present:
        missing.append(
            "native Windows semantics require procedure/source evidence beyond ATT&CK platform labels"
        )
    if windows_only:
        missing.append(
            "Windows-only ATT&CK platform labels require a campaign-level fidelity decision before native execution can be claimed"
        )
    decision = (
        "requires_external_evidence" if windows_present else "not_indicated_by_declared_techniques"
    )
    declaration_source = (
        "campaign_registry_and_verified_procedural_plan"
        if config is not None and procedural_provenance is not None
        else "campaign_registry" if config is not None else "verified_procedural_plan"
    )
    provenance: list[RequirementProvenance] = []
    if config is not None:
        provenance.append(
            RequirementProvenance(
                kind="analyst_declared_scope",
                source=_display_path(registry_path),
                source_sha256=registry_hash,
                detail=(
                    "campaign registry declares the executable campaign and its current "
                    "fidelity classification"
                ),
            )
        )
    if procedural_provenance is not None:
        provenance.append(
            RequirementProvenance(
                kind="verified_procedural_plan",
                source=procedural_provenance.plan_path,
                source_sha256=procedural_provenance.plan_content_sha256,
                detail=(
                    "procedure relationship identifiers and copied descriptions were "
                    "structurally verified against the pinned ATT&CK bundle"
                ),
            )
        )
    return CampaignEnvironmentRequirement(
        campaign_id=campaign_id,
        declaration_source=declaration_source,
        declared_classification=(
            str(config.get("classification", "unknown"))
            if config is not None
            else "not_declared_in_registry"
        ),
        declared_techniques=technique_ids,
        techniques=techniques,
        windows_platform_label_present=windows_present,
        linux_platform_label_present=linux_present,
        native_windows_backend_decision=decision,
        missing_evidence=missing,
        provenance=provenance,
        procedural_provenance=procedural_provenance,
    )


def audit_environment_requirements(
    *,
    stix_path: Path = STIX_PATH,
    registry_path: Path = REGISTRY_PATH,
    plan_input_root: Path = PLAN_INPUT_ROOT,
) -> CampaignEnvironmentAudit:
    """Audit declared techniques and verified procedure provenance conservatively."""

    stix_hash = _sha256(stix_path)
    registry_hash = _sha256(registry_path)
    stix = json.loads(stix_path.read_text(encoding="utf-8"))
    registry = yaml.safe_load(registry_path.read_text(encoding="utf-8"))
    if not isinstance(registry, dict):
        raise ValueError("campaign registry must contain one mapping")
    registry_campaigns = registry.get("campaigns", {})
    if not isinstance(registry_campaigns, dict):
        raise ValueError("campaign registry campaigns entry must be a mapping")
    patterns = _attack_patterns(stix)
    procedural_plans = _load_procedure_plans(
        plan_input_root=plan_input_root,
        stix_objects=_stix_objects(stix),
        stix_hash=stix_hash,
        stix_object_count=len(stix.get("objects", [])),
    )
    campaigns = [
        _campaign_requirement(
            campaign_id,
            registry_campaigns.get(campaign_id),
            procedural_plans.get(campaign_id),
            patterns,
            stix_hash,
            registry_hash,
            stix_path,
            registry_path,
        )
        for campaign_id in sorted(set(registry_campaigns) | set(procedural_plans))
    ]
    return CampaignEnvironmentAudit(
        stix_path=_display_path(stix_path),
        stix_sha256=stix_hash,
        registry_path=_display_path(registry_path),
        registry_sha256=registry_hash,
        plan_input_root=_display_path(plan_input_root),
        campaigns=campaigns,
        non_claim=(
            "This audit does not establish that a Windows backend is qualified or required. "
            "It validates copied procedure provenance only, does not interpret natural-language "
            "procedures into backend requirements, and requires separate qualified execution "
            "evidence for any native-semantics claim."
        ),
    )


def main() -> int:
    audit = audit_environment_requirements()
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(audit.model_dump_json(indent=2) + "\n", encoding="utf-8")
    print(
        "[campaign-environment-audit] "
        f"campaigns={len(audit.campaigns)} output={_display_path(OUTPUT_PATH)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
