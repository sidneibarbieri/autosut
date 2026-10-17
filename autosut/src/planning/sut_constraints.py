"""Resolve procedural metadata into explicit, auditable SUT constraints."""

from __future__ import annotations

import hashlib
import itertools
import json
from enum import Enum

from pydantic import BaseModel, Field

from .procedural_plan import ProceduralPlanInput


class RequirementSource(str, Enum):
    stix_field = "stix_field"
    curated_rule = "curated_rule"


class EnvironmentRequirement(BaseModel):
    requirement_id: str
    kind: str
    acceptable_values: list[str] = Field(min_length=1)
    technique_ids: list[str] = Field(min_length=1)
    source: RequirementSource
    rationale: str


class PlatformResolution(BaseModel):
    selected_platforms: list[str]
    materializable_platforms: list[str]
    unsupported_platforms: list[str]
    uncovered_technique_ids: list[str]
    complete: bool


class SUTConstraintSet(BaseModel):
    schema_version: str = "1"
    campaign_id: str
    source_plan_sha256: str
    platform_resolution: PlatformResolution
    requirements: list[EnvironmentRequirement]
    content_sha256: str = ""

    def finalize_hash(self) -> None:
        payload = self.model_dump(mode="json", exclude={"content_sha256"})
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        self.content_sha256 = hashlib.sha256(encoded).hexdigest()


PLATFORM_PREFERENCE = (
    "Linux",
    "Windows",
    "macOS",
    "Network Devices",
    "Containers",
    "IaaS",
    "SaaS",
    "Office 365",
    "Azure AD",
    "Google Workspace",
)

TECHNIQUE_REQUIREMENT_RULES: dict[str, tuple[tuple[str, tuple[str, ...], str], ...]] = {
    "T1190": (
        (
            "service",
            ("public-facing-application",),
            "The exploit target requires a reachable application boundary.",
        ),
    ),
    "T1105": (
        (
            "network",
            ("controlled-ingress-channel",),
            "Ingress transfer requires a bounded source-to-target channel.",
        ),
    ),
    "T1005": (
        (
            "data",
            ("declared-decoy-data",),
            "Local collection requires a predeclared non-sensitive data target.",
        ),
    ),
    "T1189": (
        (
            "service",
            ("private-lab-http-target",),
            "The controlled drive-by witness requires a reachable lab web target.",
        ),
    ),
    "T1568": (
        (
            "service",
            ("private-lab-resolver",),
            "Dynamic resolution requires a declared resolver with no external DNS dependency.",
        ),
    ),
    "T1560.001": (
        (
            "utility",
            ("local-archive-utility",),
            "Archive creation requires a declared local utility.",
        ),
    ),
    "T1030": (
        (
            "storage",
            ("bounded-local-chunk-store",),
            "Chunking requires a local destination that cannot exfiltrate data.",
        ),
    ),
}


def _platform_rank(platform: str) -> tuple[int, str]:
    try:
        return PLATFORM_PREFERENCE.index(platform), platform
    except ValueError:
        return len(PLATFORM_PREFERENCE), platform


def _minimum_platform_cover(platform_sets: list[set[str]]) -> list[str]:
    constrained_sets = [platforms for platforms in platform_sets if platforms]
    if not constrained_sets:
        return []
    universe = sorted(set().union(*constrained_sets), key=_platform_rank)
    for size in range(1, len(universe) + 1):
        candidates = [
            combination
            for combination in itertools.combinations(universe, size)
            if all(set(combination) & allowed for allowed in constrained_sets)
        ]
        if candidates:
            return list(min(candidates, key=lambda item: tuple(_platform_rank(p) for p in item)))
    return []


def resolve_sut_constraints(
    plan: ProceduralPlanInput,
    *,
    materializable_platforms: set[str],
) -> SUTConstraintSet:
    sut_steps = [step for step in plan.steps if step.execution_domain != "attacker"]
    platform_sets = [set(step.platforms) - {"PRE"} for step in sut_steps]
    available_sets = [platforms & materializable_platforms for platforms in platform_sets if platforms]
    selected_platforms = _minimum_platform_cover(available_sets)
    unsupported_sets = [
        platforms for platforms in platform_sets
        if platforms and not (platforms & materializable_platforms)
    ]
    unsupported_selection = _minimum_platform_cover(unsupported_sets)
    selected_platforms.extend(unsupported_selection)
    supported_selected = [
        platform for platform in selected_platforms if platform in materializable_platforms
    ]
    unsupported = [
        platform for platform in selected_platforms if platform not in materializable_platforms
    ]
    uncovered = [
        step.technique_id
        for step in sut_steps
        if (set(step.platforms) - {"PRE"})
        and not ((set(step.platforms) - {"PRE"}) & set(supported_selected))
    ]

    requirements: list[EnvironmentRequirement] = []
    for step in plan.steps:
        sut_platforms = set(step.platforms) - {"PRE"}
        if step.execution_domain != "attacker" and sut_platforms:
            requirements.append(
                EnvironmentRequirement(
                    requirement_id=f"{step.technique_id}.platform",
                    kind="platform",
                    acceptable_values=sorted(sut_platforms, key=_platform_rank),
                    technique_ids=[step.technique_id],
                    source=RequirementSource.stix_field,
                    rationale="Derived directly from x_mitre_platforms.",
                )
            )
        if step.permissions_required:
            requirements.append(
                EnvironmentRequirement(
                    requirement_id=f"{step.technique_id}.permission",
                    kind="permission",
                    acceptable_values=sorted(set(step.permissions_required)),
                    technique_ids=[step.technique_id],
                    source=RequirementSource.stix_field,
                    rationale="Derived directly from x_mitre_permissions_required.",
                )
            )
        for rule_index, (kind, values, rationale) in enumerate(
            TECHNIQUE_REQUIREMENT_RULES.get(step.technique_id, ()), start=1
        ):
            requirements.append(
                EnvironmentRequirement(
                    requirement_id=f"{step.technique_id}.{kind}.{rule_index}",
                    kind=kind,
                    acceptable_values=list(values),
                    technique_ids=[step.technique_id],
                    source=RequirementSource.curated_rule,
                    rationale=rationale,
                )
            )

    constraint_set = SUTConstraintSet(
        campaign_id=plan.campaign_id,
        source_plan_sha256=plan.content_sha256,
        platform_resolution=PlatformResolution(
            selected_platforms=selected_platforms,
            materializable_platforms=sorted(materializable_platforms, key=_platform_rank),
            unsupported_platforms=unsupported,
            uncovered_technique_ids=uncovered,
            complete=not unsupported and not uncovered,
        ),
        requirements=requirements,
    )
    constraint_set.finalize_hash()
    return constraint_set
