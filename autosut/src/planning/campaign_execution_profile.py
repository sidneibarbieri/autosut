"""Consolidate every environment signal a campaign carries before any proposal is made.

Measuring what a proposer introduces is only meaningful once the proposer has been given
everything the artifact already knows. AutoSUT resolves campaign CVEs to installable packages
with candidate versions, and it extracts platform constraints from the bundle, but those two
results live in separate records. A proposer handed only the platform constraints will invent
a product, and the invention would be an artifact of the missing join rather than a property
of the intelligence.

This module performs that join and then narrows the choice deterministically. When the
resolved evidence leaves exactly one deployable candidate, the selection is made here and no
proposer is consulted; when it leaves several, the remaining ambiguity is what a proposer may
resolve; when it leaves none, the campaign is reported as unsupported rather than filled in.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class SelectionOutcome(str, Enum):
    """What the deterministic narrowing left to decide."""

    unsupported = "unsupported"
    deterministic = "deterministic"
    ambiguous = "ambiguous"


class DeployableCandidate(BaseModel):
    """One installable product the resolved evidence permits for a campaign."""

    model_config = ConfigDict(extra="forbid")

    package_name: str
    ecosystem: str
    install_channel: str
    candidate_versions: list[str] = Field(default_factory=list)
    cve_id: str = ""
    overlay_template: str = ""


class CampaignExecutionProfile(BaseModel):
    """Every environment signal for one campaign, and what remains to be decided."""

    model_config = ConfigDict(extra="forbid")

    campaign_id: str
    campaign_name: str = ""
    platform_values: list[str] = Field(default_factory=list)
    role_requirements: list[str] = Field(default_factory=list)
    cve_ids: list[str] = Field(default_factory=list)
    candidates: list[DeployableCandidate] = Field(default_factory=list)
    outcome: SelectionOutcome
    selected: DeployableCandidate | None = None

    @property
    def consults_proposer(self) -> bool:
        """A proposer is worth consulting only when a real choice remains."""
        return self.outcome is SelectionOutcome.ambiguous


def _platform_values(requirements: list[dict]) -> list[str]:
    values = {
        value
        for requirement in requirements
        if requirement["kind"] == "platform"
        for value in requirement["acceptable_values"]
    }
    return sorted(values)


def _role_requirements(requirements: list[dict]) -> list[str]:
    values = {
        value
        for requirement in requirements
        if requirement["kind"] != "platform"
        for value in requirement["acceptable_values"]
    }
    return sorted(values)


def _candidates_for(campaign_name: str, resolution_rows: list[dict]) -> list[DeployableCandidate]:
    """Deployable packages the CVE resolution already established for this campaign."""
    return [
        DeployableCandidate(
            package_name=row["package_name"],
            ecosystem=row.get("ecosystem", ""),
            install_channel=row.get("install_channel", ""),
            candidate_versions=list(row.get("candidate_versions", [])),
            cve_id=row.get("cve_id", ""),
            overlay_template=row.get("overlay_template", ""),
        )
        for row in resolution_rows
        if row.get("campaign_name") == campaign_name
        and row.get("automatic_sut_support") is True
        and row.get("package_name")
    ]


def build_profile(
    campaign_id: str,
    campaign_name: str,
    requirements: list[dict],
    resolution_rows: list[dict],
) -> CampaignExecutionProfile:
    """Join platform constraints with resolved packages and narrow the remaining choice."""
    candidates = _candidates_for(campaign_name, resolution_rows)
    distinct_packages = {candidate.package_name for candidate in candidates}
    if not candidates:
        outcome = SelectionOutcome.unsupported
        selected = None
    elif len(distinct_packages) == 1:
        outcome = SelectionOutcome.deterministic
        selected = candidates[0]
    else:
        outcome = SelectionOutcome.ambiguous
        selected = None

    return CampaignExecutionProfile(
        campaign_id=campaign_id,
        campaign_name=campaign_name,
        platform_values=_platform_values(requirements),
        role_requirements=_role_requirements(requirements),
        cve_ids=sorted({candidate.cve_id for candidate in candidates if candidate.cve_id}),
        candidates=candidates,
        outcome=outcome,
        selected=selected,
    )
