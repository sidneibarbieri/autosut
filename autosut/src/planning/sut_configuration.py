"""Candidate SUT configurations and the provenance of the values they contain.

AutoSUT measures which environment constraints structured CTI supports. Those constraints
stop at platform families and, where a curated rule applies, an affected product: they never
reach the concrete service a replay must run. Somebody still has to choose a product version,
a port, and an exposure condition before a campaign can execute.

This module represents that choice explicitly. A proposer, human or model, suggests a
candidate configuration; a deterministic check then classifies every value in it by where the
value could have come from, and reports which measured requirements the candidate satisfies.
Provenance is decided here rather than declared by the proposer, because a proposer that
labels its own output cannot be used to measure how much it introduced.

A satisfied candidate is a configuration consistent with the measured constraints of the
campaign. It is not the environment the campaign historically ran against, and nothing in this
module establishes that it is.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

from .sut_constraints import EnvironmentRequirement


class ValueProvenance(str, Enum):
    """Where a configuration value could have come from, in decreasing evidential strength."""

    cti_evidenced = "cti_evidenced"
    catalog_supplied = "catalog_supplied"
    proposer_introduced = "proposer_introduced"


class ConfiguredService(BaseModel):
    """One concrete service a candidate configuration would deploy."""

    model_config = ConfigDict(extra="forbid")

    host_role: str
    product: str
    version: str = ""
    port: str = ""
    exposure: str = ""


class SutConfigurationProposal(BaseModel):
    """A proposer's candidate configuration for one campaign."""

    model_config = ConfigDict(extra="forbid")

    campaign_id: str
    proposer: str
    platform: str = ""
    services: list[ConfiguredService] = Field(default_factory=list)


class ClassifiedValue(BaseModel):
    """A single configuration value with the provenance the checker assigned it."""

    model_config = ConfigDict(extra="forbid")

    field_name: str
    value: str
    provenance: ValueProvenance


class ConfigurationVerdict(BaseModel):
    """What a candidate configuration satisfies, and what it introduced to get there."""

    model_config = ConfigDict(extra="forbid")

    campaign_id: str
    proposer: str
    services: int
    classified_values: list[ClassifiedValue] = Field(default_factory=list)
    satisfied_requirement_ids: list[str] = Field(default_factory=list)
    unsatisfied_requirement_ids: list[str] = Field(default_factory=list)
    satisfies_all_requirements: bool = False

    def provenance_counts(self) -> dict[str, int]:
        """Occurrence counts per provenance class, so repeated values are counted each time."""
        counts = {provenance.value: 0 for provenance in ValueProvenance}
        for classified in self.classified_values:
            counts[classified.provenance.value] += 1
        return counts


PLATFORM_KIND = "platform"


def _normalize(text: str) -> str:
    return text.strip().lower()


def partition_requirements(
    requirements: list[EnvironmentRequirement],
) -> tuple[list[EnvironmentRequirement], list[EnvironmentRequirement]]:
    """Split measured requirements into those a configuration can be checked against, and the rest.

    Platform requirements name real-world systems, so a proposed configuration states values
    from the same vocabulary and satisfaction is decidable by comparison. The other kinds name
    the role a component plays in the declared laboratory, such as a public-facing application
    or a controlled ingress channel. A deployable configuration answers those with a concrete
    product, which sits at a different level of description, so string comparison cannot decide
    whether the role was met. Keeping the two apart avoids reporting that mismatch as failure.
    """
    comparable = [item for item in requirements if item.kind == PLATFORM_KIND]
    role_level = [item for item in requirements if item.kind != PLATFORM_KIND]
    return comparable, role_level


def _evidenced_values(requirements: list[EnvironmentRequirement]) -> set[str]:
    """Every value the measured constraints accept, which is what the CTI can support."""
    return {
        _normalize(value)
        for requirement in requirements
        for value in requirement.acceptable_values
    }


def _classify(value: str, evidenced: set[str], catalog: set[str]) -> ValueProvenance:
    normalized = _normalize(value)
    if normalized in evidenced:
        return ValueProvenance.cti_evidenced
    if normalized in catalog:
        return ValueProvenance.catalog_supplied
    return ValueProvenance.proposer_introduced


def _service_values(service: ConfiguredService) -> list[tuple[str, str]]:
    """Named values of one service, skipping fields the proposer left empty."""
    candidates = (
        ("product", service.product),
        ("version", service.version),
        ("port", service.port),
        ("exposure", service.exposure),
    )
    return [(name, value) for name, value in candidates if value.strip()]


def classify_proposal(
    proposal: SutConfigurationProposal,
    requirements: list[EnvironmentRequirement],
    deployment_catalog: set[str],
) -> ConfigurationVerdict:
    """Assign provenance to every proposed value and record which requirements it meets.

    A requirement counts as satisfied when the proposal states one of its acceptable values,
    either as the platform or as a service field.
    """
    evidenced = _evidenced_values(requirements)
    catalog = {_normalize(entry) for entry in deployment_catalog}

    classified: list[ClassifiedValue] = []
    if proposal.platform.strip():
        classified.append(
            ClassifiedValue(
                field_name="platform",
                value=proposal.platform,
                provenance=_classify(proposal.platform, evidenced, catalog),
            )
        )
    for service in proposal.services:
        for field_name, value in _service_values(service):
            classified.append(
                ClassifiedValue(
                    field_name=field_name,
                    value=value,
                    provenance=_classify(value, evidenced, catalog),
                )
            )

    stated = {_normalize(item.value) for item in classified}
    satisfied = [
        requirement.requirement_id
        for requirement in requirements
        if any(_normalize(value) in stated for value in requirement.acceptable_values)
    ]
    unsatisfied = [
        requirement.requirement_id
        for requirement in requirements
        if requirement.requirement_id not in satisfied
    ]
    return ConfigurationVerdict(
        campaign_id=proposal.campaign_id,
        proposer=proposal.proposer,
        services=len(proposal.services),
        classified_values=classified,
        satisfied_requirement_ids=satisfied,
        unsatisfied_requirement_ids=unsatisfied,
        satisfies_all_requirements=not unsatisfied,
    )
