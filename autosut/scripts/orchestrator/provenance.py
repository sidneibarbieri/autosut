"""Provenance aggregation over a SUTProfile.

The orchestrator tags every concrete SUT element with a
:class:`~.models.ProvenanceSource` - ``corpus_supported``,
``external_reference``, ``analyst_authored``, ``autosut_concretized`` or
``inferred`` - at authoring
time in :mod:`catalog`. This module rolls those per-element tags up into a
campaign-level (and corpus-level) summary so the paper can report, auditable
down to the individual element:

    "Of everything we materialised for this campaign, X% is anchored in the
     CTI corpus, Y% is an explicit analyst lab choice, Z% is an AutoSUT
     concretisation of an under-specified corpus signal."

This is the load-bearing measurement for the environment-gap argument: it
quantifies *how much of an executable environment public cyber knowledge
supports* versus *how much must be concretised outside the corpus*. We never
**compute** a tag here - that would fabricate the very evidence the paper
reports. We only count tags an analyst deliberately set in the catalog.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field

from .models import (
    CVEInjection, ProvenanceSource, SUTComposition, SUTProfile,
)

# Stable dimension vocabulary. Each tagged SUT element belongs to exactly one
# dimension; the order here is the column/row order the report + dashboard use.
# It answers the paper's central question dimension-by-dimension: "how much of
# THIS part of the environment came from the corpus?"
DIMENSIONS = (
    "platform", "software", "vulnerability",
    "credentials", "exposures", "artifacts", "topology",
)

# All four sources always appear in a summary (even at count 0) so the table
# shape is stable across campaigns - reviewers compare columns directly.
_SOURCES = tuple(s.value for s in ProvenanceSource)


class ProvenanceElement(BaseModel):
    """One tagged SUT element, flattened for the per-element audit trail."""

    dimension: str  # one of DIMENSIONS
    identifier: str  # stable, human-auditable id, e.g. "target.software.apache_httpd@2.4.49"
    value: str  # the concrete value the reviewer sees materialised
    source: ProvenanceSource
    host: Optional[str] = None  # which host carries it (None => SUT-level/topology)
    purpose: str = ""  # the analyst-facing rationale carried on the element


class ProvenanceSummary(BaseModel):
    """Campaign-level (or corpus-level) provenance roll-up."""

    campaign_id: Optional[str] = None
    total_elements: int = 0
    by_source: dict[str, int] = Field(default_factory=dict)
    percentages: dict[str, float] = Field(default_factory=dict)
    by_dimension: dict[str, dict[str, int]] = Field(default_factory=dict)
    elements: list[ProvenanceElement] = Field(default_factory=list)


def _zero_source_counts() -> dict[str, int]:
    return {source: 0 for source in _SOURCES}


def _composition_elements(
    composition: Optional[SUTComposition], host: Optional[str]
) -> list[ProvenanceElement]:
    """Flatten one host's declarative composition into tagged elements."""
    if composition is None:
        return []
    prefix = f"{host}." if host else ""
    elements: list[ProvenanceElement] = []
    for app in composition.applications:
        elements.append(ProvenanceElement(
            dimension="software",
            identifier=f"{prefix}software.{app.name}@{app.version}",
            value=f"{app.name}@{app.version}",
            source=app.source, host=host, purpose=app.purpose,
        ))
    for cred in composition.credentials:
        elements.append(ProvenanceElement(
            dimension="credentials",
            identifier=f"{prefix}credential.{cred.user}",
            value=f"{cred.kind}:{cred.user}",
            source=cred.source, host=host, purpose=cred.purpose,
        ))
    for exposure in composition.exposures:
        elements.append(ProvenanceElement(
            dimension="exposures",
            identifier=f"{prefix}exposure.{exposure.port}",
            value=f"{exposure.port}/{exposure.protocol} {exposure.service}".strip(),
            source=exposure.source, host=host, purpose=exposure.purpose,
        ))
    for artifact in composition.artifacts:
        elements.append(ProvenanceElement(
            dimension="artifacts",
            identifier=f"{prefix}artifact.{artifact.path}",
            value=artifact.path,
            source=artifact.source, host=host, purpose=artifact.purpose,
        ))
    return elements


def _os_family(base_image: str) -> str:
    """Map a base image to an OS family. ATT&CK's ``x_mitre_platforms`` field
    pins the OS family a technique targets, so the family ("linux"/"windows")
    is corpus-supported even though the concrete image is a concretization."""
    image = (base_image or "").lower()
    if any(tag in image for tag in ("windows", "servercore", "nanoserver")):
        return "windows"
    if "macos" in image or "darwin" in image:
        return "macos"
    return "linux"


def _platform_element(
    base_image: str,
    host: Optional[str],
    source: ProvenanceSource,
) -> ProvenanceElement:
    family = _os_family(base_image)
    prefix = f"{host}." if host else ""
    return ProvenanceElement(
        dimension="platform",
        identifier=f"{prefix}platform.{family}",
        value=family,
        # A platform is corpus-supported only when the profile declaration
        # carries that provenance.  Technique-wide ATT&CK compatibility must
        # not be silently promoted to campaign-specific environment evidence.
        source=source,
        host=host,
        purpose=f"materialised as {base_image}",
    )


def _vulnerability_elements(cves: list[CVEInjection]) -> list[ProvenanceElement]:
    elements: list[ProvenanceElement] = []
    for cve in cves:
        elements.append(ProvenanceElement(
            dimension="vulnerability",
            identifier=f"vulnerability.{cve.cve_id}",
            value=cve.cve_id,
            # The declaration carries the source explicitly.  A syntactically
            # valid CVE identifier can come from the evaluated bundle or from
            # an external advisory; syntax alone cannot decide provenance.
            source=cve.source,
            host=None,
            purpose=f"{cve.realization.value} / {cve.target_software}",
        ))
    return elements


def collect_elements(
    profile: SUTProfile, cves: Optional[list[CVEInjection]] = None
) -> list[ProvenanceElement]:
    """Flatten every tagged element in a SUTProfile into one ordered list.

    Per host: platform, then the declarative composition (software,
    credentials, exposures, artifacts). Then SUT-level vulnerabilities (the
    injected CVE set) and topology zones. Order is stable - hosts in
    declaration order - so two runs of the same campaign emit byte-identical
    element lists (the determinism the paper claims for concretization).
    """
    elements: list[ProvenanceElement] = []
    if profile.is_multi_host:
        for host in profile.hosts or []:
            elements.append(_platform_element(
                host.base_image, host.name, host.platform_source,
            ))
            elements.extend(_composition_elements(host.composition, host.name))
    else:
        elements.append(_platform_element(
            profile.base_image, None, profile.platform_source,
        ))
        elements.extend(_composition_elements(profile.composition, None))
    elements.extend(_vulnerability_elements(cves or []))
    if profile.topology is not None:
        for zone in profile.topology.zones:
            elements.append(ProvenanceElement(
                dimension="topology",
                identifier=f"topology.zone.{zone.name}",
                value=zone.name,
                source=zone.source, host=None, purpose=zone.description,
            ))
    return elements


def summarize_profile(
    profile: SUTProfile, campaign_id: Optional[str] = None,
    cves: Optional[list[CVEInjection]] = None,
) -> ProvenanceSummary:
    """Roll up a SUTProfile's per-element provenance tags into a summary."""
    elements = collect_elements(profile, cves)

    by_source = _zero_source_counts()
    by_dimension: dict[str, dict[str, int]] = {
        dim: _zero_source_counts() for dim in DIMENSIONS
    }
    for element in elements:
        by_source[element.source.value] += 1
        by_dimension[element.dimension][element.source.value] += 1

    total = len(elements)
    percentages = {
        source: round(100.0 * count / total, 1) if total else 0.0
        for source, count in by_source.items()
    }
    return ProvenanceSummary(
        campaign_id=campaign_id,
        total_elements=total,
        by_source=by_source,
        percentages=percentages,
        by_dimension=by_dimension,
        elements=elements,
    )


def merge_summaries(
    summaries: list[ProvenanceSummary], campaign_id: Optional[str] = "ALL"
) -> ProvenanceSummary:
    """Roll several campaign summaries up into one corpus-wide summary."""
    by_source = _zero_source_counts()
    by_dimension: dict[str, dict[str, int]] = {
        dim: _zero_source_counts() for dim in DIMENSIONS
    }
    elements: list[ProvenanceElement] = []
    for summary in summaries:
        for source, count in summary.by_source.items():
            by_source[source] += count
        for dim, counts in summary.by_dimension.items():
            for source, count in counts.items():
                by_dimension[dim][source] += count
        elements.extend(summary.elements)

    total = sum(by_source.values())
    percentages = {
        source: round(100.0 * count / total, 1) if total else 0.0
        for source, count in by_source.items()
    }
    return ProvenanceSummary(
        campaign_id=campaign_id,
        total_elements=total,
        by_source=by_source,
        percentages=percentages,
        by_dimension=by_dimension,
        elements=elements,
    )


def support_matrix_rows(summary: ProvenanceSummary) -> list[dict[str, object]]:
    """Dimension x source rows for a support_matrix.csv export."""
    rows: list[dict[str, object]] = []
    for dim in DIMENSIONS:
        counts = summary.by_dimension.get(dim, _zero_source_counts())
        dim_total = sum(counts.values())
        row: dict[str, object] = {"dimension": dim, "total": dim_total}
        for source in _SOURCES:
            row[source] = counts.get(source, 0)
        rows.append(row)
    return rows
