#!/usr/bin/env python3
"""Generate the deterministic state of published campaign/SUT contracts.

This report describes declared inputs and validation results. It deliberately
does not summarize historical executor records or turn reviewer-generated runs
into a current operational claim. The canonical claim ledger remains the only
authority for bounded execution evidence.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_ROOT = PROJECT_ROOT / "scripts"
SRC_ROOT = PROJECT_ROOT / "src"
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from evaluation.canonical_operational_witness import (  # noqa: E402
    assess_caldera_dispatch_witness,
)
from loaders.campaign_loader import (  # noqa: E402
    list_campaigns,
    list_sut_profiles,
    load_campaign,
    validate_campaign_sut_pair,
)
from release_clock import release_isoformat  # noqa: E402


MITRE_AUDIT = PROJECT_ROOT / "results" / "mitre_metadata_audit.json"
OUTPUT_JSON = PROJECT_ROOT / "results" / "corpus_state.json"
OUTPUT_MD = PROJECT_ROOT / "results" / "CORPUS_STATE.md"


class ReportModel(BaseModel):
    """Reject accidental fields in reviewer-facing report DTOs."""

    model_config = ConfigDict(extra="forbid")


class BoundedDispatchWitness(ReportModel):
    """The one sealed witness represented in the public claim ledger."""

    campaign_id: str = Field(min_length=1)
    source_campaign_id: str = Field(min_length=1)
    realization: Literal["surrogate"]


class CampaignContractRow(ReportModel):
    """One available campaign definition and its declared SUT contract state."""

    campaign_id: str = Field(min_length=1)
    sut_profile_id: str = Field(min_length=1)
    has_declared_sut_profile: bool
    pair_valid: bool
    pair_error: str
    mitre_metadata_status: Literal["clean", "findings", "not_audited"]
    has_bounded_dispatch_witness: bool


class CorpusStateTotals(ReportModel):
    """Aggregate counts for the contract state, not execution outcomes."""

    available_campaign_definitions: int = Field(ge=0)
    campaigns_with_declared_sut_profile: int = Field(ge=0)
    campaigns_with_strict_pair_validation: int = Field(ge=0)
    campaigns_with_pair_validation_findings: int = Field(ge=0)
    campaigns_with_clean_mitre_metadata: int = Field(ge=0)
    campaigns_not_audited_for_mitre_metadata: int = Field(ge=0)
    campaigns_with_bounded_dispatch_witness: int = Field(ge=0)


class CorpusStateReport(ReportModel):
    """Versioned deterministic report emitted by the corpus-state generator."""

    schema_version: Literal["autosut-corpus-contract-state/v2"] = (
        "autosut-corpus-contract-state/v2"
    )
    generated_at: str = Field(min_length=1)
    generated_from: dict[str, str]
    bounded_dispatch_witness: BoundedDispatchWitness
    totals: CorpusStateTotals
    campaigns: list[CampaignContractRow]


def _read_json_object(path: Path) -> dict:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"expected a JSON object: {path}")
    return payload


def _mitre_status_by_campaign() -> dict[str, Literal["clean", "findings"]]:
    audit = _read_json_object(MITRE_AUDIT)
    entries = audit.get("campaigns")
    if not isinstance(entries, list):
        raise ValueError("MITRE metadata audit lacks a campaign list")

    statuses: dict[str, Literal["clean", "findings"]] = {}
    required_fields = (
        "steps_with_missing_metadata",
        "steps_with_tactic_mismatch",
        "steps_without_mitre_support",
    )
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("MITRE metadata audit contains a non-object campaign entry")
        campaign_id = entry.get("campaign_id")
        if not isinstance(campaign_id, str) or not campaign_id:
            raise ValueError("MITRE metadata audit contains a campaign without an identifier")
        if campaign_id in statuses:
            raise ValueError(f"MITRE metadata audit duplicates campaign: {campaign_id}")
        if any(not isinstance(entry.get(field), int) for field in required_fields):
            raise ValueError(f"MITRE metadata audit has invalid counters for: {campaign_id}")
        statuses[campaign_id] = (
            "clean"
            if all(entry[field] == 0 for field in required_fields)
            else "findings"
        )
    return statuses


def _bounded_dispatch_witness() -> BoundedDispatchWitness:
    assessment = assess_caldera_dispatch_witness(PROJECT_ROOT)
    if assessment.status != "supported_bounded" or assessment.witness is None:
        reason = assessment.failure_reason or assessment.status
        raise RuntimeError(f"canonical bounded dispatch witness is unavailable: {reason}")
    return BoundedDispatchWitness(
        campaign_id=assessment.witness.campaign_id,
        source_campaign_id=assessment.witness.source_campaign_id,
        realization=assessment.witness.realization,
    )


def _campaign_row(
    campaign_id: str,
    sut_profile_ids: frozenset[str],
    mitre_statuses: dict[str, Literal["clean", "findings"]],
    witness_campaign_id: str,
) -> CampaignContractRow:
    campaign = load_campaign(campaign_id)
    has_sut_profile = campaign.sut_profile_id in sut_profile_ids
    if has_sut_profile:
        pair_error = validate_campaign_sut_pair(campaign_id) or ""
    else:
        pair_error = (
            "No published SUT profile matches declared profile "
            f"`{campaign.sut_profile_id}`."
        )

    return CampaignContractRow(
        campaign_id=campaign_id,
        sut_profile_id=campaign.sut_profile_id,
        has_declared_sut_profile=has_sut_profile,
        pair_valid=has_sut_profile and not pair_error,
        pair_error=pair_error,
        mitre_metadata_status=mitre_statuses.get(campaign_id, "not_audited"),
        has_bounded_dispatch_witness=campaign_id == witness_campaign_id,
    )


def build_report() -> CorpusStateReport:
    """Build the static campaign/SUT contract state from released inputs."""
    witness = _bounded_dispatch_witness()
    mitre_statuses = _mitre_status_by_campaign()
    sut_profile_ids = frozenset(list_sut_profiles())
    rows = [
        _campaign_row(
            campaign_id,
            sut_profile_ids,
            mitre_statuses,
            witness.campaign_id,
        )
        for campaign_id in list_campaigns()
    ]

    totals = CorpusStateTotals(
        available_campaign_definitions=len(rows),
        campaigns_with_declared_sut_profile=sum(
            row.has_declared_sut_profile for row in rows
        ),
        campaigns_with_strict_pair_validation=sum(row.pair_valid for row in rows),
        campaigns_with_pair_validation_findings=sum(
            row.has_declared_sut_profile and not row.pair_valid for row in rows
        ),
        campaigns_with_clean_mitre_metadata=sum(
            row.mitre_metadata_status == "clean" for row in rows
        ),
        campaigns_not_audited_for_mitre_metadata=sum(
            row.mitre_metadata_status == "not_audited" for row in rows
        ),
        campaigns_with_bounded_dispatch_witness=sum(
            row.has_bounded_dispatch_witness for row in rows
        ),
    )
    return CorpusStateReport(
        generated_at=release_isoformat(),
        generated_from={
            "campaign_definitions": "campaigns/ and data/campaigns/",
            "sut_profiles": "data/sut_profiles/",
            "mitre_metadata_audit": "results/mitre_metadata_audit.json",
            "execution_claim_authority": "release/claim_evidence_traceability.json",
        },
        bounded_dispatch_witness=witness,
        totals=totals,
        campaigns=rows,
    )


def markdown_report(report: CorpusStateReport) -> str:
    """Render a concise, reviewer-readable contract state report."""
    totals = report.totals
    lines = [
        "# Campaign/SUT Contract State",
        "",
        "This deterministic report describes released campaign definitions and their",
        "declared SUT contracts. It does not summarize historical executor records,",
        "report a success rate, or promote reviewer-generated runs to a claim.",
        "Use `release/CLAIM_EVIDENCE_TRACEABILITY.md` for the canonical execution",
        "claim and its hash-bound evidence.",
        "",
        "## Summary",
        "",
        f"- Generated at: `{report.generated_at}`",
        f"- Available campaign definitions: `{totals.available_campaign_definitions}`",
        f"- Campaigns with a declared SUT profile: `{totals.campaigns_with_declared_sut_profile}`",
        f"- Campaign/SUT pairs passing strict validation: `{totals.campaigns_with_strict_pair_validation}`",
        f"- Campaign/SUT pairs with validation findings: `{totals.campaigns_with_pair_validation_findings}`",
        f"- Campaigns with clean MITRE metadata audit: `{totals.campaigns_with_clean_mitre_metadata}`",
        f"- Campaigns not covered by the MITRE metadata audit: `{totals.campaigns_not_audited_for_mitre_metadata}`",
        f"- Bounded dispatch witnesses: `{totals.campaigns_with_bounded_dispatch_witness}`",
        "",
        "## Bounded Dispatch Witness",
        "",
        f"- Contract campaign: `{report.bounded_dispatch_witness.campaign_id}`",
        f"- Source campaign: `{report.bounded_dispatch_witness.source_campaign_id}`",
        f"- Realization: `{report.bounded_dispatch_witness.realization}`",
        "",
        "The witness is one sealed, static observation. It does not establish",
        "campaign-wide execution, a current-revision live rerun, or an analyst-effort result.",
        "",
        "## Contract State",
        "",
        "| Campaign | Declared SUT Profile | Profile Present | Pair Valid | MITRE Audit | Bounded Dispatch Witness |",
        "|---|---|---:|---:|---|---:|",
    ]
    for row in report.campaigns:
        lines.append(
            f"| `{row.campaign_id}` | `{row.sut_profile_id}` | "
            f"{'yes' if row.has_declared_sut_profile else 'no'} | "
            f"{'yes' if row.pair_valid else 'no'} | {row.mitre_metadata_status} | "
            f"{'yes' if row.has_bounded_dispatch_witness else 'no'} |"
        )

    findings = [row for row in report.campaigns if row.pair_error]
    lines.extend(["", "## SUT Contract Findings", ""])
    if findings:
        for row in findings:
            lines.append(f"- `{row.campaign_id}`: {row.pair_error}")
    else:
        lines.append("- None")
    return "\n".join(lines) + "\n"


def main() -> None:
    report = build_report()
    OUTPUT_JSON.write_text(
        json.dumps(report.model_dump(mode="json"), indent=2) + "\n",
        encoding="utf-8",
    )
    OUTPUT_MD.write_text(markdown_report(report), encoding="utf-8")
    print(f"Wrote {OUTPUT_JSON}")
    print(f"Wrote {OUTPUT_MD}")


if __name__ == "__main__":
    main()
