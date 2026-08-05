#!/usr/bin/env python3
"""Generate a campaign-SUT-fidelity matrix for the executable published subset."""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

TIMESTAMP_SUFFIX = re.compile(r"\d{8}_\d{6}$")


@dataclass(frozen=True)
class CampaignMatrixRow:
    campaign_id: str
    sut_profile_id: str
    pair_valid: bool
    pair_error: str
    has_latest_evidence: bool
    latest_evidence: str
    total_techniques: int
    successful: int
    failed: int
    skipped: int
    faithful: int
    adapted: int
    inspired: int
    rubric_total: int
    rubric_consistent: int
    rubric_mismatches: int
def _load_campaign_helpers(root_dir: Path):
    sys.path.insert(0, str(root_dir / "src"))
    from loaders.campaign_loader import (  # type: ignore
        list_campaigns,
        list_sut_profiles,
        load_campaign,
        validate_campaign_sut_pair,
    )

    return list_campaigns, list_sut_profiles, load_campaign, validate_campaign_sut_pair


def _matching_evidence_dirs(evidence_root: Path, campaign_id: str) -> list[Path]:
    prefix = f"{campaign_id}_"
    matches: list[Path] = []
    for candidate in evidence_root.iterdir():
        if not candidate.is_dir():
            continue
        if not candidate.name.startswith(prefix):
            continue
        suffix = candidate.name[len(prefix) :]
        if TIMESTAMP_SUFFIX.fullmatch(suffix):
            matches.append(candidate)
    return matches


def _latest_summary(evidence_root: Path, campaign_id: str) -> tuple[str, dict]:
    latest_dirs = _matching_evidence_dirs(evidence_root, campaign_id)
    if not latest_dirs:
        return "", {}
    latest_dir = max(latest_dirs, key=lambda path: path.name)
    summary_path = latest_dir / "summary.json"
    if not summary_path.exists():
        return latest_dir.name, {}
    return latest_dir.name, json.loads(summary_path.read_text(encoding="utf-8"))


def _build_rows(root_dir: Path) -> list[CampaignMatrixRow]:
    evidence_root = root_dir / "release" / "evidence"
    fidelity_report_path = root_dir / "release" / "fidelity_report.json"
    (
        list_campaigns,
        list_sut_profiles,
        load_campaign,
        validate_campaign_sut_pair,
    ) = _load_campaign_helpers(root_dir)

    fidelity_report = {"campaigns": {}}
    if fidelity_report_path.exists():
        fidelity_report = json.loads(fidelity_report_path.read_text(encoding="utf-8"))

    campaign_ids = sorted(set(list_campaigns()) & set(list_sut_profiles()))

    rows: list[CampaignMatrixRow] = []
    for campaign_id in campaign_ids:
        try:
            pair_error = validate_campaign_sut_pair(campaign_id)
        except FileNotFoundError as exc:
            pair_error = str(exc)
        campaign = load_campaign(campaign_id)
        latest_evidence, summary = _latest_summary(evidence_root, campaign_id)

        distribution = summary.get("fidelity_distribution", {})
        rubric_entry = fidelity_report.get("campaigns", {}).get(campaign_id, {})

        rows.append(
            CampaignMatrixRow(
                campaign_id=campaign_id,
                sut_profile_id=campaign.sut_profile_id,
                pair_valid=pair_error is None,
                pair_error=pair_error or "",
                has_latest_evidence=bool(latest_evidence and summary),
                latest_evidence=latest_evidence,
                total_techniques=int(summary.get("total_techniques", 0)),
                successful=int(summary.get("successful", 0)),
                failed=int(summary.get("failed", 0)),
                skipped=int(summary.get("skipped", 0)),
                faithful=int(distribution.get("faithful", 0)),
                adapted=int(distribution.get("adapted", 0)),
                inspired=int(distribution.get("inspired", 0)),
                rubric_total=int(rubric_entry.get("total", 0)),
                rubric_consistent=int(rubric_entry.get("consistent", 0)),
                rubric_mismatches=int(rubric_entry.get("mismatches", 0)),
            )
        )

    return rows


def _write_json(rows: list[CampaignMatrixRow], output_path: Path) -> None:
    payload = {
        "generated_from": (
            "published campaign + SUT intersection, latest release/evidence "
            "summaries, and release/fidelity_report.json"
        ),
        "campaigns": [row.__dict__ for row in rows],
    }
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _write_markdown(rows: list[CampaignMatrixRow], output_path: Path) -> None:
    lines = [
        "# Campaign-SUT-Fidelity Matrix",
        "",
        "Source of truth:",
        "- Published campaigns with a matching SUT profile only",
        "- Exact `<campaign_id>_YYYYMMDD_HHMMSS` evidence directory matching per campaign",
        "- `release/evidence/*/summary.json` (latest exact match per campaign)",
        "- `release/fidelity_report.json` (rubric consistency when available)",
        "- `src/loaders/campaign_loader.py` (`validate_campaign_sut_pair`)",
        "- Rows without shipped evidence are shown explicitly rather than treated as failed runs",
        "",
        "| Campaign | SUT Profile | Pair Valid | Evidence | Latest Evidence Dir | Total | Success | Failed | Skipped | Faithful | Adapted | Inspired | Rubric Total | Rubric Consistent | Rubric Mismatches |",
        "|---|---|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]

    for row in rows:
        total = str(row.total_techniques) if row.has_latest_evidence else "--"
        successful = str(row.successful) if row.has_latest_evidence else "--"
        failed = str(row.failed) if row.has_latest_evidence else "--"
        skipped = str(row.skipped) if row.has_latest_evidence else "--"
        faithful = str(row.faithful) if row.has_latest_evidence else "--"
        adapted = str(row.adapted) if row.has_latest_evidence else "--"
        inspired = str(row.inspired) if row.has_latest_evidence else "--"
        lines.append(
            "| `{campaign_id}` | `{sut_profile_id}` | {pair_valid} | {has_latest_evidence} | `{latest_evidence}` | {total_techniques} | {successful} | {failed} | {skipped} | {faithful} | {adapted} | {inspired} | {rubric_total} | {rubric_consistent} | {rubric_mismatches} |".format(
                campaign_id=row.campaign_id,
                sut_profile_id=row.sut_profile_id,
                pair_valid="yes" if row.pair_valid else "no",
                has_latest_evidence="yes" if row.has_latest_evidence else "no",
                latest_evidence=row.latest_evidence or "-",
                total_techniques=total,
                successful=successful,
                failed=failed,
                skipped=skipped,
                faithful=faithful,
                adapted=adapted,
                inspired=inspired,
                rubric_total=row.rubric_total,
                rubric_consistent=row.rubric_consistent,
                rubric_mismatches=row.rubric_mismatches,
            )
        )

    invalid_rows = [row for row in rows if not row.pair_valid]
    lines.extend(["", "## Pair Validation Exceptions", ""])
    if invalid_rows:
        for row in invalid_rows:
            lines.append(f"- `{row.campaign_id}`: {row.pair_error}")
    else:
        lines.append("- None")

    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    root_dir = Path(__file__).resolve().parent.parent
    release_dir = root_dir / "release"
    results_dir = root_dir / "results"
    release_dir.mkdir(parents=True, exist_ok=True)
    results_dir.mkdir(parents=True, exist_ok=True)

    rows = _build_rows(root_dir)

    release_json = release_dir / "campaign_sut_fidelity_matrix.json"
    release_md = release_dir / "CAMPAIGN_SUT_FIDELITY_MATRIX.md"
    results_json = results_dir / "campaign_sut_fidelity_matrix.json"
    results_md = results_dir / "CAMPAIGN_SUT_FIDELITY_MATRIX.md"

    _write_json(rows, release_json)
    _write_markdown(rows, release_md)
    _write_json(rows, results_json)
    _write_markdown(rows, results_md)

    print(f"[OK] Matrix JSON: {release_json}")
    print(f"[OK] Matrix Markdown: {release_md}")
    print(f"[OK] Matrix JSON mirror: {results_json}")
    print(f"[OK] Matrix Markdown mirror: {results_md}")
    print(f"[OK] Campaigns summarized: {len(rows)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
