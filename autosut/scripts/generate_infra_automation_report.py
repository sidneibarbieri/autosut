#!/usr/bin/env python3
"""Generate infrastructure and SUT automation coverage reports."""

from __future__ import annotations

import csv
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from loaders.campaign_loader import (  # noqa: E402
    list_campaigns,
    list_sut_profiles,
    load_campaign,
    load_sut_profile,
    validate_campaign_sut_pair,
)
from utils.infra_automation import (  # noqa: E402
    build_infra_automation_summary,
    csv_rows,
    json_report,
    markdown_report,
)
from evaluation.canonical_operational_witness import (  # noqa: E402
    assess_caldera_dispatch_witness,
)


RELEASE_JSON = PROJECT_ROOT / "release" / "infra_automation_coverage.json"
RELEASE_MD = PROJECT_ROOT / "release" / "INFRA_AUTOMATION_COVERAGE.md"
RESULTS_JSON = PROJECT_ROOT / "results" / "infra_automation_coverage.json"
RESULTS_MD = PROJECT_ROOT / "results" / "INFRA_AUTOMATION_COVERAGE.md"
RESULTS_CSV = PROJECT_ROOT / "results" / "infra_automation_coverage.csv"


def _write_csv(path: Path, rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = list(rows[0].keys()) if rows else []
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=fieldnames,
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(rows)


def _bounded_dispatch_witness_campaign_ids() -> frozenset[str]:
    assessment = assess_caldera_dispatch_witness(PROJECT_ROOT)
    if assessment.status != "supported_bounded" or assessment.witness is None:
        raise RuntimeError(
            "canonical bounded dispatch witness is not supported: "
            f"{assessment.failure_reason or assessment.status}"
        )
    return frozenset({assessment.witness.campaign_id})


def main() -> int:
    campaign_ids = sorted(set(list_campaigns()) & set(list_sut_profiles()))
    summary = build_infra_automation_summary(
        campaign_ids=campaign_ids,
        load_campaign=load_campaign,
        load_sut_profile=load_sut_profile,
        validate_campaign_sut_pair=validate_campaign_sut_pair,
        bounded_dispatch_witness_campaign_ids=_bounded_dispatch_witness_campaign_ids(),
    )

    RELEASE_JSON.parent.mkdir(parents=True, exist_ok=True)
    RESULTS_JSON.parent.mkdir(parents=True, exist_ok=True)

    RELEASE_JSON.write_text(json_report(summary), encoding="utf-8")
    RELEASE_MD.write_text(markdown_report(summary) + "\n", encoding="utf-8")
    RESULTS_JSON.write_text(json_report(summary), encoding="utf-8")
    RESULTS_MD.write_text(markdown_report(summary) + "\n", encoding="utf-8")
    _write_csv(RESULTS_CSV, csv_rows(summary))

    totals = summary.totals
    print(f"[OK] Release JSON: {RELEASE_JSON}")
    print(f"[OK] Release Markdown: {RELEASE_MD}")
    print(f"[OK] Results JSON: {RESULTS_JSON}")
    print(f"[OK] Results Markdown: {RESULTS_MD}")
    print(f"[OK] Results CSV: {RESULTS_CSV}")
    print(
        {
            "published_campaigns": totals.published_campaigns,
            "pair_valid": totals.campaigns_with_strict_pair_validation,
            "single_target": totals.campaigns_with_single_target_host,
            "multi_target": totals.campaigns_with_multi_target_host,
            "multi_vm_runtime": totals.campaigns_with_multi_vm_runtime,
            "step_overlay_campaigns": totals.campaigns_with_step_overlays,
        }
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
