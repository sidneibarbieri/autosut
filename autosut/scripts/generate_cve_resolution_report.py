#!/usr/bin/env python3
"""Generate a deterministic report for campaign-linked CVE concretization."""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "src"))

from utils.cve_resolution import csv_rows, markdown_report, resolve_campaign_cves  # noqa: E402


RULES_PATH = ROOT_DIR / "data" / "cve_resolution_rules.yml"
CAMPAIGN_CVES_PATH = ROOT_DIR / "measurement" / "sut" / "scripts" / "results" / "audit" / "campaign_cves.csv"
CAMPAIGN_STRUCTURE_PATH = ROOT_DIR / "measurement" / "sut" / "scripts" / "results" / "audit" / "campaign_factual_structure.csv"
ATTACK_BUNDLE_PATH = ROOT_DIR / "measurement" / "sut" / "scripts" / "data" / "enterprise-attack.json"
RELEASE_JSON = ROOT_DIR / "release" / "cve_resolution_candidates.json"
RELEASE_MD = ROOT_DIR / "release" / "CVE_RESOLUTION_CANDIDATES.md"
RESULTS_JSON = ROOT_DIR / "results" / "cve_resolution_candidates.json"
RESULTS_MD = ROOT_DIR / "results" / "CVE_RESOLUTION_CANDIDATES.md"
AUDIT_CSV = ROOT_DIR / "measurement" / "sut" / "scripts" / "results" / "audit" / "cve_resolution_candidates.csv"


def _sanitize_source_paths(source_paths: dict[str, str]) -> dict[str, str]:
    sanitized: dict[str, str] = {}
    for name, raw_path in source_paths.items():
        path = Path(raw_path)
        try:
            sanitized[name] = path.resolve().relative_to(ROOT_DIR.resolve()).as_posix()
        except ValueError:
            sanitized[name] = raw_path
    return sanitized


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


def main() -> int:
    summary = resolve_campaign_cves(
        rules_path=RULES_PATH,
        campaign_cves_path=CAMPAIGN_CVES_PATH,
        campaign_structure_path=CAMPAIGN_STRUCTURE_PATH,
        attack_bundle_path=ATTACK_BUNDLE_PATH,
    )
    summary.generated_from = _sanitize_source_paths(summary.generated_from)

    RELEASE_JSON.parent.mkdir(parents=True, exist_ok=True)
    RESULTS_JSON.parent.mkdir(parents=True, exist_ok=True)
    RELEASE_JSON.write_text(summary.model_dump_json(indent=2), encoding="utf-8")
    markdown = markdown_report(summary).rstrip() + "\n"
    RELEASE_MD.write_text(markdown, encoding="utf-8")
    RESULTS_JSON.write_text(summary.model_dump_json(indent=2), encoding="utf-8")
    RESULTS_MD.write_text(markdown, encoding="utf-8")
    _write_csv(AUDIT_CSV, csv_rows(summary))

    totals = summary.totals
    print(f"[OK] Release JSON: {RELEASE_JSON}")
    print(f"[OK] Release Markdown: {RELEASE_MD}")
    print(f"[OK] JSON: {RESULTS_JSON}")
    print(f"[OK] Markdown: {RESULTS_MD}")
    print(f"[OK] Audit CSV: {AUDIT_CSV}")
    print(
        json.dumps(
            {
                "total_cve_positive_campaigns": totals.total_cve_positive_campaigns,
                "total_campaign_cve_pairs": totals.total_campaign_cve_pairs,
                "automatic_candidate_pairs": totals.automatic_candidate_pairs,
                "automatic_candidate_campaigns": totals.automatic_candidate_campaigns,
                "direct_attck_binding_pairs": totals.direct_attck_binding_pairs,
                "open_package_pairs": totals.open_package_pairs,
                "open_package_campaigns": totals.open_package_campaigns,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
