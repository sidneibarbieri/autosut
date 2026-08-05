#!/usr/bin/env python3
"""
Generate an honest corpus-state report for the published and executable subsets.
"""

from __future__ import annotations

import json
import re
import sys
from datetime import datetime
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
CAMPAIGNS_DIR = PROJECT_ROOT / "campaigns"
SUT_DIR = PROJECT_ROOT / "data" / "sut_profiles"
EVIDENCE_DIR = PROJECT_ROOT / "release" / "evidence"
DASHBOARD_EVIDENCE_DIR = PROJECT_ROOT / "release" / "dashboard" / "data" / "evidence"
MITRE_AUDIT = PROJECT_ROOT / "results" / "mitre_metadata_audit.json"
HOST_LEAKAGE = PROJECT_ROOT / "results" / "host_leakage_audit.json"
OUTPUT_JSON = PROJECT_ROOT / "results" / "corpus_state.json"
OUTPUT_MD = PROJECT_ROOT / "results" / "CORPUS_STATE.md"
TIMESTAMP_SUFFIX = re.compile(r"\d{8}_\d{6}$")


def display_path(path: Path) -> str:
    try:
        return str(path.relative_to(PROJECT_ROOT))
    except ValueError:
        return str(path)


def _load_validation_helper():
    sys.path.insert(0, str(PROJECT_ROOT / "src"))
    from loaders.campaign_loader import validate_campaign_sut_pair  # type: ignore

    return validate_campaign_sut_pair


def evidence_dirs_for_campaign(campaign_id: str) -> list[Path]:
    prefix = f"{campaign_id}_"
    for evidence_dir in (DASHBOARD_EVIDENCE_DIR, EVIDENCE_DIR):
        matches: list[Path] = []
        if not evidence_dir.exists():
            continue
        for candidate in evidence_dir.iterdir():
            if not candidate.is_dir():
                continue
            if not candidate.name.startswith(prefix):
                continue
            suffix = candidate.name[len(prefix) :]
            if TIMESTAMP_SUFFIX.fullmatch(suffix):
                matches.append(candidate)
        if matches:
            return matches
    return []


def latest_summary(campaign_id: str) -> dict | None:
    candidates = evidence_dirs_for_campaign(campaign_id)
    candidates_with_summary = [
        candidate for candidate in candidates if (candidate / "summary.json").exists()
    ]
    if not candidates_with_summary:
        return None
    latest_dir = max(candidates_with_summary, key=lambda path: path.name)
    summary_path = latest_dir / "summary.json"
    summary = json.loads(summary_path.read_text())
    total = summary.get("total_techniques", 0)
    successful = summary.get("successful", 0)
    return {
        "evidence_dir": display_path(latest_dir),
        "total_techniques": total,
        "successful": successful,
        "failed": summary.get("failed", 0),
        "success_rate": successful / total if total else 0.0,
    }


def build_report() -> dict:
    published = sorted(path.stem for path in CAMPAIGNS_DIR.glob("*.json"))
    sut_profiles = {path.stem for path in SUT_DIR.glob("*.yml")}
    validate_campaign_sut_pair = _load_validation_helper()
    mitre = json.loads(MITRE_AUDIT.read_text()) if MITRE_AUDIT.exists() else {}
    host_leakage = json.loads(HOST_LEAKAGE.read_text()) if HOST_LEAKAGE.exists() else {}

    mitre_by_campaign = {
        item["campaign_id"]: item for item in mitre.get("campaigns", [])
    }
    leakage_by_campaign = {
        item["campaign_id"]: item for item in host_leakage.get("campaigns", [])
    }

    campaign_rows = []
    for campaign_id in published:
        summary = latest_summary(campaign_id)
        has_sut = campaign_id in sut_profiles
        pair_error = ""
        pair_valid = False
        if has_sut:
            pair_error = validate_campaign_sut_pair(campaign_id) or ""
            pair_valid = pair_error == ""
        row = {
            "campaign_id": campaign_id,
            "published": True,
            "has_sut": has_sut,
            "pair_valid": pair_valid,
            "pair_error": pair_error,
            "has_latest_evidence": summary is not None,
            "latest_execution": summary,
            "mitre_metadata_clean": (
                mitre_by_campaign.get(campaign_id, {}).get("steps_with_missing_metadata", 1)
                == 0
                and mitre_by_campaign.get(campaign_id, {}).get("steps_with_tactic_mismatch", 1)
                == 0
                and mitre_by_campaign.get(campaign_id, {}).get("steps_without_mitre_support", 1)
                == 0
            ),
            "host_leakage_detected": leakage_by_campaign.get(campaign_id, {}).get(
                "host_leakage_detected", False
            ),
        }
        campaign_rows.append(row)

    executable_subset = [row for row in campaign_rows if row["has_sut"]]
    evidenced_subset = [row for row in campaign_rows if row["has_latest_evidence"]]
    successful_subset = [
        row
        for row in evidenced_subset
        if row["latest_execution"] and row["latest_execution"]["failed"] == 0
    ]

    return {
        "generated_at": datetime.now().isoformat(),
        "published_campaigns": len(campaign_rows),
        "executable_campaigns_with_sut": len(executable_subset),
        "campaigns_with_strict_pair_validation": sum(
            1 for row in campaign_rows if row["pair_valid"]
        ),
        "campaigns_with_latest_evidence": len(evidenced_subset),
        "campaigns_with_zero_failed_in_latest_evidence": len(successful_subset),
        "mitre_metadata_clean_campaigns": sum(
            1 for row in campaign_rows if row["mitre_metadata_clean"]
        ),
        "campaigns_without_host_leakage": sum(
            1 for row in evidenced_subset if not row["host_leakage_detected"]
        ),
        "campaigns": campaign_rows,
    }


def write_markdown(report: dict) -> None:
    lines = [
        "# Corpus State",
        "",
        f"- Generated at: `{report['generated_at']}`",
        f"- Published campaigns: `{report['published_campaigns']}`",
        f"- Executable campaigns with SUT profile: `{report['executable_campaigns_with_sut']}`",
        f"- Campaign/SUT pairs passing strict validation: `{report['campaigns_with_strict_pair_validation']}`",
        f"- Campaigns with latest evidence: `{report['campaigns_with_latest_evidence']}`",
        f"- Campaigns with zero failed techniques in latest evidence: `{report['campaigns_with_zero_failed_in_latest_evidence']}`",
        f"- Campaigns with clean MITRE metadata audit: `{report['mitre_metadata_clean_campaigns']}`",
        f"- Campaigns without host leakage in latest evidence: `{report['campaigns_without_host_leakage']}`",
        "",
        "## Campaign Status",
        "",
        "| Campaign | SUT | Pair Valid | Evidence | Latest Success | MITRE Clean | Host Leakage |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]

    for row in report["campaigns"]:
        latest = row["latest_execution"]
        latest_rate = (
            f"{latest['successful']}/{latest['total_techniques']} ({latest['success_rate']:.1%})"
            if latest
            else "none"
        )
        lines.append(
            f"| {row['campaign_id']} | {'yes' if row['has_sut'] else 'no'} | "
            f"{'yes' if row['pair_valid'] else 'no'} | "
            f"{'yes' if row['has_latest_evidence'] else 'no'} | {latest_rate} | "
            f"{'yes' if row['mitre_metadata_clean'] else 'no'} | "
            f"{'yes' if row['host_leakage_detected'] else 'no'} |"
        )

    invalid_rows = [row for row in report["campaigns"] if row["has_sut"] and not row["pair_valid"]]
    lines.extend(["", "## Validation Exceptions", ""])
    if invalid_rows:
        for row in invalid_rows:
            lines.append(f"- `{row['campaign_id']}`: {row['pair_error']}")
    else:
        lines.append("- None")

    OUTPUT_MD.write_text("\n".join(lines))


def main() -> None:
    report = build_report()
    OUTPUT_JSON.write_text(json.dumps(report, indent=2))
    write_markdown(report)
    print(f"Wrote {OUTPUT_JSON}")
    print(f"Wrote {OUTPUT_MD}")


if __name__ == "__main__":
    main()
