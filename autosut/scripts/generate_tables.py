#!/usr/bin/env python3
"""
Generate paper tables from the current published corpus and canonical evidence.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from loaders.campaign_loader import load_campaign

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PUBLISHED_CAMPAIGNS_DIR = PROJECT_ROOT / "campaigns"
EVIDENCE_DIR = PROJECT_ROOT / "release" / "evidence"
DASHBOARD_EVIDENCE_DIR = PROJECT_ROOT / "release" / "dashboard" / "data" / "evidence"


def list_published_campaigns() -> list[str]:
    """Return campaign IDs from the published JSON corpus."""
    return sorted(
        path.stem
        for path in PUBLISHED_CAMPAIGNS_DIR.glob("*.json")
        if not path.name.startswith("_")
    )


def get_latest_summary(campaign_id: str) -> dict | None:
    """Load the latest summary.json for a campaign, if present."""
    # Use timestamp-prefixed pattern to avoid matching longer campaign IDs
    # (e.g. "0.apt41_dust_*" must not match "0.apt41_dust_full_*")
    campaign_dirs = []
    for evidence_dir in (DASHBOARD_EVIDENCE_DIR, EVIDENCE_DIR):
        campaign_dirs = [
            d
            for d in evidence_dir.glob(f"{campaign_id}_*")
            if d.name[len(campaign_id) + 1 : len(campaign_id) + 9].isdigit()
        ]
        if campaign_dirs:
            break
    if not campaign_dirs:
        return None

    latest_dir = max(campaign_dirs, key=lambda path: path.name)
    summary_path = latest_dir / "summary.json"
    if not summary_path.exists():
        return None

    return json.loads(summary_path.read_text())


def generate_corpus_table() -> str:
    """Generate a corpus table for every published campaign."""
    campaigns = list_published_campaigns()

    table = "\\begin{table}[htbp]\n"
    table += "\\centering\n"
    table += "\\caption{Published AutoSUT Campaign Corpus}\n"
    table += "\\label{tab:corpus}\n"
    table += "\\begin{tabular}{lccc}\n"
    table += "\\toprule\n"
    table += "Campaign & Techniques & SUT Profile & Evidence \\\\\n"
    table += "\\midrule\n"

    for campaign_id in campaigns:
        campaign = load_campaign(campaign_id)
        evidence = "yes" if get_latest_summary(campaign_id) else "no"
        table += (
            f"{campaign_id} & {len(campaign.steps)} & "
            f"{campaign.sut_profile_id} & {evidence} \\\\\n"
        )

    table += "\\bottomrule\n"
    table += "\\end{tabular}\n"
    table += "\\end{table}\n"
    return table


def generate_fidelity_table() -> str:
    """Generate fidelity counts for every published campaign."""
    table = "\\begin{table}[htbp]\n"
    table += "\\centering\n"
    table += "\\caption{Declared Fidelity by Published Campaign}\n"
    table += "\\label{tab:fidelity}\n"
    table += "\\begin{tabular}{lccc}\n"
    table += "\\toprule\n"
    table += "Campaign & Faithful & Adapted & Inspired \\\\\n"
    table += "\\midrule\n"

    for campaign_id in list_published_campaigns():
        campaign = load_campaign(campaign_id)
        faithful = adapted = inspired = 0

        for step in campaign.steps:
            fidelity = step.expected_fidelity.value
            if fidelity == "faithful":
                faithful += 1
            elif fidelity == "adapted":
                adapted += 1
            elif fidelity == "inspired":
                inspired += 1

        table += f"{campaign_id} & {faithful} & {adapted} & {inspired} \\\\\n"

    table += "\\bottomrule\n"
    table += "\\end{tabular}\n"
    table += "\\end{table}\n"
    return table


def generate_execution_summary() -> str:
    """Generate execution summary from canonical release evidence."""
    table = "\\begin{table}[htbp]\n"
    table += "\\centering\n"
    table += "\\caption{Published Campaign Execution Results}\n"
    table += "\\label{tab:execution}\n"
    table += "\\begin{tabular}{lccc}\n"
    table += "\\toprule\n"
    table += "Campaign & Total & Successful & Success Rate \\\\\n"
    table += "\\midrule\n"

    row_count = 0
    for campaign_id in list_published_campaigns():
        summary = get_latest_summary(campaign_id)
        if summary is None:
            continue
        total = summary["total_techniques"]
        successful = summary["successful"]
        rate = 100.0 * successful / total if total else 0.0
        table += f"{campaign_id} & {total} & {successful} & {rate:.1f}\\% \\\\\n"
        row_count += 1

    if row_count == 0:
        table += "\\multicolumn{4}{c}{No canonical execution evidence found} \\\\\n"

    table += "\\bottomrule\n"
    table += "\\end{tabular}\n"
    table += "\\end{table}\n"
    return table


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate LaTeX tables for STICKS")
    parser.add_argument(
        "--output",
        default="results/tables",
        help="Output directory for generated tables",
    )
    parser.add_argument(
        "--format",
        choices=["latex", "json"],
        default="latex",
        help="Output format",
    )
    args = parser.parse_args()

    output_dir = PROJECT_ROOT / args.output
    output_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    tables = {
        "corpus": generate_corpus_table(),
        "fidelity": generate_fidelity_table(),
        "execution": generate_execution_summary(),
    }

    if args.format == "latex":
        for name, content in tables.items():
            file_path = output_dir / f"{name}_table.tex"
            file_path.write_text(content)
            print(f"Generated {file_path}")

        combined_file = output_dir / f"all_tables_{timestamp}.tex"
        with combined_file.open("w") as handle:
            handle.write("% STICKS Paper Tables\n")
            handle.write(f"% Generated: {datetime.now().isoformat()}\n\n")
            for name, content in tables.items():
                handle.write(f"% {name.upper()} TABLE\n")
                handle.write(content)
                handle.write("\n\n")
        print(f"Generated combined tables: {combined_file}")
        return

    json_file = output_dir / f"tables_summary_{timestamp}.json"
    json_file.write_text(
        json.dumps({"timestamp": timestamp, "tables": tables}, indent=2)
    )
    print(f"Generated JSON summary: {json_file}")


if __name__ == "__main__":
    main()
