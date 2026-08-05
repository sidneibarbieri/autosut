#!/usr/bin/env python3
"""
Campaign Batch Runner

Executes campaigns multiple times and collects results.
Supports both Docker and Vagrant environments.

Usage:
    python3 run_campaign_batch.py --campaign <name> --runs <n>
    python3 run_campaign_batch.py --all --runs <n>

Example:
    python3 run_campaign_batch.py --campaign solarwinds --runs 10
"""

import argparse
import json
import sys
import yaml
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from campaign_runner import CampaignRunner
from campaign_analyzer import CampaignAnalyzer


# Configuration
SCRIPT_DIR = Path(__file__).parent
RESULTS_DIR = SCRIPT_DIR / "results" / "executions"
WORKSPACE_ROOT = Path(__file__).resolve().parents[4]
STICKS_ROOT = Path(__file__).resolve().parents[3]
CALDERA_ADVERSARIES_DIR = STICKS_ROOT / "data" / "caldera_adversaries"


def load_campaign(campaign_name: str) -> Dict[str, Any]:
    """Load campaign YAML file."""
    campaign_file = CALDERA_ADVERSARIES_DIR / f"{campaign_name}.yml"

    if not campaign_file.exists():
        raise FileNotFoundError(f"Campaign not found: {campaign_file}")

    with open(campaign_file) as file:
        return yaml.safe_load(file)


def print_header(campaign_name: str, num_runs: int) -> None:
    """Print execution header."""
    print(f"\n{'='*60}")
    print(f"Campaign: {campaign_name}")
    print(f"Runs: {num_runs}")
    print(f"{'='*60}")


def print_summary(results: List[Dict]) -> None:
    """Print execution summary."""
    total_runs = len(results)
    successful_runs = sum(1 for r in results if r["success"])
    avg_time = sum(r["execution_time_seconds"] for r in results) / total_runs

    print(f"\n{'='*60}")
    print(f"SUMMARY")
    print(f"{'='*60}")
    print(f"  Total runs: {total_runs}")
    print(f"  Successful: {successful_runs} ({successful_runs/total_runs*100:.1f}%)")
    print(f"  Failed: {total_runs - successful_runs}")
    print(f"  Avg time: {avg_time:.1f}s")
    print(f"{'='*60}")


def save_results(campaign_name: str, results: List[Dict], num_runs: int) -> None:
    """Save execution results to file."""
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    output_file = RESULTS_DIR / f"{campaign_name}_executions.json"

    with open(output_file, "w") as file:
        json.dump({
            "campaign": campaign_name,
            "num_runs": num_runs,
            "results": results,
        }, file, indent=2)

    print(f"\n[+] Results saved to: {output_file}")


def run_campaign(campaign_name: str, num_runs: int) -> List[Dict]:
    """Execute a single campaign multiple times."""
    # Load campaign
    campaign_data = load_campaign(campaign_name)

    # Analyze Linux coverage
    analyzer = CampaignAnalyzer(campaign_data)
    coverage = analyzer.analyze_linux_coverage()

    print(f"\nCampaign Analysis:")
    print(f"  Total abilities: {coverage['total_abilities']}")
    print(f"  Linux executors: {coverage['linux']} ({coverage['linux_percentage']:.1f}%)")
    print(f"  Windows executors: {coverage['windows']}")

    # Execute runs
    runner = CampaignRunner(campaign_data, num_runs)
    results = runner.run()

    # Save and summarize
    save_results(campaign_name, results, num_runs)
    print_summary(results)

    return results


def run_all_campaigns(campaigns: List[str], num_runs: int) -> None:
    """Execute all campaigns."""
    for campaign in campaigns:
        run_campaign(campaign, num_runs)
        print()


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--campaign",
        type=str,
        help="Campaign name (without .yml)"
    )
    parser.add_argument(
        "--runs",
        type=int,
        default=10,
        help="Number of runs"
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Run all campaigns"
    )

    args = parser.parse_args()

    if args.all:
        campaigns = [
            "0.solarwinds_compromise",
            "0.operation_wocao",
            "0.operation_dream_job",
            "0.sharepoint_toolshell_exploitation",
            "0.c0015",
        ]
        run_all_campaigns(campaigns, args.runs)

    elif args.campaign:
        run_campaign(args.campaign, args.runs)

    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
