#!/usr/bin/env python3
"""
Campaign Orchestrator

Full pipeline:
1. Analyze campaign requirements
2. Provision SUT (single or multi-host)
3. Filter Linux executors
4. Execute campaign
5. Collect results
"""

import argparse
import json
import subprocess
import sys
import yaml
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from campaign_analyzer import CampaignAnalyzer
from campaign_runner import CampaignRunner
from sut_provisioner import SUTProvisioner


# Configuration
WORKSPACE_ROOT = Path(__file__).resolve().parents[4]
STICKS_ROOT = Path(__file__).resolve().parents[3]
SCRIPTS_DIR = STICKS_ROOT / "measurement" / "sut" / "scripts"
CALDERA_DIR = STICKS_ROOT / "data" / "caldera_adversaries"
RESULTS_DIR = SCRIPTS_DIR / "results" / "executions"


class CampaignOrchestrator:
    """Orchestrates full campaign execution pipeline."""

    def __init__(self, campaign_name: str, num_runs: int = 10) -> None:
        self.campaign_name = campaign_name
        self.num_runs = num_runs
        self.campaign_data: Dict[str, Any] = {}
        self.results: List[Dict] = []

    def load_campaign(self) -> Dict[str, Any]:
        """Load campaign from file."""
        campaign_file = CALDERA_DIR / f"{self.campaign_name}.yml"

        if not campaign_file.exists():
            raise FileNotFoundError(f"Campaign not found: {campaign_file}")

        with open(campaign_file) as file:
            return yaml.safe_load(file)

    def analyze_requirements(self) -> Dict[str, Any]:
        """Analyze campaign requirements."""
        print("\n[1/5] Analyzing campaign requirements...")

        provisioner = SUTProvisioner(self.campaign_data)
        requirements = provisioner.detect_requirements()

        print(f"  Platforms: {requirements['platforms']}")
        print(f"  Services: {requirements['services']}")
        print(f"  Host count: {requirements['host_count']}")
        print(f"  SUT type: {'multi-host' if requirements['host_count'] > 2 else 'single-host'}")

        return requirements

    def provision_sut(self, requirements: Dict[str, Any]) -> None:
        """Provision SUT based on requirements."""
        print("\n[2/5] Provisioning SUT...")

        sut_type = "multi-host" if requirements["host_count"] > 2 else "single-host"
        print(f"  SUT type: {sut_type}")

        # Generate provisioning config
        provisioner = SUTProvisioner(self.campaign_data)
        config = provisioner.generate_provisioning_config()

        # Save config
        config_file = RESULTS_DIR / f"{self.campaign_name}_sut_config.yml"
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)

        with open(config_file, "w") as file:
            yaml.dump(config, file, default_flow_style=False)

        print(f"  Config saved: {config_file}")

        # Note: Actual Vagrant provisioning would happen here
        # For now, we document the requirements

    def filter_executors(self) -> None:
        """Filter to Linux-only executors."""
        print("\n[3/5] Filtering Linux executors...")

        analyzer = CampaignAnalyzer(self.campaign_data)
        coverage = analyzer.analyze_linux_coverage()

        print(f"  Total abilities: {coverage['total_abilities']}")
        print(f"  Linux executors: {coverage['linux']} ({coverage['linux_percentage']:.1f}%)")

        # In production, this would generate filtered YAML

    def execute_campaign(self) -> List[Dict]:
        """Execute campaign."""
        print("\n[4/5] Executing campaign...")

        runner = CampaignRunner(self.campaign_data, self.num_runs)
        results = runner.run()

        return results

    def save_results(self) -> None:
        """Save execution results."""
        print("\n[5/5] Saving results...")

        output_file = RESULTS_DIR / f"{self.campaign_name}_full_results.json"

        full_results = {
            "campaign": self.campaign_name,
            "timestamp": datetime.now().isoformat(),
            "num_runs": self.num_runs,
            "results": self.results,
        }

        with open(output_file, "w") as file:
            json.dump(full_results, file, indent=2)

        print(f"  Results saved: {output_file}")

    def run(self) -> Dict[str, Any]:
        """Execute full pipeline."""
        print(f"\n{'='*60}")
        print(f"Campaign Orchestrator")
        print(f"Campaign: {self.campaign_name}")
        print(f"Runs: {self.num_runs}")
        print(f"{'='*60}")

        # Load campaign
        self.campaign_data = self.load_campaign()

        # Pipeline
        requirements = self.analyze_requirements()
        self.provision_sut(requirements)
        self.filter_executors()
        self.results = self.execute_campaign()
        self.save_results()

        # Summary
        successful = sum(1 for r in self.results if r["success"])
        print(f"\n{'='*60}")
        print(f"COMPLETE - Success: {successful}/{len(self.results)}")
        print(f"{'='*60}")

        return {
            "campaign": self.campaign_name,
            "requirements": requirements,
            "results": self.results,
        }


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--campaign",
        type=str,
        required=True,
        help="Campaign name (without .yml)"
    )
    parser.add_argument(
        "--runs",
        type=int,
        default=10,
        help="Number of runs"
    )

    args = parser.parse_args()

    orchestrator = CampaignOrchestrator(args.campaign, args.runs)
    orchestrator.run()


if __name__ == "__main__":
    main()
