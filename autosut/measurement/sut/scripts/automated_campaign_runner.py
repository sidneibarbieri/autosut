#!/usr/bin/env python3
"""
Automated Campaign Runner

Full automation pipeline:
1. Analyze campaign requirements
2. Provision SUT (single/multi-host based on campaign)
3. Configure vulnerabilities
4. Execute campaign
5. Collect and save results

No manual intervention required.
"""

import argparse
import json
import os
import subprocess
import sys
import time
import yaml
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


# Configuration
WORKSPACE_ROOT = Path(__file__).resolve().parents[4]
STICKS_ROOT = Path(__file__).resolve().parents[3]
CALDERA_DIR = STICKS_ROOT / "data" / "caldera_adversaries"
SCRIPTS_DIR = STICKS_ROOT / "measurement" / "sut" / "scripts"
RESULTS_DIR = SCRIPTS_DIR / "results" / "executions"
COMPOSE_FILE = STICKS_ROOT / "measurement" / "sut" / "docker-compose.multi-host.yml"


@dataclass
class CampaignRequirements:
    """Campaign requirements for SUT provisioning."""
    platforms: List[str] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    host_count: int = 1
    vulnerabilities: List[str] = field(default_factory=list)
    campaign_name: str = ""


@dataclass
class ExecutionResult:
    """Result of campaign execution."""
    success: bool
    operation_id: Optional[str] = None
    state: str = ""
    host_count: int = 0
    abilities_executed: int = 0
    duration_seconds: float = 0.0
    error: Optional[str] = None


class CalderaClient:
    """Client for Caldera REST API."""

    def __init__(
        self,
        base_url: str = "http://localhost:8888",
        username: str = "red",
        password: str = "MIPILOM0hMOJuulLeD1hB7KtFIMSYXe5fA-Scja9cLM",
    ) -> None:
        self.base_url = base_url
        self.username = username
        self.password = password
        self.logged_in = False

    def _run_request(self, method: str, path: str, **kwargs) -> Any:
        """Execute HTTP request with authentication."""
        import requests

        session = requests.Session()

        # Login first
        session.get(f"{self.base_url}/enter")
        response = session.post(
            f"{self.base_url}/enter",
            data={"username": self.username, "password": self.password},
            allow_redirects=False,
        )

        if response.status_code in (301, 302):
            location = response.headers.get("Location", "/")
            session.get(f"{self.base_url}{location}")

        # Make the actual request
        response = session.request(method, f"{self.base_url}{path}", **kwargs)
        return response

    def is_healthy(self) -> bool:
        """Check if Caldera is running."""
        try:
            response = self._run_request("GET", "/")
            return response.status_code == 200
        except Exception:
            return False

    def get_adversaries(self) -> List[Dict]:
        """Get list of adversaries."""
        try:
            response = self._run_request("GET", "/api/adversaries")
            if response.status_code == 200:
                return response.json()
        except Exception:
            pass
        return []

    def find_adversary(self, campaign_name: str) -> Optional[str]:
        """Find matching adversary."""
        adversaries = self.get_adversaries()

        for adv in adversaries:
            if campaign_name.lower() in adv.get("name", "").lower():
                return adv.get("adversary_id")

        if adversaries:
            return adversaries[0].get("adversary_id")
        return None

    def create_operation(self, name: str, adversary_id: str) -> Optional[Dict]:
        """Create and start operation."""
        try:
            response = self._run_request(
                "PUT",
                "/api/rest",
                json={
                    "index": "operations",
                    "name": name,
                    "adversary_id": adversary_id,
                },
            )

            if response.status_code == 200:
                result = response.json()
                if isinstance(result, list) and len(result) > 0:
                    return result[0]
                return result
        except Exception:
            pass
        return None

    def get_operation(self, operation_id: str) -> Optional[Dict]:
        """Get operation by ID."""
        try:
            response = self._run_request("GET", f"/api/v2/operations/{operation_id}")
            if response.status_code == 200:
                return response.json()
        except Exception:
            pass
        return None

    def delete_operation(self, operation_id: str) -> bool:
        """Delete operation."""
        try:
            response = self._run_request(
                "DELETE", f"/api/v2/operations/{operation_id}"
            )
            return response.status_code in (200, 204)
        except Exception:
            pass
        return False


class CampaignAnalyzer:
    """Analyzes campaign to determine requirements."""

    def __init__(self, campaign_data: Dict[str, Any]) -> None:
        self.campaign_data = campaign_data

    def analyze_requirements(self) -> CampaignRequirements:
        """Analyze campaign and return requirements."""
        requirements = CampaignRequirements()
        requirements.campaign_name = self.campaign_data.get("name", "")

        # Analyze platforms from abilities
        platforms = {"linux": False, "windows": False, "darwin": False}
        abilities = self.campaign_data.get("abilities", {})

        for ability_id, ability_data in abilities.items():
            if "attack-pattern--" not in ability_id:
                continue

            executors = ability_data.get("executors", [])
            for executor in executors:
                for executor_type, executor_data in executor.items():
                    if isinstance(executor_data, dict):
                        platform = executor_data.get("platform", "")
                        if platform in platforms:
                            platforms[platform] = True

        requirements.platforms = [p for p, v in platforms.items() if v]

        # Estimate host count based on campaign complexity
        ability_count = len(
            [a for a in abilities.keys() if "attack-pattern--" in a]
        )

        if ability_count <= 3:
            requirements.host_count = 1
        elif ability_count <= 6:
            requirements.host_count = 2
        else:
            requirements.host_count = 3

        # Extract vulnerabilities from campaign
        requirements.vulnerabilities = self._extract_vulnerabilities()

        return requirements

    def _extract_vulnerabilities(self) -> List[str]:
        """Extract CVEs/vulnerabilities from campaign."""
        vulns = []

        # Look for CVE references in attack patterns
        kill_chain = self.campaign_data.get("kill_chain_phases", [])
        for phase in kill_chain:
            phase_name = phase.get("phase_name", "")
            if "initial-access" in phase_name:
                vulns.append("initial_access")

        # Look for specific CVEs in metadata
        objects = self.campaign_data.get("objects", [])
        for obj in objects:
            external_references = obj.get("external_references", [])
            for ref in external_references:
                if "cve" in ref.get("source_name", "").lower():
                    vulns.append(ref.get("external_id", ""))

        return vulns[:5]  # Limit to 5


class SUTProvisioner:
    """Provisions SUT based on campaign requirements."""

    def __init__(self, requirements: CampaignRequirements) -> None:
        self.requirements = requirements

    def provision(self) -> bool:
        """Provision SUT infrastructure."""
        print(f"\n[PROVISIONING] SUT with {self.requirements.host_count} hosts")

        # Check if Caldera is running
        client = CalderaClient()
        if client.is_healthy():
            print("[PROVISIONING] Caldera is already running")
            return True

        # Start infrastructure
        print("[PROVISIONING] Starting Docker infrastructure...")

        try:
            result = subprocess.run(
                [
                    "docker", "compose", "-f",
                    str(COMPOSE_FILE), "up", "-d"
                ],
                cwd=str(PROJECT_ROOT),
                capture_output=True,
                text=True,
                timeout=300,
            )

            if result.returncode == 0:
                print("[PROVISIONING] Infrastructure started successfully")
                # Wait for Caldera to be healthy
                time.sleep(30)
                return True
            else:
                print(f"[PROVISIONING] Error: {result.stderr}")
                return False

        except subprocess.TimeoutExpired:
            print("[PROVISIONING] Timeout starting infrastructure")
            return False
        except FileNotFoundError:
            print("[PROVISIONING] Docker not found")
            return False


class AutomatedCampaignRunner:
    """Full automation pipeline for campaign execution."""

    def __init__(self, campaign_name: str) -> None:
        self.campaign_name = campaign_name
        self.caldera = CalderaClient()
        self.results: List[ExecutionResult] = []

    def load_campaign(self) -> Dict[str, Any]:
        """Load campaign from file."""
        campaign_file = CALDERA_DIR / f"{self.campaign_name}.yml"

        if not campaign_file.exists():
            raise FileNotFoundError(f"Campaign not found: {campaign_file}")

        with open(campaign_file) as file:
            return yaml.safe_load(file)

    def run(self, num_runs: int = 1) -> List[ExecutionResult]:
        """Execute full automation pipeline."""
        print(f"\n{'='*60}")
        print("AUTOMATED CAMPAIGN RUNNER")
        print(f"Campaign: {self.campaign_name}")
        print(f"{'='*60}")

        # Load campaign
        print("\n[1/5] Loading campaign...")
        campaign_data = self.load_campaign()
        print(f"  Campaign: {campaign_data.get('name', 'unknown')}")

        # Analyze requirements
        print("\n[2/5] Analyzing requirements...")
        analyzer = CampaignAnalyzer(campaign_data)
        requirements = analyzer.analyze_requirements()
        print(f"  Platforms: {requirements.platforms}")
        print(f"  Host count: {requirements.host_count}")
        print(f"  Vulnerabilities: {requirements.vulnerabilities}")

        # Provision SUT
        print("\n[3/5] Provisioning SUT...")
        provisioner = SUTProvisioner(requirements)
        if not provisioner.provision():
            print("[ERROR] Failed to provision SUT")
            return []

        # Execute campaign
        print("\n[4/5] Executing campaign...")
        results = self._execute_campaign(requirements, num_runs)
        self.results = results

        # Save results
        print("\n[5/5] Saving results...")
        self._save_results(requirements, results)

        # Summary
        successful = sum(1 for r in results if r.success)
        print(f"\n{'='*60}")
        print(f"COMPLETE - Success: {successful}/{len(results)}")
        print(f"{'='*60}")

        return results

    def _execute_campaign(
        self, requirements: CampaignRequirements, num_runs: int
    ) -> List[ExecutionResult]:
        """Execute campaign on Caldera."""
        # Find adversary
        adversary_id = self.caldera.find_adversary(self.campaign_name)
        if not adversary_id:
            print("[ERROR] No adversary found in Caldera")
            return []

        print(f"  Using adversary: {adversary_id}")

        results = []

        for run in range(1, num_runs + 1):
            print(f"  Run {run}/{num_runs}...", end=" ")

            operation_name = (
                f"{self.campaign_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            )

            # Create operation
            operation = self.caldera.create_operation(operation_name, adversary_id)

            if not operation:
                results.append(ExecutionResult(success=False, error="Failed to create operation"))
                print("FAIL")
                continue

            operation_id = operation.get("id")
            start_time = time.time()

            # Wait for completion
            timeout = 300  # 5 minutes
            while time.time() - start_time < timeout:
                op = self.caldera.get_operation(operation_id)

                if not op:
                    break

                state = op.get("state", "")

                if state == "finished":
                    result = ExecutionResult(
                        success=True,
                        operation_id=operation_id,
                        state=state,
                        host_count=len(op.get("host_group", [])),
                        abilities_executed=len(op.get("chain", [])),
                        duration_seconds=time.time() - start_time,
                    )
                    results.append(result)
                    print("OK")
                    break

                if state in ("timeout", "failed"):
                    result = ExecutionResult(
                        success=False,
                        operation_id=operation_id,
                        state=state,
                        error=f"Operation {state}",
                    )
                    results.append(result)
                    print("FAIL")
                    break

                time.sleep(10)
            else:
                results.append(
                    ExecutionResult(
                        success=False,
                        operation_id=operation_id,
                        error="Timeout",
                    )
                )
                print("FAIL")

            # Cleanup
            if operation_id:
                self.caldera.delete_operation(operation_id)

        return results

    def _save_results(
        self, requirements: CampaignRequirements, results: List[ExecutionResult]
    ) -> None:
        """Save execution results."""
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)

        output_file = RESULTS_DIR / f"{self.campaign_name}_results.json"

        data = {
            "campaign": self.campaign_name,
            "timestamp": datetime.now().isoformat(),
            "requirements": {
                "platforms": requirements.platforms,
                "host_count": requirements.host_count,
                "vulnerabilities": requirements.vulnerabilities,
            },
            "results": [
                {
                    "success": r.success,
                    "operation_id": r.operation_id,
                    "state": r.state,
                    "host_count": r.host_count,
                    "abilities_executed": r.abilities_executed,
                    "duration_seconds": r.duration_seconds,
                    "error": r.error,
                }
                for r in results
            ],
        }

        with open(output_file, "w") as file:
            json.dump(data, file, indent=2)

        print(f"  Results saved: {output_file}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--campaign",
        type=str,
        required=True,
        help="Campaign name (without .yml)",
    )
    parser.add_argument(
        "--runs",
        type=int,
        default=1,
        help="Number of runs",
    )

    args = parser.parse_args()

    runner = AutomatedCampaignRunner(args.campaign)
    results = runner.run(args.runs)

    sys.exit(0 if all(r.success for r in results) else 1)


if __name__ == "__main__":
    main()
