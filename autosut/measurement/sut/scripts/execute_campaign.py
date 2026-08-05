#!/usr/bin/env python3
"""
Real Campaign Executor

Actually executes campaigns in Caldera and captures real results.
Requires Caldera server running.
"""

import json
import time
import requests
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


class CalderaClient:
    """Client for Caldera REST API with cookie-based auth."""

    def __init__(self, base_url: str = "http://localhost:8888",
                 username: str = "red",
                 password: str = "MIPILOM0hMOJuulLeD1hB7KtFIMSYXe5fA-Scja9cLM") -> None:
        self.base_url = base_url
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.logged_in = False

    def login(self) -> bool:
        """Authenticate with Caldera using cookie-based login."""
        try:
            # First get to establish session
            self.session.get(f"{self.base_url}/enter")

            # Then post with credentials - handle redirect manually
            response = self.session.post(
                f"{self.base_url}/enter",
                data={
                    "username": self.username,
                    "password": self.password
                },
                allow_redirects=False
            )

            # Follow redirect manually if needed
            if response.status_code in (301, 302):
                location = response.headers.get("Location", "/")
                self.session.get(f"{self.base_url}{location}")

            # Verify login worked - try API
            test_response = self.session.get(f"{self.base_url}/api/v2/adversaries")
            if test_response.status_code == 200:
                self.logged_in = True
                return True

        except Exception as e:
            print(f"Login error: {e}")

        return False

    def get_adversaries(self) -> List[Dict]:
        """Get list of adversaries from Caldera."""
        if not self.logged_in:
            return []

        try:
            response = self.session.get(f"{self.base_url}/api/adversaries")
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            print(f"Error getting adversaries: {e}")

        return []

    def create_operation(self, name: str, adversary_id: str) -> Optional[Dict]:
        """Create and start an operation."""
        if not self.logged_in:
            return None

        try:
            # The correct Caldera API uses PUT to /api/rest with index in body
            response = self.session.put(
                f"{self.base_url}/api/rest",
                json={
                    "index": "operations",
                    "name": name,
                    "adversary_id": adversary_id,
                }
            )

            print(f"  [API] Status: {response.status_code}")
            if response.status_code == 200:
                result = response.json()
                if isinstance(result, list) and len(result) > 0:
                    return result[0]
                return result

            print(f"  Response: {response.text[:200]}")

        except Exception as e:
            print(f"  Error: {e}")

        return None

    def get_operation_status(self, operation_id: str) -> Dict:
        """Get operation status."""
        if not self.logged_in:
            return {}

        try:
            response = self.session.get(
                f"{self.base_url}/api/v2/operations/{operation_id}"
            )
            if response.status_code == 200:
                return response.json()
        except Exception:
            pass

        return {}

    def wait_for_completion(self, operation_id: str, timeout: int = 300) -> Dict:
        """Wait for operation to complete."""
        start_time = time.time()

        while time.time() - start_time < timeout:
            status = self.get_operation_status(operation_id)
            state = status.get("state", "")

            if state in ["finished", "completed", "timeout"]:
                return status

            time.sleep(10)

        return {"error": "timeout", "state": "timeout"}


class RealCampaignExecutor:
    """Executes campaigns in real Caldera environment."""

    def __init__(self, caldera_url: str = "http://localhost:8888") -> None:
        self.caldera = CalderaClient(base_url=caldera_url)
        self.results: List[Dict] = []

    def load_campaign(self, campaign_file: Path) -> Dict:
        """Load campaign from file."""
        import yaml
        with open(campaign_file) as file:
            return yaml.safe_load(file)

    def find_matching_adversary(self, campaign_data: Dict) -> Optional[str]:
        """Find a matching adversary in Caldera or create one."""
        # Get list of existing adversaries
        adversaries = self.caldera.get_adversaries()

        campaign_name = campaign_data.get("name", "")

        # Look for matching adversary
        for adv in adversaries:
            if campaign_name.lower() in adv.get("name", "").lower():
                return adv.get("adversary_id")

        # Return default adversary if no match found
        if adversaries:
            return adversaries[0].get("adversary_id")

        return None

    def execute_campaign(self, campaign_name: str, campaign_data: Dict,
                        num_runs: int = 1) -> List[Dict]:
        """Execute campaign in real Caldera."""

        # Connect to Caldera
        if not self.caldera.login():
            print("[!] Failed to connect to Caldera")
            return []

        print(f"[+] Connected to Caldera")

        # Find adversary
        adversary_id = self.find_matching_adversary(campaign_data)
        if not adversary_id:
            print("[!] No adversary found in Caldera")
            return []

        print(f"[+] Using adversary: {adversary_id}")

        # Execute runs
        for run in range(num_runs):
            print(f"  Run {run + 1}/{num_runs}...", end=" ")

            try:
                # Create operation
                operation = self.caldera.create_operation(
                    f"{campaign_name}_run_{run + 1}",
                    adversary_id
                )

                if not operation:
                    print("FAIL (operation failed)")
                    continue

                operation_id = operation.get("id")

                # Wait for completion
                result = self.caldera.wait_for_completion(operation_id)

                self.results.append({
                    "run_id": run + 1,
                    "timestamp": datetime.now().isoformat(),
                    "operation_id": operation_id,
                    "success": result.get("state") == "finished",
                    "result": result,
                })

                print("OK")

            except Exception as e:
                print(f"FAIL ({str(e)})")

        return self.results


def main():
    """Main function."""
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign", required=True, help="Campaign name")
    parser.add_argument("--runs", type=int, default=1, help="Number of runs")
    parser.add_argument("--caldera-url", default="http://localhost:8888",
                       help="Caldera URL")

    args = parser.parse_args()

    # Load campaign
    sticks_root = Path(__file__).resolve().parents[3]
    campaign_file = sticks_root / "data" / "caldera_adversaries" / f"{args.campaign}.yml"

    if not campaign_file.exists():
        print(f"Error: Campaign not found: {campaign_file}")
        return

    with open(campaign_file) as file:
        import yaml
        campaign_data = yaml.safe_load(file)

    # Execute
    executor = RealCampaignExecutor(args.caldera_url)
    results = executor.execute_campaign(args.campaign, campaign_data, args.runs)

    print(f"\nResults: {len(results)}/{args.runs} successful")


if __name__ == "__main__":
    main()
