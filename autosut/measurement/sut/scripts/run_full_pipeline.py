#!/usr/bin/env python3
"""
Full Campaign Execution Pipeline

Complete automation for:
1. Infrastructure provisioning (Docker/Vagrant)
2. Agent deployment to targets
3. Campaign execution
4. Results collection

Usage:
    python3 run_full_pipeline.py --campaign 0.solarwinds_compromise
    python3 run_full_pipeline.py --infra docker --campaign 0.apt28_nearest_neighbor_campaign
"""

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

# Configuration
WORKSPACE_ROOT = Path(__file__).resolve().parents[4]
STICKS_ROOT = Path(__file__).resolve().parents[3]
SCRIPTS_DIR = STICKS_ROOT / "measurement" / "sut" / "scripts"
CALDERA_DIR = STICKS_ROOT / "data" / "caldera_adversaries"
RESULTS_DIR = SCRIPTS_DIR / "results"
SANDBOX_DIR = RESULTS_DIR / "sandbox"
SANDBOX_DIR.mkdir(parents=True, exist_ok=True)

# Default Caldera credentials
DEFAULT_CREDENTIALS = {
    "host": "localhost",
    "port": 8889,
    "username": "red",
    "password": "BgbJ-PzikRWCp3BMpkg3PXUIz_RCyBaw6r2JeeGkdBI",
}


class InfrastructureManager:
    """Manages infrastructure provisioning (Docker/Vagrant)."""

    def __init__(self, infra_type: str) -> None:
        self.infra_type = infra_type

    def start(self) -> bool:
        """Start infrastructure."""
        print(f"[INFRA] Starting {self.infra_type} infrastructure...")

        if self.infra_type == "docker":
            return self._start_docker()
        elif self.infra_type == "vagrant":
            return self._start_vagrant()

        raise ValueError(f"Unknown infrastructure: {self.infra_type}")

    def stop(self) -> bool:
        """Stop infrastructure."""
        print(f"[INFRA] Stopping {self.infra_type} infrastructure...")

        if self.infra_type == "docker":
            return self._stop_docker()
        elif self.infra_type == "vagrant":
            return self._stop_vagrant()

        raise ValueError(f"Unknown infrastructure: {self.infra_type}")

    def _start_docker(self) -> bool:
        """Start Docker Compose infrastructure."""
        compose_file = STICKS_ROOT / "measurement" / "sut" / "docker-compose.multi-host.yml"

        if not compose_file.exists():
            print(f"[INFRA] Compose file not found: {compose_file}")
            return False

        try:
            subprocess.run(
                ["docker", "compose", "-f", str(compose_file), "up", "-d"],
                check=True,
                capture_output=True,
            )
            print("[INFRA] Docker infrastructure started")
            return True
        except subprocess.CalledProcessError as e:
            print(f"[INFRA] Docker start failed: {e.stderr}")
            return False

    def _stop_docker(self) -> bool:
        """Stop Docker Compose infrastructure."""
        compose_file = STICKS_ROOT / "measurement" / "sut" / "docker-compose.multi-host.yml"

        try:
            subprocess.run(
                ["docker", "compose", "-f", str(compose_file), "down"],
                check=True,
                capture_output=True,
            )
            return True
        except subprocess.CalledProcessError:
            return False

    def _start_vagrant(self) -> bool:
        """Start Vagrant infrastructure."""
        vagrant_file = STICKS_ROOT / "measurement" / "sut" / "Vagrantfile"

        if not vagrant_file.exists():
            print(f"[INFRA] Vagrantfile not found: {vagrant_file}")
            return False

        os.chdir(STICKS_ROOT / "measurement" / "sut")

        try:
            subprocess.run(["vagrant", "up"], check=True, capture_output=True)
            print("[INFRA] Vagrant infrastructure started")
            return True
        except subprocess.CalledProcessError as e:
            print(f"[INFRA] Vagrant start failed: {e.stderr}")
            return False

    def _stop_vagrant(self) -> bool:
        """Stop Vagrant infrastructure."""
        os.chdir(PROJECT_ROOT / "measurement" / "sut")

        try:
            subprocess.run(["vagrant", "destroy", "-f"], check=True, capture_output=True)
            return True
        except subprocess.CalledProcessError:
            return False


class CalderaClient:
    """Client for Caldera API interaction."""

    def __init__(self, host: str, port: int, username: str, password: str) -> None:
        self.base_url = f"http://{host}:{port}"
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.session.headers.update({"Content-Type": "application/json"})

    def login(self) -> bool:
        """Login to Caldera."""
        try:
            # First attempt to see if we get a redirect
            response = self.session.post(
                f"{self.base_url}/enter",
                data={"username": self.username, "password": self.password},
                allow_redirects=False,
            )

            # If 302, it usually means successful login redirecting to dashboard
            if response.status_code in [200, 302]:
                print(f"[CALDERA] Login successful (Status: {response.status_code})")
                return True

            print(f"[CALDERA] Login failed (Status: {response.status_code})")
            return False
        except requests.RequestException as e:
            print(f"[CALDERA] Connection error during login: {e}")
            return False

    def get_agents(self) -> List[Dict[str, Any]]:
        """Get all agents."""
        try:
            response = self.session.get(f"{self.base_url}/api/v2/agents")
            if response.status_code == 200:
                return response.json()
            return []
        except requests.RequestException:
            return []

    def get_adversaries(self) -> List[Dict[str, Any]]:
        """Get all adversaries."""
        try:
            response = self.session.get(f"{self.base_url}/api/v2/adversaries")
            if response.status_code == 200:
                return response.json()
            return []
        except requests.RequestException:
            return []

    def create_operation(
        self,
        name: str,
        adversary_id: str,
        host_group: List[str],
    ) -> Optional[Dict[str, Any]]:
        """Create and start an operation."""
        payload = {
            "index": "operations",
            "name": name,
            "adversary_id": adversary_id,
            "host_group": host_group,
        }

        try:
            response = self.session.put(
                f"{self.base_url}/api/rest",
                json=payload,
            )
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, list) and len(data) > 0:
                    return data[0]
                return data
            return None
        except requests.RequestException:
            return None

    def get_operation(self, name: str) -> Optional[Dict[str, Any]]:
        """Get operation by name."""
        try:
            response = self.session.get(f"{self.base_url}/api/v2/operations")
            if response.status_code == 200:
                operations = response.json()
                for op in operations:
                    if op.get("name") == name:
                        return op
            return None
        except requests.RequestException:
            return None


class AgentDeployer:
    """Manages agent deployment to targets."""

    def __init__(self, caldera_client: CalderaClient) -> None:
        self.caldera = caldera_client

    def deploy_to_docker(self, target_container: str, server_url: str, group: str) -> bool:
        """Deploy agent to Docker container."""
        print(f"[AGENT] Deploying to {target_container}...")

        # Copy agent binary to container
        try:
            subprocess.run(
                ["docker", "cp", "/tmp/sandcat_linux", f"{target_container}:/tmp/sandcat"],
                check=True,
                capture_output=True,
            )
        except subprocess.CalledProcessError:
            print(f"[AGENT] Failed to copy agent to {target_container}")
            return False

        # Execute agent
        try:
            subprocess.run(
                [
                    "docker", "exec", "-d", target_container,
                    "/tmp/sandcat", "-server", server_url, "-group", group, "-v",
                ],
                check=True,
                capture_output=True,
            )
            print(f"[AGENT] Agent deployed to {target_container}")
            return True
        except subprocess.CalledProcessError:
            print(f"[AGENT] Failed to execute agent in {target_container}")
            return False


class CampaignExecutor:
    """Executes campaigns and collects results."""

    def __init__(self, caldera_client: CalderaClient) -> None:
        self.caldera = caldera_client
        self.campaigns_dir = CALDERA_DIR

    def find_adversary_by_name(self, campaign_name: str) -> Optional[str]:
        """Find adversary ID by campaign name."""
        adversaries = self.caldera.get_adversaries()

        # Try exact match
        for adv in adversaries:
            if campaign_name.lower() in adv.get("name", "").lower():
                return adv.get("adversary_id")

        # Try file-based match
        campaign_file = self.campaigns_dir / f"{campaign_name}.yml"
        if campaign_file.exists():
            # Return default adversary for file-based campaigns
            return "50855e29-3b4e-4562-aa55-b3d7f93c26b8"  # Alice 2.0

        return None

    def execute(
        self,
        campaign_name: str,
        agents: List[str],
        wait_seconds: int = 30,
    ) -> Dict[str, Any]:
        """Execute a campaign."""
        print(f"[CAMPAIGN] Executing: {campaign_name}")

        # Find adversary
        adversary_id = self.find_adversary_by_name(campaign_name)
        if not adversary_id:
            print(f"[CAMPAIGN] Could not find adversary for: {campaign_name}")
            return {"success": False, "error": "adversary not found"}

        # Create operation
        operation_name = f"exp_{campaign_name}_{int(time.time())}"
        operation = self.caldera.create_operation(
            name=operation_name,
            adversary_id=adversary_id,
            host_group=agents,
        )

        if not operation:
            print(f"[CAMPAIGN] Failed to create operation")
            return {"success": False, "error": "operation creation failed"}

        print(f"[CAMPAIGN] Operation created: {operation_name}")
        print(f"[CAMPAIGN] Waiting {wait_seconds}s for execution...")

        # Wait for execution
        time.sleep(wait_seconds)

        # Get results
        result = self.caldera.get_operation(operation_name)

        return {
            "success": True,
            "operation_name": operation_name,
            "state": result.get("state") if result else "unknown",
            "host_count": len(result.get("host_group", [])) if result else 0,
            "details": result,
        }


def run_pipeline(
    campaign_name: str,
    infra_type: str = "docker",
    num_runs: int = 1,
) -> Dict[str, Any]:
    """Run full pipeline."""
    print(f"\n{'='*60}")
    print(f"Full Campaign Execution Pipeline")
    print(f"Campaign: {campaign_name}")
    print(f"Infrastructure: {infra_type}")
    print(f"{'='*60}\n")

    # Track results
    results = {
        "campaign": campaign_name,
        "infrastructure": infra_type,
        "timestamp": datetime.now().isoformat(),
        "runs": [],
    }

    # Initialize infrastructure
    infra = InfrastructureManager(infra_type)

    # For Docker, check if Caldera is already running
    caldera_running = False
    if infra_type == "docker":
        result = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}"],
            capture_output=True,
            text=True,
        )
        caldera_running = "friendly_liskov" in result.stdout or "caldera_server" in result.stdout

    if not caldera_running:
        print("[INFRA] Starting Caldera...")
        if not infra.start():
            print("[ERROR] Failed to start infrastructure")
            return {"success": False, "error": "infrastructure failed"}

    # Connect to Caldera
    caldera = CalderaClient(
        host=DEFAULT_CREDENTIALS["host"],
        port=DEFAULT_CREDENTIALS["port"],
        username=DEFAULT_CREDENTIALS["username"],
        password=DEFAULT_CREDENTIALS["password"],
    )

    if not caldera.login():
        print("[ERROR] Failed to login to Caldera")
        return {"success": False, "error": "caldera login failed"}

    print("[CALDERA] Connected successfully")

    # Get agents
    agents = caldera.get_agents()
    print(f"[AGENTS] Found {len(agents)} agents")

    if len(agents) == 0:
        print("[AGENTS] No agents found. Attempting auto-deployment...")
        deployer = AgentDeployer(caldera)
        # Try to deploy to target-1 and target-2 which should be in the docker-compose
        targets = ["target_linux_1", "target_linux_2", "target_linux_3"]
        server_url = f"http://{DEFAULT_CREDENTIALS['host']}:{DEFAULT_CREDENTIALS['port']}"

        deployed_count = 0
        for target in targets:
            if deployer.deploy_to_docker(target, server_url, "red"):
                deployed_count += 1

        if deployed_count > 0:
            print(f"[AGENTS] Deployed to {deployed_count} targets. Waiting for registration...")
            time.sleep(15)
            agents = caldera.get_agents()
            print(f"[AGENTS] Found {len(agents)} agents after deployment")

    if len(agents) == 0:
        print("[ERROR] No agents available after deployment attempt")
        return {"success": False, "error": "no agents"}

    # Extract agent PAWs
    agent_paws = [a.get("paw") for a in agents if a.get("paw")]

    # Execute campaigns
    executor = CampaignExecutor(caldera)

    for run_idx in range(num_runs):
        print(f"\n[RUN] {run_idx + 1}/{num_runs}")

        result = executor.execute(campaign_name, agent_paws)
        results["runs"].append(result)

        if run_idx < num_runs - 1:
            time.sleep(5)  # Delay between runs

    # Summary
    successful = sum(1 for r in results["runs"] if r.get("success"))
    print(f"\n{'='*60}")
    print(f"COMPLETE - Success: {successful}/{num_runs}")
    print(f"{'='*60}")

    # Save results
    output_file = SANDBOX_DIR / f"{campaign_name}_results.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\n[RESULTS] Saved to: {output_file}")

    return results


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--campaign",
        type=str,
        required=True,
        help="Campaign name to execute",
    )
    parser.add_argument(
        "--infra",
        type=str,
        choices=["docker", "vagrant"],
        default="docker",
        help="Infrastructure type",
    )
    parser.add_argument(
        "--runs",
        type=int,
        default=1,
        help="Number of runs",
    )

    args = parser.parse_args()

    result = run_pipeline(args.campaign, args.infra, args.runs)

    sys.exit(0 if result.get("success") else 1)


if __name__ == "__main__":
    main()
