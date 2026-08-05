#!/usr/bin/env python3
"""
Real Campaign Runner

Executes campaigns on real Caldera server.
"""

import time
import requests
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


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
        self.session = requests.Session()
        self.logged_in = False

    def login(self) -> bool:
        """Authenticate with Caldera."""
        try:
            self.session.get(f"{self.base_url}/enter")

            response = self.session.post(
                f"{self.base_url}/enter",
                data={"username": self.username, "password": self.password},
                allow_redirects=False,
            )

            if response.status_code in (301, 302):
                location = response.headers.get("Location", "/")
                self.session.get(f"{self.base_url}{location}")

            test_response = self.session.get(f"{self.base_url}/api/v2/adversaries")
            if test_response.status_code == 200:
                self.logged_in = True
                return True

        except Exception:
            pass

        return False

    def get_adversaries(self) -> List[Dict]:
        """Get list of adversaries."""
        if not self.logged_in:
            return []

        try:
            response = self.session.get(f"{self.base_url}/api/adversaries")
            if response.status_code == 200:
                return response.json()
        except Exception:
            pass

        return []

    def create_operation(self, name: str, adversary_id: str) -> Optional[Dict]:
        """Create and start an operation."""
        if not self.logged_in:
            return None

        try:
            response = self.session.put(
                f"{self.base_url}/api/rest",
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
        if not self.logged_in:
            return None

        try:
            response = self.session.get(
                f"{self.base_url}/api/v2/operations/{operation_id}"
            )
            if response.status_code == 200:
                return response.json()
        except Exception:
            pass

        return None

    def delete_operation(self, operation_id: str) -> bool:
        """Delete an operation."""
        if not self.logged_in:
            return False

        try:
            response = self.session.delete(
                f"{self.base_url}/api/v2/operations/{operation_id}"
            )
            return response.status_code in (200, 204)
        except Exception:
            pass

        return False

    def get_operations(self) -> List[Dict]:
        """Get all operations."""
        if not self.logged_in:
            return []

        try:
            response = self.session.get(f"{self.base_url}/api/operations")
            if response.status_code == 200:
                return response.json()
        except Exception:
            pass

        return []


class RealCampaignRunner:
    """Executes campaigns on real Caldera."""

    def __init__(
        self,
        caldera_url: str = "http://localhost:8888",
    ) -> None:
        self.caldera = CalderaClient(base_url=caldera_url)
        self.results: List[Dict] = []

    def find_adversary(self, campaign_name: str) -> Optional[str]:
        """Find matching adversary in Caldera."""
        adversaries = self.caldera.get_adversaries()

        for adv in adversaries:
            if campaign_name.lower() in adv.get("name", "").lower():
                return adv.get("adversary_id")

        if adversaries:
            return adversaries[0].get("adversary_id")

        return None

    def run_single(
        self,
        campaign_name: str,
        adversary_id: str,
        timeout: int = 300,
    ) -> Dict[str, Any]:
        """Run a single campaign execution."""
        operation_name = f"{campaign_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        operation = self.caldera.create_operation(operation_name, adversary_id)

        if not operation:
            return {
                "success": False,
                "error": "Failed to create operation",
                "operation_id": None,
            }

        operation_id = operation.get("id")
        start_time = time.time()

        while time.time() - start_time < timeout:
            op = self.caldera.get_operation(operation_id)

            if not op:
                break

            state = op.get("state", "")

            if state == "finished":
                host_count = len(op.get("host_group", []))
                chain = op.get("chain", [])

                return {
                    "success": True,
                    "operation_id": operation_id,
                    "state": state,
                    "host_count": host_count,
                    "abilities_executed": len(chain),
                    "duration_seconds": time.time() - start_time,
                }

            if state in ("timeout", "failed"):
                return {
                    "success": False,
                    "operation_id": operation_id,
                    "state": state,
                    "error": f"Operation {state}",
                }

            time.sleep(10)

        return {
            "success": False,
            "operation_id": operation_id,
            "error": "Timeout waiting for operation",
        }

    def run(
        self,
        campaign_name: str,
        num_runs: int = 1,
    ) -> List[Dict[str, Any]]:
        """Execute campaign multiple times."""
        if not self.caldera.login():
            print("[!] Failed to connect to Caldera")
            return []

        print(f"[+] Connected to Caldera")

        adversary_id = self.find_adversary(campaign_name)
        if not adversary_id:
            print("[!] No adversary found")
            return []

        print(f"[+] Using adversary: {adversary_id}")

        for run in range(1, num_runs + 1):
            print(f"  Run {run}/{num_runs}...", end=" ")

            result = self.run_single(campaign_name, adversary_id)
            self.results.append(result)

            status = "OK" if result["success"] else "FAIL"
            print(f"{status}")

            if result.get("operation_id"):
                self.caldera.delete_operation(result["operation_id"])

        return self.results
