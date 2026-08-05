#!/usr/bin/env python3
"""
SUT Provisioner

Automatically provisions vulnerable configurations based on campaign requirements.
Supports both single-host and multi-host SUT configurations.
"""

import yaml
from pathlib import Path
from typing import Any, Dict, List, Set


class SUTProvisioner:
    """Provisions System Under Test for campaign execution."""

    def __init__(self, campaign_data: Dict[str, Any]) -> None:
        """Initialize provisioner with campaign data."""
        self.campaign_data = campaign_data
        self.requirements: Set[str] = set()

    def detect_requirements(self) -> Dict[str, Any]:
        """Detect SUT requirements from campaign."""
        abilities = self.campaign_data.get("abilities", {})

        # Detect required platforms
        platforms = self._detect_platforms(abilities)

        # Detect required services
        services = self._detect_services(abilities)

        # Detect network requirements
        network = self._detect_network_requirements(abilities)

        return {
            "platforms": platforms,
            "services": services,
            "network": network,
            "host_count": self._estimate_host_count(abilities, network),
        }

    def _detect_platforms(self, abilities: Dict) -> List[str]:
        """Detect required platforms."""
        platforms = set()

        for ability_data in abilities.values():
            executors = ability_data.get("executors", [])
            for executor in executors:
                for executor_data in executor.values():
                    if isinstance(executor_data, dict):
                        platform = executor_data.get("platform", "")
                        if platform:
                            platforms.add(platform)

        return sorted(platforms)

    def _detect_services(self, abilities: Dict) -> List[str]:
        """Detect required services."""
        services = set()

        # Common service indicators
        service_keywords = [
            "http", "https", "smb", "ssh", "rdp", "dns",
            "ftp", "sftp", "mysql", "postgres", "mongodb",
            "redis", "nginx", "apache", "iis", "winrm",
        ]

        for ability_data in abilities.values():
            description = ability_data.get("description", "").lower()
            for service in service_keywords:
                if service in description:
                    services.add(service)

        return sorted(services)

    def _detect_network_requirements(self, abilities: Dict) -> Dict[str, Any]:
        """Detect network requirements."""
        has_lateral_movement = False
        has_multiple_targets = False

        # Keywords indicating lateral movement
        lateral_keywords = [
            "lateral", "pivot", "remote", "wmi", "winrm",
            "ssh", "rdp", "psexec", "pass-the-hash",
        ]

        for ability_data in abilities.values():
            description = ability_data.get("description", "").lower()
            for keyword in lateral_keywords:
                if keyword in description:
                    has_lateral_movement = True
                    break

        return {
            "lateral_movement": has_lateral_movement,
            "multiple_targets": has_multiple_targets,
        }

    def _estimate_host_count(self, abilities: Dict, network: Dict) -> int:
        """Estimate number of hosts required."""
        if network.get("lateral_movement"):
            return 3  # Attacker + 2 targets
        return 2  # Attacker + 1 target

    def generate_provisioning_config(self) -> Dict[str, Any]:
        """Generate provisioning configuration."""
        requirements = self.detect_requirements()

        return {
            "campaign_id": self.campaign_data.get("id", "unknown"),
            "campaign_name": self.campaign_data.get("name", "Unknown"),
            "sut_type": "multi-host" if requirements["host_count"] > 2 else "single-host",
            "hosts": self._generate_hosts(requirements),
            "vulnerabilities": self._generate_vulnerabilities(requirements),
        }

    def _generate_hosts(self, requirements: Dict) -> List[Dict]:
        """Generate host configurations."""
        host_count = requirements["host_count"]
        platforms = requirements.get("platforms", ["linux"])

        hosts = []
        for i in range(host_count):
            role = "attacker" if i == 0 else f"target_{i}"
            hosts.append({
                "name": f"host_{i+1}",
                "role": role,
                "platform": platforms[i % len(platforms)] if platforms else "linux",
                "services": requirements.get("services", [])[:3],
            })

        return hosts

    def _generate_vulnerabilities(self, requirements: Dict) -> List[Dict]:
        """Generate vulnerable configurations to provision."""
        vulnerabilities = []

        # Common vulnerabilities based on services
        service_vulns = {
            "http": ["outdated-web-server", "missing-security-headers"],
            "ssh": ["weak-ssh-config", "default-credentials"],
            "smb": ["smb-signing-disabled", "anonymous-access"],
            "rdp": ["rdp-enabled-weak-auth"],
            "dns": ["dns-cache-snooping"],
        }

        for service in requirements.get("services", []):
            if service in service_vulns:
                for vuln in service_vulns[service]:
                    vulnerabilities.append({
                        "service": service,
                        "vulnerability": vuln,
                    })

        return vulnerabilities


def main():
    """Main function for testing."""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python3 sut_provisioner.py <campaign.yml>")
        sys.exit(1)

    campaign_file = Path(sys.argv[1])

    with open(campaign_file) as file:
        campaign_data = yaml.safe_load(file)

    provisioner = SUTProvisioner(campaign_data)

    print("=== SUT Requirements ===")
    requirements = provisioner.detect_requirements()
    print(f"Platforms: {requirements['platforms']}")
    print(f"Services: {requirements['services']}")
    print(f"Host count: {requirements['host_count']}")
    print(f"Network: {requirements['network']}")

    print("\n=== Provisioning Config ===")
    config = provisioner.generate_provisioning_config()
    print(yaml.dump(config, default_flow_style=False))


if __name__ == "__main__":
    main()
