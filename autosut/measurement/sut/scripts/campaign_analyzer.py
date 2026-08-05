#!/usr/bin/env python3
"""
Campaign Analyzer Module

Analyzes campaign data for platform coverage.
"""

from typing import Any, Dict


class CampaignAnalyzer:
    """Analyzes campaign platform coverage."""

    def __init__(self, campaign_data: Dict[str, Any]) -> None:
        """Initialize analyzer with campaign data."""
        self.campaign_data = campaign_data

    def analyze_linux_coverage(self) -> Dict[str, Any]:
        """Analyze Linux coverage in campaign."""
        platforms = {"linux": 0, "windows": 0, "darwin": 0}
        total = 0

        abilities = self.campaign_data.get("abilities", {})

        for ability_id, ability_data in abilities.items():
            if "attack-pattern--" not in ability_id:
                continue

            total += 1
            executors = ability_data.get("executors", [])

            for executor in executors:
                for executor_type, executor_data in executor.items():
                    if isinstance(executor_data, dict):
                        platform = executor_data.get("platform", "")
                        if platform in platforms:
                            platforms[platform] += 1

        return {
            "total_abilities": total,
            "linux": platforms["linux"],
            "windows": platforms["windows"],
            "darwin": platforms["darwin"],
            "linux_percentage": (
                platforms["linux"] / total * 100 if total > 0 else 0
            ),
        }
