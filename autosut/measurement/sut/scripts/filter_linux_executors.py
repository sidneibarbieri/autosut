#!/usr/bin/env python3
"""
Linux Executor Filter for Caldera Campaigns

This script filters campaign YAML files to include only Linux executors.
This enables running campaigns in a Linux-only Docker environment.

Usage:
    python3 filter_linux_executors.py <campaign_file.yml> [output_file.yml]

Example:
    python3 filter_linux_executors.py 0.solarwinds_compromise.yml solarwinds_linux.yml
"""

import sys
import yaml
from pathlib import Path
from typing import Dict, Any, List


def filter_linux_executors(campaign_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Filter campaign abilities to only Linux executors.

    Args:
        campaign_data: Original campaign YAML data

    Returns:
        Campaign data with only Linux executors
    """
    filtered = campaign_data.copy()
    abilities = filtered.get("abilities", {})

    filtered_abilities = {}

    for ability_id, ability_data in abilities.items():
        # Skip if not an attack pattern (technique)
        if "attack-pattern--" not in ability_id:
            continue

        filtered_ability = ability_data.copy()
        executors = filtered_ability.get("executors", [])

        # Filter to only Linux executors
        linux_executors = []
        for executor in executors:
            for executor_type, executor_data in executor.items():
                if isinstance(executor_data, dict):
                    platform = executor_data.get("platform", "")
                    if platform == "linux":
                        linux_executors.append({executor_type: executor_data})

        # Only include ability if it has Linux executors
        if linux_executors:
            filtered_ability["executors"] = linux_executors
            filtered_abilities[ability_id] = filtered_ability

    filtered["abilities"] = filtered_abilities

    # Update atomic_ordering to only include techniques that have Linux executers
    original_ordering = filtered.get("atomic_ordering", [])
    filtered_ordering = [
        ap_id for ap_id in original_ordering
        if ap_id in filtered_abilities
    ]
    filtered["atomic_ordering"] = filtered_ordering

    return filtered


def analyze_campaign_platforms(campaign_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze which platforms are available in a campaign.

    Returns:
        Dict with platform counts and percentages
    """
    platforms = {"linux": 0, "windows": 0, "darwin": 0}
    total_abilities = 0

    abilities = campaign_data.get("abilities", {})

    for ability_id, ability_data in abilities.items():
        if "attack-pattern--" not in ability_id:
            continue

        total_abilities += 1
        executors = ability_data.get("executors", [])

        for executor in executors:
            for executor_type, executor_data in executor.items():
                if isinstance(executor_data, dict):
                    platform = executor_data.get("platform", "")
                    if platform in platforms:
                        platforms[platform] += 1

    return {
        "total_abilities": total_abilities,
        "platforms": platforms,
        "linux_percentage": (platforms["linux"] / total_abilities * 100) if total_abilities > 0 else 0,
    }


def main():
    """Main function."""
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    # Support both relative and absolute paths
    input_path = Path(sys.argv[1])
    if input_path.is_absolute():
        input_file = input_path
    else:
        # Resolve relative to project root
        project_root = Path(__file__).resolve().parents[4]
        input_file = project_root / input_path

    output_file = Path(sys.argv[2]) if len(sys.argv) > 2 else None

    if not input_file.exists():
        print(f"Error: File not found: {input_file}")
        sys.exit(1)

    # Load campaign
    print(f"Loading campaign: {input_file}")
    with open(input_file) as file:
        campaign_data = yaml.safe_load(file)

    # Analyze original platforms
    analysis = analyze_campaign_platforms(campaign_data)
    print(f"\nOriginal campaign analysis:")
    print(f"  Total abilities: {analysis['total_abilities']}")
    print(f"  Linux: {analysis['platforms']['linux']} ({analysis['linux_percentage']:.1f}%)")
    print(f"  Windows: {analysis['platforms']['windows']}")
    print(f"  macOS: {analysis['platforms']['darwin']}")

    # Filter to Linux-only
    print(f"\nFiltering to Linux-only executors...")
    filtered_data = filter_linux_executors(campaign_data)

    # Analyze filtered platforms
    filtered_analysis = analyze_campaign_platforms(filtered_data)
    print(f"\nFiltered campaign analysis:")
    print(f"  Total abilities: {filtered_analysis['total_abilities']}")
    print(f"  Linux: {filtered_analysis['platforms']['linux']}")

    # Save filtered campaign
    if output_file:
        with open(output_file, "w") as file:
            yaml.dump(filtered_data, file, default_flow_style=False, sort_keys=False)
        print(f"\nSaved: {output_file}")
    else:
        # Print to stdout
        print("\n--- Filtered YAML ---")
        print(yaml.dump(filtered_data, default_flow_style=False, sort_keys=False))


if __name__ == "__main__":
    main()
