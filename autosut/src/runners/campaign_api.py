#!/usr/bin/env python3
"""
AutoSUT Campaign Public API - Provides stable programmatic interface
"""

from pathlib import Path
from typing import List, Optional

from .campaign_runner import (
    BASE_CAPABILITIES,
    CampaignEvidence,
    UnifiedCampaignRunner,
    list_campaigns,
    load_campaign,
    load_sut_profile,
)


def run_campaign(
    campaign_id: str,
    output_dir: Optional[Path] = None,
    capabilities: Optional[List[str]] = None,
) -> CampaignEvidence:
    """
    Execute a single campaign and return evidence.

    Args:
        campaign_id: Campaign identifier (e.g., '0.c0017')
        output_dir: Evidence output directory (defaults to 'results/evidence')
        capabilities: Initial capabilities (defaults to BASE_CAPABILITIES)

    Returns:
        CampaignEvidence: Complete execution evidence

    Raises:
        FileNotFoundError: Campaign or SUT profile not found
        Exception: Execution errors
    """
    if capabilities is None:
        capabilities = list(BASE_CAPABILITIES)

    runner = UnifiedCampaignRunner(campaign_id=campaign_id, output_dir=output_dir)
    return runner.run()


def run_all_campaigns(
    output_dir: Optional[Path] = None, capabilities: Optional[List[str]] = None
) -> List[CampaignEvidence]:
    """
    Execute all available campaigns and return evidence list.

    Args:
        output_dir: Evidence output directory (defaults to 'results/evidence')
        capabilities: Initial capabilities (defaults to BASE_CAPABILITIES)

    Returns:
        List[CampaignEvidence]: Evidence for all campaigns
    """
    if capabilities is None:
        capabilities = list(BASE_CAPABILITIES)

    results = []
    for campaign_id in list_campaigns():
        try:
            evidence = run_campaign(campaign_id, output_dir, capabilities)
            results.append(evidence)
        except Exception as e:
            print(f"Failed to run campaign {campaign_id}: {e}")
            # Continue with other campaigns
            continue

    return results


def get_available_campaigns() -> List[str]:
    """Get list of all available campaign IDs."""
    return list_campaigns()


def validate_campaign(campaign_id: str) -> bool:
    """
    Validate that a campaign can be loaded and has all required components.

    Args:
        campaign_id: Campaign identifier

    Returns:
        bool: True if campaign is valid
    """
    try:
        campaign = load_campaign(campaign_id)
        load_sut_profile(campaign.sut_profile_id)
        return True
    except Exception:
        return False


__all__ = [
    "run_campaign",
    "run_all_campaigns",
    "get_available_campaigns",
    "validate_campaign",
    "CampaignEvidence",
    "BASE_CAPABILITIES",
]
