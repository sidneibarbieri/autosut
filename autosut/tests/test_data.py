from __future__ import annotations

import json
from pathlib import Path

import yaml


PROJECT_ROOT = Path(__file__).resolve().parent.parent
CAMPAIGNS_DIR = PROJECT_ROOT / "data" / "campaigns"
LEGACY_CAMPAIGNS_DIR = PROJECT_ROOT / "campaigns"
SUT_PROFILES_DIR = PROJECT_ROOT / "data" / "sut_profiles"
STIX_DIR = PROJECT_ROOT / "data" / "stix"


def test_campaign_yaml_directory_contains_canonical_definitions() -> None:
    campaign_files = sorted(CAMPAIGNS_DIR.glob("*.yml"))
    assert campaign_files, "Expected canonical YAML campaigns in data/campaigns"

    sample = yaml.safe_load(campaign_files[0].read_text(encoding="utf-8"))
    assert isinstance(sample, dict)
    assert "campaign_id" in sample
    assert "steps" in sample


def test_legacy_campaign_json_directory_is_still_available_for_parity() -> None:
    campaign_files = sorted(LEGACY_CAMPAIGNS_DIR.glob("*.json"))
    assert campaign_files, "Expected compatibility JSON campaigns in campaigns/"

    sample = json.loads(campaign_files[0].read_text(encoding="utf-8"))
    assert isinstance(sample, dict)
    assert "campaign_id" in sample


def test_sut_profiles_exist_for_live_campaign_surface() -> None:
    sut_files = sorted(
        path for path in SUT_PROFILES_DIR.glob("*.yml") if not path.name.startswith("_")
    )
    assert sut_files, "Expected SUT profiles in data/sut_profiles"

    sample = yaml.safe_load(sut_files[0].read_text(encoding="utf-8"))
    assert isinstance(sample, dict)
    assert "campaign_id" in sample
    assert "sut_configuration" in sample


def test_stix_directory_contains_enterprise_bundle_and_metadata() -> None:
    enterprise_bundle = STIX_DIR / "enterprise-attack.json"
    bundle_metadata = STIX_DIR / "enterprise-attack.metadata.json"

    assert enterprise_bundle.exists(), f"Missing bundle: {enterprise_bundle}"
    assert bundle_metadata.exists(), f"Missing bundle metadata: {bundle_metadata}"

    metadata = json.loads(bundle_metadata.read_text(encoding="utf-8"))
    assert isinstance(metadata, dict)
