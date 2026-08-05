from __future__ import annotations

import json
from pathlib import Path
import sys

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from loaders import campaign_loader


def _write_yaml(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(payload), encoding="utf-8")


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_load_campaign_reads_json_compatibility_definition(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(campaign_loader, "CAMPAIGNS_DIR", tmp_path / "data" / "campaigns")
    monkeypatch.setattr(
        campaign_loader,
        "LEGACY_CAMPAIGNS_DIR",
        tmp_path / "campaigns",
    )

    _write_json(
        tmp_path / "campaigns" / "0.c0011.json",
        {
            "campaign_id": "0.c0011",
            "description": "Baseline",
            "techniques": [
                {
                    "technique_id": "T1059.004",
                    "name": "Unix Shell",
                    "tactic": "execution",
                    "platform": "linux",
                    "description": "Execute shell commands on the target host.",
                    "expected_fidelity": "adapted",
                    "requires": ["access:initial"],
                    "produces": ["code_execution"],
                    "sut_delta": {
                        "target_host": "target-base",
                        "services": [
                            {"name": "ray-dashboard", "config": "unauthenticated_api_enabled"}
                        ],
                        "deliberate_weaknesses": [
                            {
                                "type": "exposed_ray_jobs_api",
                                "cve": "CVE-2023-48022",
                                "description": "Expose the Ray jobs API boundary.",
                            }
                        ],
                        "notes": "Expose the public-facing boundary just before execution.",
                    },
                },
                {
                    "technique_id": "T1204.001",
                    "name": "User Execution",
                    "platform": "windows",
                    "expected_fidelity": "inspired",
                    "expected_mode": "naive_simulated",
                    "requires": ["artifacts:spearphish_link"],
                    "produces": ["artifacts:malicious_link_accessed"],
                    "fidelity_rationale": "Windows step on a Linux substrate.",
                },
            ],
        },
    )

    campaign = campaign_loader.load_campaign("0.c0011")

    assert campaign.campaign_id == "0.c0011"
    assert campaign.sut_profile_id == "0.c0011"
    assert [step.technique_id for step in campaign.steps] == ["T1059.004", "T1204.001"]
    assert campaign.steps[0].requires == ["access:initial"]
    assert campaign.steps[0].produces == ["code_execution"]
    assert campaign.steps[0].tactic == "execution"
    assert campaign.steps[0].platform == "linux"
    assert campaign.steps[0].procedure_summary == "Execute shell commands on the target host."
    assert campaign.steps[0].expected_fidelity.value == "adapted"
    assert campaign.steps[0].expected_mode.value == "real_controlled"
    assert campaign.steps[0].sut_delta is not None
    assert campaign.steps[0].sut_delta.target_host == "target-base"
    assert campaign.steps[0].sut_delta.services[0].name == "ray-dashboard"
    assert campaign.steps[0].sut_delta.deliberate_weaknesses[0].cve == "CVE-2023-48022"
    assert campaign.steps[1].requires == ["artifacts:spearphish_link"]
    assert campaign.steps[1].produces == ["artifacts:malicious_link_accessed"]
    assert campaign.steps[1].expected_fidelity.value == "inspired"
    assert campaign.steps[1].expected_mode.value == "naive_simulated"
    assert campaign.steps[1].fidelity_rationale == "Windows step on a Linux substrate."


def test_list_campaigns_unifies_yaml_and_json_sources(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(campaign_loader, "CAMPAIGNS_DIR", tmp_path / "data" / "campaigns")
    monkeypatch.setattr(
        campaign_loader,
        "LEGACY_CAMPAIGNS_DIR",
        tmp_path / "campaigns",
    )

    _write_yaml(
        tmp_path / "data" / "campaigns" / "C0001.yml",
        {
            "campaign_id": "C0001",
            "name": "Operation Aurora",
            "sut_profile_id": "C0001",
            "steps": [],
        },
    )
    _write_json(
        tmp_path / "campaigns" / "0.c0011.json",
        {
            "campaign_id": "0.c0011",
            "techniques": [],
        },
    )

    assert campaign_loader.list_campaigns() == ["0.c0011", "C0001"]
