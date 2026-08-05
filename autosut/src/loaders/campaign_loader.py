"""
Campaign and SUT profile loader.

Loads canonical YAML definitions and JSON compatibility definitions.
No orchestration logic — just parsing and validation.
"""

import json
from pathlib import Path
from typing import Dict, Optional

import yaml
from executors.models import (
    Campaign,
    ExecutionFidelity,
    ExecutionMode,
    NetworkConfig,
    SUTFile,
    SUTHost,
    SUTProfile,
    SUTService,
    SUTUser,
    SUTWeakness,
    TechniqueStep,
    TechniqueSUTDelta,
)

CAMPAIGNS_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "campaigns"
LEGACY_CAMPAIGNS_DIR = Path(__file__).resolve().parent.parent.parent / "campaigns"
SUT_PROFILES_DIR = (
    Path(__file__).resolve().parent.parent.parent / "data" / "sut_profiles"
)


def _build_campaign_from_legacy_json(raw: Dict) -> Campaign:
    """Translate the published JSON campaign schema into the canonical model."""
    steps = []
    for index, raw_step in enumerate(raw.get("techniques", []), start=1):
        platform = str(raw_step.get("platform", "")).lower()
        expected_mode_value = raw_step.get(
            "expected_mode",
            (
                ExecutionMode.NAIVE_SIMULATED.value
                if platform in {"windows", "macos"}
                else ExecutionMode.REAL_CONTROLLED.value
            ),
        )
        expected_fidelity_value = raw_step.get(
            "expected_fidelity",
            ExecutionFidelity.ADAPTED.value,
        )
        steps.append(
            TechniqueStep(
                technique_id=raw_step["technique_id"],
                technique_name=raw_step["name"],
                tactic=raw_step.get("tactic", ""),
                platform=raw_step.get("platform", ""),
                order=index,
                requires=raw_step.get("requires", []),
                produces=raw_step.get("produces", []),
                expected_fidelity=ExecutionFidelity(expected_fidelity_value),
                expected_mode=ExecutionMode(expected_mode_value),
                fidelity_rationale=raw_step.get(
                    "fidelity_rationale",
                    "Imported from published JSON compatibility campaign.",
                ),
                procedure_summary=raw_step.get(
                    "procedure_summary",
                    raw_step.get("description", ""),
                ),
                sut_delta=_build_step_sut_delta(raw_step.get("sut_delta")),
            )
        )

    campaign_id = raw["campaign_id"]
    return Campaign(
        campaign_id=campaign_id,
        name=raw.get("name") or campaign_id,
        description=raw.get("description", ""),
        sut_profile_id=campaign_id,
        steps=steps,
        objective=raw.get("objective", ""),
    )


def _build_step_sut_delta(raw_delta: Optional[Dict]) -> Optional[TechniqueSUTDelta]:
    """Parse an optional step-conditioned SUT overlay."""
    if not raw_delta:
        return None

    weakness_entries = raw_delta.get(
        "deliberate_weaknesses",
        raw_delta.get("weaknesses", []),
    )
    return TechniqueSUTDelta(
        target_host=raw_delta.get("target_host", raw_delta.get("target", "")),
        services=[SUTService(**svc) for svc in raw_delta.get("services", [])],
        users=[SUTUser(**usr) for usr in raw_delta.get("users", [])],
        files=[SUTFile(**fil) for fil in raw_delta.get("files", [])],
        deliberate_weaknesses=[SUTWeakness(**w) for w in weakness_entries],
        notes=raw_delta.get("notes", ""),
    )


def load_campaign(campaign_id: str) -> Campaign:
    """Load and validate a campaign definition from YAML or JSON."""
    yaml_path = CAMPAIGNS_DIR / f"{campaign_id}.yml"
    if yaml_path.exists():
        with open(yaml_path, encoding="utf-8") as f:
            raw = yaml.safe_load(f)

        steps = []
        for raw_step in raw.get("steps", []):
            steps.append(
                TechniqueStep(
                    technique_id=raw_step["technique_id"],
                    technique_name=raw_step["technique_name"],
                    tactic=raw_step.get("tactic", ""),
                    platform=raw_step.get("platform", ""),
                    order=raw_step["order"],
                    requires=raw_step.get("requires", []),
                    produces=raw_step.get("produces", []),
                    expected_fidelity=ExecutionFidelity(raw_step["expected_fidelity"]),
                    expected_mode=ExecutionMode(
                        raw_step.get("expected_mode", "real_controlled")
                    ),
                    fidelity_rationale=raw_step.get("fidelity_rationale", ""),
                    procedure_summary=raw_step.get("procedure_summary", ""),
                    sut_delta=_build_step_sut_delta(raw_step.get("sut_delta")),
                )
            )

        return Campaign(
            campaign_id=raw["campaign_id"],
            name=raw["name"],
            description=raw.get("description", ""),
            sut_profile_id=raw["sut_profile_id"],
            steps=steps,
            objective=raw.get("objective", ""),
        )

    json_path = LEGACY_CAMPAIGNS_DIR / f"{campaign_id}.json"
    if json_path.exists():
        with open(json_path, encoding="utf-8") as f:
            raw = json.load(f)
        return _build_campaign_from_legacy_json(raw)

    raise FileNotFoundError(
        "Campaign definition not found in canonical YAML or compatibility JSON: "
        f"{yaml_path} | {json_path}"
    )


def load_sut_profile(profile_id: str) -> SUTProfile:
    """Load and validate a SUT profile from YAML."""
    path = SUT_PROFILES_DIR / f"{profile_id}.yml"
    if not path.exists():
        raise FileNotFoundError(f"SUT profile not found: {path}")

    with open(path, encoding="utf-8") as f:
        raw = yaml.safe_load(f)

    requirements = raw.get("requirements", {})
    sut_config = raw.get("sut_configuration", {})

    hosts: Dict[str, SUTHost] = {}
    for host_name, host_raw in sut_config.items():
        services = [SUTService(**svc) for svc in host_raw.get("services", [])]
        users = [SUTUser(**usr) for usr in host_raw.get("users", [])]
        files = [SUTFile(**fil) for fil in host_raw.get("files", [])]
        weaknesses = [
            SUTWeakness(**w) for w in host_raw.get("deliberate_weaknesses", [])
        ]
        network_raw = host_raw.get("network", {})
        network = NetworkConfig(
            ingress=network_raw.get("ingress", []),
            egress=network_raw.get("egress", []),
        )
        hosts[host_name] = SUTHost(
            os=host_raw.get("os", "ubuntu-2204"),
            role=host_raw.get("role", ""),
            services=services,
            users=users,
            files=files,
            network=network,
            deliberate_weaknesses=weaknesses,
        )

    fidelity_raw = raw.get("fidelity_expectations", {})
    fidelity_expectations = {
        tid: ExecutionFidelity(val.lower()) for tid, val in fidelity_raw.items()
    }

    return SUTProfile(
        campaign_id=raw["campaign_id"],
        description=raw.get("description", ""),
        min_hosts=requirements.get("min_hosts", 3),
        required_vms=requirements.get("required_vms", []),
        extra_vms=requirements.get("extra_vms", []),
        estimated_duration_minutes=requirements.get("estimated_duration_minutes", 5),
        hosts=hosts,
        fidelity_expectations=fidelity_expectations,
        execution_mode=raw.get("execution_mode", "real_controlled"),
        methodology_notes=raw.get("methodology_notes", ""),
    )


def list_campaigns() -> list[str]:
    """List available campaign IDs across supported storage formats."""
    campaign_ids = set()
    if CAMPAIGNS_DIR.exists():
        campaign_ids.update(
            p.stem for p in CAMPAIGNS_DIR.glob("*.yml") if not p.name.startswith("_")
        )
    if LEGACY_CAMPAIGNS_DIR.exists():
        campaign_ids.update(
            p.stem
            for p in LEGACY_CAMPAIGNS_DIR.glob("*.json")
            if not p.name.startswith("_")
        )
    return sorted(campaign_ids)


def list_sut_profiles() -> list[str]:
    """List available SUT profile IDs."""
    if not SUT_PROFILES_DIR.exists():
        return []
    return sorted(
        p.stem for p in SUT_PROFILES_DIR.glob("*.yml") if not p.name.startswith("_")
    )


def validate_campaign_sut_pair(campaign_id: str) -> Optional[str]:
    """
    Validate that a campaign and its SUT profile are consistent.

    Returns None if valid, or an error message string if invalid.
    """
    campaign = load_campaign(campaign_id)
    sut = load_sut_profile(campaign.sut_profile_id)

    errors = []

    # Every technique in the campaign must have fidelity in the SUT
    for step in campaign.steps:
        if step.technique_id not in sut.fidelity_expectations:
            errors.append(
                f"Technique {step.technique_id} in campaign but not in SUT fidelity_expectations"
            )
        else:
            sut_fidelity = sut.fidelity_expectations[step.technique_id]
            if sut_fidelity != step.expected_fidelity:
                errors.append(
                    f"Fidelity mismatch for {step.technique_id}: "
                    f"campaign expects {step.expected_fidelity.value}, "
                    f"SUT expects {sut_fidelity.value}"
                )

    if errors:
        return "; ".join(errors)
    return None
