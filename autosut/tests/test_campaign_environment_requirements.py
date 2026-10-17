from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import sys

import pytest
import yaml

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = PROJECT_ROOT / "scripts" / "audit_campaign_environment_requirements.py"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "campaign_environment_requirements",
        SCRIPT_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load campaign environment audit")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_hashed_plan(path: Path, stix_sha256: str, *, description: str) -> None:
    payload = {
        "schema_version": "1",
        "compiler_version": "1",
        "campaign_id": "CTEST",
        "campaign_name": "Test campaign",
        "source": {
            "bundle_sha256": stix_sha256,
            "object_count": 3,
            "campaign_stix_id": "campaign--test",
            "campaign_external_id": "CTEST",
        },
        "ordering_policy": "test-order",
        "steps": [
            {
                "technique_id": "T0001",
                "technique_stix_id": "attack-pattern--test",
                "name": "Test technique",
                "execution_domain": "target",
                "tactics": ["lateral-movement"],
                "platforms": ["Windows"],
                "permissions_required": [],
                "system_requirements": [],
                "relationship_ids": ["relationship--test"],
                "procedure_descriptions": [description],
            }
        ],
        "limitations": [],
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    payload["content_sha256"] = hashlib.sha256(encoded).hexdigest()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _write_inputs(tmp_path: Path, *, description: str) -> tuple[Path, Path, Path]:
    stix_path = tmp_path / "data" / "stix" / "enterprise-attack.json"
    stix_path.parent.mkdir(parents=True)
    stix_path.write_text(
        json.dumps(
            {
                "type": "bundle",
                "objects": [
                    {"id": "campaign--test", "type": "campaign"},
                    {
                        "id": "attack-pattern--test",
                        "type": "attack-pattern",
                        "name": "Test technique",
                        "x_mitre_platforms": ["Windows"],
                        "external_references": [
                            {"source_name": "mitre-attack", "external_id": "T0001"}
                        ],
                    },
                    {
                        "id": "relationship--test",
                        "type": "relationship",
                        "relationship_type": "uses",
                        "source_ref": "campaign--test",
                        "target_ref": "attack-pattern--test",
                        "description": "Uses a documented Windows mechanism.",
                    },
                ],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    registry_path = tmp_path / "src" / "executors" / "campaign_registry.yml"
    registry_path.parent.mkdir(parents=True)
    registry_path.write_text(yaml.safe_dump({"campaigns": {}}), encoding="utf-8")
    plan_root = tmp_path / "release" / "inputs" / "sticks"
    _write_hashed_plan(
        plan_root / "test-v1" / "CTEST.procedural-plan.json",
        _sha256(stix_path),
        description=description,
    )
    return stix_path, registry_path, plan_root


def test_audit_preserves_procedure_provenance_without_inferring_native_windows(
    tmp_path: Path,
    monkeypatch,
) -> None:
    module = _load_module()
    monkeypatch.setattr(module, "PROJECT_ROOT", tmp_path)
    stix_path, registry_path, plan_root = _write_inputs(
        tmp_path,
        description="Uses a documented Windows mechanism.",
    )

    audit = module.audit_environment_requirements(
        stix_path=stix_path,
        registry_path=registry_path,
        plan_input_root=plan_root,
    )

    assert len(audit.campaigns) == 1
    campaign = audit.campaigns[0]
    assert campaign.campaign_id == "CTEST"
    assert campaign.declaration_source == "verified_procedural_plan"
    assert campaign.declared_techniques == ["T0001"]
    assert campaign.native_windows_backend_decision == "requires_external_evidence"
    assert campaign.procedural_provenance is not None
    assert campaign.procedural_provenance.relationship_count == 1
    assert campaign.procedural_provenance.procedure_description_count == 1
    assert campaign.procedural_provenance.semantic_interpretation == "not_performed"
    assert "does not establish" in audit.non_claim


def test_audit_rejects_procedure_text_not_bound_to_the_stix_relationship(
    tmp_path: Path,
    monkeypatch,
) -> None:
    module = _load_module()
    monkeypatch.setattr(module, "PROJECT_ROOT", tmp_path)
    stix_path, registry_path, plan_root = _write_inputs(
        tmp_path,
        description="Unrelated text that was not copied from the uses relationship.",
    )

    with pytest.raises(ValueError, match="procedure descriptions do not match"):
        module.audit_environment_requirements(
            stix_path=stix_path,
            registry_path=registry_path,
            plan_input_root=plan_root,
        )
