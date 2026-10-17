"""The corpus audit must not promote platform reach to execution."""

import importlib.util
import hashlib
import json
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/audit_corpus_sut_readiness.py"
SPEC = importlib.util.spec_from_file_location("audit_corpus_sut_readiness", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_windows_scenario_only_changes_platform_reach(tmp_path):
    records = []
    for campaign_id, platform, resources in (
        ("C0001", "Linux", []),
        ("C0002", "Windows", [{"requirement_id": "service-1", "kind": "service"}]),
    ):
        folder = tmp_path / campaign_id
        folder.mkdir()
        requirements = [{
            "requirement_id": f"{campaign_id}.platform",
            "kind": "platform",
            "acceptable_values": [platform],
        }, *resources]
        constraints = {
            "campaign_id": campaign_id,
            "source_plan_sha256": "synthetic-source",
            "requirements": requirements,
        }
        encoded = json.dumps(constraints, sort_keys=True, separators=(",", ":")).encode()
        constraints["content_sha256"] = hashlib.sha256(encoded).hexdigest()
        (folder / "constraints.json").write_text(json.dumps(constraints))
        records.append({
            "campaign_id": campaign_id,
            "source_plan_sha256": "synthetic-source",
            "status": "blueprint_generated" if platform == "Linux" else "partial_plan_only",
            "materialized": False,
            "executed": False,
        })
    (tmp_path / "manifest.json").write_text(json.dumps({"campaigns": 2, "records": records}))
    campaign_specs = tmp_path / "campaigns"
    campaign_specs.mkdir()
    (campaign_specs / "bounded.json").write_text(json.dumps({
        "source_campaign_id": "C0001", "execution_contract": {"scope": "synthetic"},
    }))

    report = MODULE.audit_corpus(tmp_path, campaign_specs)

    assert report["summary"]["current_docker_covered_campaigns"] == 1
    assert report["summary"]["docker_plus_windows_covered_campaigns"] == 2
    assert report["summary"]["current_docker_without_nonplatform_requirements"] == 1
    assert report["summary"]["docker_plus_windows_without_nonplatform_requirements"] == 1
    assert report["summary"]["campaigns_with_unverified_nonplatform_requirements"] == 1
    assert report["summary"]["executed_in_corpus_batch"] == 0
    assert report["summary"]["campaigns_with_declared_execution_contracts"] == 1
    assert not report["records"][1]["declared_execution_contract"]
    assert report["records"][1]["nonplatform_requirement_ids"] == ["service-1"]
