"""Checks for the prospective consequence-study screening ledger."""

import copy
import importlib.util
import json
from pathlib import Path

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "screen_consequence_population.py"
SPEC = importlib.util.spec_from_file_location("screen_consequence_population", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
screening = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(screening)


def _manifest() -> dict:
    return {
        "schema_version": "autosut-corpus-suts/v1",
        "campaigns": 2,
        "blueprints_generated": 1,
        "partial_plans_generated": 1,
        "records": [
            {"campaign_id": "C0001", "source_plan_sha256": "a" * 64,
             "status": "blueprint_generated", "materialized": False, "executed": False},
            {"campaign_id": "C0002", "source_plan_sha256": "b" * 64,
             "status": "partial_plan_only", "materialized": False, "executed": False},
        ],
    }


def _matrix() -> dict:
    return {
        "schema_version": "autosut-pair-preparation/v1",
        "prepared": 1,
        "blocked": 0,
        "executed": 0,
        "pairs": [
            {"campaign_id": "0.example", "source_campaign_id": "C0001",
             "status": "prepared", "reasons": [], "contract_sha256": "c" * 64,
             "files": {"sut-constraints.json": "f" * 64},
             "execution_status": "not_run"},
        ],
    }


def test_prescreen_reports_preparation_without_eligibility() -> None:
    report = screening.build_report(_manifest(), _matrix(), "d" * 64, "e" * 64)
    assert report["counts"] == {
        "campaigns": 2, "blueprints_generated": 1, "partial_plans_generated": 1,
        "contract_available_campaigns": 1, "executed_campaigns": 0,
    }
    assert report["records"][0]["screening_status"] == "contract_available_unassessed"
    assert report["records"][0]["cti_constraints_sha256"] == "f" * 64
    assert report["records"][1]["cti_constraints_sha256"] is None
    assert report["records"][0]["prospective_eligible"] is None
    assert report["records"][1]["screening_status"] == "partial_plan"


@pytest.mark.parametrize("mutation", [
    lambda manifest: manifest["records"].append(copy.deepcopy(manifest["records"][0])),
    lambda manifest: manifest.update(campaigns=3),
    lambda manifest: manifest["records"][0].update(status="unknown"),
])
def test_invalid_manifest_is_rejected(mutation) -> None:
    manifest = _manifest()
    mutation(manifest)
    with pytest.raises(ValueError):
        screening.build_report(manifest, _matrix(), "d" * 64, "e" * 64)


def test_orphan_pair_is_rejected() -> None:
    matrix = _matrix()
    matrix["pairs"][0]["source_campaign_id"] = "C9999"
    with pytest.raises(ValueError, match="unknown source campaign"):
        screening.build_report(_manifest(), matrix, "d" * 64, "e" * 64)


def test_invalid_constraint_hash_is_rejected() -> None:
    matrix = _matrix()
    matrix["pairs"][0]["files"]["sut-constraints.json"] = "not-a-digest"
    with pytest.raises(ValueError, match="invalid CTI-constraint digest"):
        screening.build_report(_manifest(), matrix, "d" * 64, "e" * 64)


def test_check_detects_modified_report(tmp_path: Path) -> None:
    destination = tmp_path / "report.json"
    report = screening.build_report(_manifest(), _matrix(), "d" * 64, "e" * 64)
    screening.write_report(destination, report)
    screening.check_report(destination, report)
    tampered = json.loads(destination.read_text())
    tampered["counts"]["contract_available_campaigns"] = 2
    destination.write_text(json.dumps(tampered))
    with pytest.raises(ValueError, match="differs"):
        screening.check_report(destination, report)


def test_existing_pilot_is_excluded_from_prospective_population() -> None:
    manifest = _manifest()
    manifest["records"][0]["campaign_id"] = "C0045"
    matrix = _matrix()
    matrix["pairs"][0]["source_campaign_id"] = "C0045"
    report = screening.build_report(manifest, matrix, "d" * 64, "e" * 64)
    assert report["records"][1]["pilot_excluded"] is True
    assert report["records"][1]["prospective_eligible"] is None
