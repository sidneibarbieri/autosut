from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import yaml


PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = PROJECT_ROOT / "measurement" / "sut" / "scripts" / "fetch_fight_snapshot.py"
PIPELINE_PATH = PROJECT_ROOT / "measurement" / "sut" / "scripts" / "sut_measurement_pipeline.py"
DATA_DIR = SCRIPT_PATH.parent / "data"
RAW_PATH = DATA_DIR / "fight-3.1.0.yaml"
NORMALIZED_PATH = DATA_DIR / "fight-3.1.0.normalized.json"
METADATA_PATH = DATA_DIR / "fight-3.1.0.metadata.json"

spec = importlib.util.spec_from_file_location("fetch_fight_snapshot", SCRIPT_PATH)
assert spec and spec.loader
fetch_fight_snapshot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fetch_fight_snapshot)

pipeline_spec = importlib.util.spec_from_file_location("sut_measurement_pipeline", PIPELINE_PATH)
assert pipeline_spec and pipeline_spec.loader
sut_measurement_pipeline = importlib.util.module_from_spec(pipeline_spec)
pipeline_spec.loader.exec_module(sut_measurement_pipeline)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_fight_raw_snapshot_is_the_pinned_official_yaml() -> None:
    assert _sha256(RAW_PATH) == fetch_fight_snapshot.EXPECTED_RAW_SHA256
    document = yaml.safe_load(RAW_PATH.read_bytes())
    assert document["id"] == "FiGHT"
    assert document["name"] == "FiGHT Threat Matrix"
    assert len(document["techniques"]) == 183


def test_fight_normalized_snapshot_is_deterministic_and_schema_complete() -> None:
    raw_payload = RAW_PATH.read_bytes()
    regenerated = fetch_fight_snapshot.serialize_json(
        fetch_fight_snapshot.build_normalized(raw_payload)
    )
    assert NORMALIZED_PATH.read_bytes() == regenerated

    snapshot = json.loads(regenerated)
    assert snapshot["schema_version"] == "autosut.fight-normalized.v1"
    assert snapshot["source"]["version"] == "3.1.0"
    assert snapshot["counts"] == {
        "techniques": 183,
        "with_platforms": 140,
        "with_architecture_segments": 163,
        "with_software": 25,
        "with_cves": 5,
        "fight_namespace_ids": 183,
    }
    assert len({item["id"] for item in snapshot["techniques"]}) == 183
    assert {item["id"] for item in snapshot["techniques"] if item["cves"]} == {
        "FGT1078.003",
        "FGT1190",
        "FGT1210",
        "FGT1498.503",
        "FGT5040",
    }

    required = {
        "id",
        "name",
        "status",
        "platforms",
        "architecture_segments",
        "software",
        "description",
        "references",
        "procedure_examples",
        "cves",
    }
    assert all(set(item) == required for item in snapshot["techniques"])
    assert all(item["id"].startswith("FGT") for item in snapshot["techniques"])
    assert any(item["id"].startswith("FGT5") for item in snapshot["techniques"])
    assert any(item["architecture_segments"] for item in snapshot["techniques"])
    serialized = regenerated.decode("utf-8")
    assert "relatedObjects" not in serialized
    assert '"route"' not in serialized


def test_fight_metadata_authenticates_raw_and_derived_files() -> None:
    metadata = json.loads(METADATA_PATH.read_text(encoding="utf-8"))
    assert metadata["dataset"] == "MITRE FiGHT"
    assert metadata["version"] == "3.1.0"
    assert metadata["retrieved_at"] == "2026-07-18T13:04:28Z"
    assert metadata["source_terms_url"] == "https://fight.mitre.org/resources/terms/"
    assert "royalty-free" in metadata["license"]
    assert "trademark" in metadata["marking"]
    assert metadata["authoritative_file"] == RAW_PATH.name
    assert metadata["authoritative_sha256"] == _sha256(RAW_PATH)
    assert metadata["derived_file"] == NORMALIZED_PATH.name
    assert metadata["derived_sha256"] == _sha256(NORMALIZED_PATH)


def test_offline_regeneration_is_byte_reproducible(tmp_path: Path) -> None:
    regenerated_paths = fetch_fight_snapshot.write_snapshot(RAW_PATH.read_bytes(), tmp_path)
    frozen_paths = (RAW_PATH, NORMALIZED_PATH, METADATA_PATH)
    for regenerated, frozen in zip(regenerated_paths, frozen_paths):
        assert regenerated.read_bytes() == frozen.read_bytes()


def test_pipeline_consumes_native_fight_snapshot_with_source_denominators() -> None:
    result = sut_measurement_pipeline.analyze_fight_snapshot(NORMALIZED_PATH)
    assert result["source_schema"] == "fight-native-yaml"
    assert result["source_version"] == "3.1.0"
    assert result["total_techniques"] == 183
    assert result["with_platform"] == 140
    assert result["platform_pct"] == 76.5
    assert result["software_link_pct"] == 13.7
    assert result["cve_link_pct"] == 2.7
    assert result["num_campaigns"] == 2
    assert result["num_intrusion_sets"] == 10
    assert result["num_software"] == 16
