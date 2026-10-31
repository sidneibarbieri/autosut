"""The canonical-product sensitivity record is recomputable from the pinned Enterprise bundle."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "measurement" / "sut" / "scripts"
RECORD = SCRIPTS / "results" / "canonical_product_sensitivity.json"


def _module():
    spec = importlib.util.spec_from_file_location(
        "canonical_product_sensitivity", SCRIPTS / "canonical_product_sensitivity.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_canonical_map_merges_shared_aliases_only() -> None:
    module = _module()
    software = [
        {"id": "a", "name": "Alpha", "x_mitre_aliases": ["Alpha", "Shared"]},
        {"id": "b", "name": "Beta", "x_mitre_aliases": ["shared"]},
        {"id": "c", "name": "Gamma"},
    ]
    mapping = module.canonical_product_map(software)
    assert mapping["a"] == mapping["b"]
    assert mapping["c"] == "c"


def test_record_matches_recorded_structure() -> None:
    record = json.loads(RECORD.read_text(encoding="utf-8"))
    assert record["canonical_products"] == record["software_objects"] - sum(
        len(group) - 1 for group in record["merged_groups"]
    )
    for view in ("object_identity", "product_identity"):
        assert record[view]["k2_confused"] <= record[view]["k1_confused"]
