from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "measurement" / "sut" / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

import build_compatibility_validation_sample as sampler  # noqa: E402


def _rows(count_per_stratum: dict[str, int]) -> list[dict]:
    rows = []
    serial = 0
    for stratum, count in count_per_stratum.items():
        cls = "fallback" if stratum == "fallback" else stratum.split("_")[1]
        for _ in range(count):
            serial += 1
            rows.append({
                "technique_external_id": f"T{serial:04d}", "technique_name": f"Technique {serial}",
                "tactics": "discovery", "platforms": "Linux", "permissions": "",
                "description_excerpt": "desc", "autosut_class": cls if cls != "fallback" else "VMR",
                "rule_id": stratum if stratum != "fallback" else "R8_DEFAULT_VMR", "stratum": stratum,
            })
    return rows


def test_the_sample_respects_each_stratum_target_and_is_deterministic() -> None:
    rows = _rows({name: target + 50 for name, target in sampler.STRATUM_TARGET.items()})
    first = sampler.draw_sample(rows, seed=1)
    second = sampler.draw_sample(rows, seed=1)
    assert [row["technique_external_id"] for row in first] == [row["technique_external_id"] for row in second]
    for stratum, target in sampler.STRATUM_TARGET.items():
        assert sum(row["stratum"] == stratum for row in first) == target
    assert [row["item_id"] for row in first] == [f"CMP-{index:03d}" for index in range(1, len(first) + 1)]


def test_a_small_stratum_is_taken_whole() -> None:
    rows = _rows({**{name: target for name, target in sampler.STRATUM_TARGET.items()},
                  "R7_CF_CONTAINER_COMPATIBLE": 3})
    sample = sampler.draw_sample(rows, seed=7)
    assert sum(row["stratum"] == "R7_CF_CONTAINER_COMPATIBLE" for row in sample) == 3


def test_blind_sheets_never_expose_the_autosut_label(tmp_path) -> None:
    rows = _rows({name: target + 5 for name, target in sampler.STRATUM_TARGET.items()})
    sample = sampler.draw_sample(rows, seed=3)
    sheet = tmp_path / "sheet.csv"
    sampler.write_blind_sheet(sample, sheet)
    with sheet.open(encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        assert "autosut_class" not in reader.fieldnames
        assert "rule_id" not in reader.fieldnames
        for record in reader:
            assert record["annotator_class"] == ""


def test_the_frame_keeps_the_autosut_label_for_adjudication(tmp_path) -> None:
    rows = _rows({name: target + 5 for name, target in sampler.STRATUM_TARGET.items()})
    sample = sampler.draw_sample(rows, seed=3)
    frame = tmp_path / "frame.csv"
    sampler.write_frame(sample, frame)
    with frame.open(encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        assert "autosut_class" in reader.fieldnames
