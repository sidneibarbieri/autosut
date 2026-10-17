from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import pytest

SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "measurement" / "sut" / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

import longitudinal_gap  # noqa: E402


def test_release_arguments_require_a_label_and_a_path() -> None:
    assert longitudinal_gap.parse_release("18.1=data/a.json") == ("18.1", Path("data/a.json"))
    with pytest.raises(argparse.ArgumentTypeError):
        longitudinal_gap.parse_release("data/a.json")


def test_a_release_is_measured_with_the_pipeline_functions(tmp_path) -> None:
    technique = {
        "type": "attack-pattern", "id": "attack-pattern--1", "name": "Benign Step",
        "description": "", "x_mitre_platforms": ["Linux"],
        "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "discovery"}],
    }
    bundle = tmp_path / "bundle.json"
    bundle.write_text(json.dumps({"type": "bundle", "objects": [technique]}))
    row = longitudinal_gap.measure_release("test", bundle)
    assert row.active_techniques == 1
    assert row.technique_platform_pct == 100.0
    assert row.cf_pct == 100.0
    assert row.usable_campaigns == 0
    assert len(row.bundle_sha256) == 64
