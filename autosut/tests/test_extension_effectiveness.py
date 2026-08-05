from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from evaluation.extension_effectiveness import build_extension_effectiveness_report


def test_extension_arms_are_monotonic_and_keep_unknowns_unknown() -> None:
    bundle = json.loads(
        (PROJECT_ROOT / "release/enriched/C0045.stix.json").read_text()
    )
    report = build_extension_effectiveness_report(bundle)
    resolved = [arm.resolved_cells for arm in report.arms]
    assert resolved == sorted(resolved)
    assert report.arms[-1].resolved_cells > report.arms[0].resolved_cells
    unresolved = {
        (cell.technique_id, cell.dimension)
        for cell in report.unresolved_full_arm_cells
    }
    assert ("T1190", "version_range") in unresolved
    assert ("T1190", "cpe23_uri") in unresolved
    assert any(
        item.removed_dimension == "backend_cue"
        and item.resolved_cell_drop > 0
        for item in report.ablations
    )

