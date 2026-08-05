from __future__ import annotations

import importlib.util
import csv
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
PIPELINE_PATH = (
    PROJECT_ROOT
    / "measurement"
    / "sut"
    / "scripts"
    / "sut_measurement_pipeline.py"
)


def _load_pipeline():
    spec = importlib.util.spec_from_file_location(
        "autosut_test_sut_measurement_pipeline",
        PIPELINE_PATH,
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _enterprise_compatibility(module):
    objects = module.load_bundle(module.ENTERPRISE_FILE)
    by_type, by_id = module.index_objects_by_type(objects)
    rel_fwd, _, _ = module.build_relationship_index(by_type["relationship"])
    techniques = by_type["attack-pattern"]
    return techniques, rel_fwd, by_id, module.analyze_compatibility(
        techniques,
        rel_fwd,
        by_id,
    )


def test_compatibility_denominators_are_not_mixed() -> None:
    module = _load_pipeline()
    _, _, _, result = _enterprise_compatibility(module)

    assert result["total"] == 691
    assert result["explicit_count"] == 226
    assert result["fallback_count"] == 465
    assert result["explicit_pct"] == 32.7
    assert result["fallback_pct"] == 67.3

    # 91.6% is explicit-only: 207 / 226.  It is not a post-step coverage
    # percentage and therefore cannot be subtracted from 32.7%.
    assert result["explicit_non_cf_count"] == 207
    assert result["explicit_non_cf_explicit_only_pct"] == 91.6
    assert result["explicit_non_cf_corpus_pct"] == 30.0

    # Final non-CF composition is corpus-wide and must be calculated directly
    # from counts (672 / 691), not by summing rounded VMR and ID percentages.
    assert result["final_non_cf_count"] == 672
    assert result["final_non_cf_corpus_pct"] == 97.3
    assert result["resolved_count"] == 691
    assert result["resolved_pct"] == 100.0


def test_rule_trace_describes_policy_cues_not_backend_ground_truth() -> None:
    module = _load_pipeline()
    linux_trace = module.classify_technique_compatibility_trace(
        {
            "id": "attack-pattern--linux-cue",
            "name": "Synthetic Linux technique",
            "x_mitre_platforms": ["Linux"],
        },
        {},
        {},
    )
    fallback_trace = module.classify_technique_compatibility_trace(
        {
            "id": "attack-pattern--fallback",
            "name": "Synthetic unspecified technique",
        },
        {},
        {},
    )

    assert linux_trace["class"] == "CF"
    assert linux_trace["rule_desc"] == "platform labels match configured CF cue set"
    assert "feasible" not in linux_trace["rule_desc"]
    assert fallback_trace["class"] == "VMR"
    assert fallback_trace["is_fallback"] is True
    assert "default policy label" in fallback_trace["rule_desc"]


def test_compatibility_sensitivity_uses_corpus_wide_non_cf_denominator() -> None:
    module = _load_pipeline()
    techniques, rel_fwd, by_id, _ = _enterprise_compatibility(module)

    rows = module.analyze_compatibility_default_sensitivity(
        techniques,
        rel_fwd,
        by_id,
    )
    by_default = {row["default_class"]: row for row in rows}

    assert by_default["CF"]["non_cf_corpus_pct"] == 30.0
    assert by_default["VMR"]["non_cf_corpus_pct"] == 97.3
    assert by_default["ID"]["non_cf_corpus_pct"] == 97.3
    assert by_default["UNRESOLVED"]["non_cf_corpus_pct"] == 30.0
    assert {
        row["explicit_non_cf_explicit_only_pct"] for row in rows
    } == {91.6}


def test_denominator_audit_surface_names_scope_explicitly() -> None:
    module = _load_pipeline()
    _, _, _, result = _enterprise_compatibility(module)

    rows = module.build_compatibility_denominator_summary(
        result,
        manual_sample_size=36,
        manual_labels_completed=0,
    )
    by_metric = {row["metric"]: row for row in rows}

    explicit_non_cf = by_metric["explicit_non_cf_share"]
    assert (explicit_non_cf["numerator"], explicit_non_cf["denominator"]) == (
        207,
        226,
    )
    assert explicit_non_cf["denominator_scope"] == "explicit-only"
    assert explicit_non_cf["percentage"] == 91.6

    assignment_gain = (
        by_metric["final_policy_label_coverage"]["percentage"]
        - by_metric["explicit_rule_assignment_coverage"]["percentage"]
    )
    assert assignment_gain == 67.3

    manual = by_metric["manual_label_completion"]
    assert (manual["numerator"], manual["denominator"]) == (0, 36)
    assert "not accuracy" in manual["interpretation"]


def test_pipeline_regeneration_preserves_manual_annotations(tmp_path: Path) -> None:
    module = _load_pipeline()
    existing = tmp_path / "compatibility_validation_sample.csv"
    with existing.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "technique_stix_id",
                "manual_expected_class",
                "manual_verdict_match",
                "manual_notes",
                "reviewer",
            ],
        )
        writer.writeheader()
        writer.writerow(
            {
                "technique_stix_id": "attack-pattern--preserved",
                "manual_expected_class": "ID",
                "manual_verdict_match": "false",
                "manual_notes": "requires adjudication",
                "reviewer": "R1",
            }
        )

    rows = [
        {
            "technique_stix_id": "attack-pattern--preserved",
            "manual_expected_class": "",
            "manual_verdict_match": "",
            "manual_notes": "",
            "reviewer": "",
        },
        {
            "technique_stix_id": "attack-pattern--new",
            "manual_expected_class": "",
            "manual_verdict_match": "",
            "manual_notes": "",
            "reviewer": "",
        },
    ]

    merged = module.merge_compatibility_manual_annotations(rows, existing)

    assert merged[0]["manual_expected_class"] == "ID"
    assert merged[0]["manual_notes"] == "requires adjudication"
    assert merged[0]["reviewer"] == "R1"
    assert merged[1]["manual_expected_class"] == ""
