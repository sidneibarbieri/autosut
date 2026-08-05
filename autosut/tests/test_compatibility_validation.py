from __future__ import annotations

import csv
import importlib.util
import json
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODULE_PATH = (
    PROJECT_ROOT
    / "measurement"
    / "sut"
    / "scripts"
    / "evaluate_compatibility_validation.py"
)


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "autosut_test_evaluate_compatibility_validation",
        MODULE_PATH,
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _run_evaluator(tmp_path: Path, rows: list[dict[str, str]]) -> dict:
    module = _load_module()
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()

    module.SAMPLE_CSV = audit_dir / "compatibility_validation_sample.csv"
    module.SUMMARY_JSON = tmp_path / "compatibility_validation_summary.json"
    module.CONFUSION_CSV = audit_dir / "compatibility_validation_confusion.csv"
    module.DISAGREEMENTS_CSV = (
        audit_dir / "compatibility_validation_disagreements.csv"
    )
    module.RESULTS_DIR = tmp_path
    module.AUDIT_DIR = audit_dir

    fieldnames = [
        "sample_class",
        "technique_name",
        "technique_stix_id",
        "technique_external_id",
        "attack_url",
        "policy_label",
        "predicted_class",
        "rule_id",
        "is_fallback",
        "manual_expected_class",
        "manual_verdict_match",
        "manual_notes",
        "reviewer",
    ]
    with module.SAMPLE_CSV.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    module.main()
    return json.loads(module.SUMMARY_JSON.read_text(encoding="utf-8"))


def _row(*, manual: str = "", policy_label: str = "VMR") -> dict[str, str]:
    return {
        "sample_class": policy_label,
        "technique_name": "Synthetic technique",
        "technique_stix_id": "attack-pattern--synthetic",
        "technique_external_id": "T0000",
        "attack_url": "",
        "policy_label": policy_label,
        # Intentionally conflict with policy_label to verify the canonical
        # routing-policy field takes precedence over the legacy column.
        "predicted_class": "CF" if policy_label != "CF" else "VMR",
        "rule_id": "R8_DEFAULT_VMR",
        "is_fallback": "True",
        "manual_expected_class": manual,
        "manual_verdict_match": "",
        "manual_notes": "",
        "reviewer": "",
    }


def test_pending_labels_do_not_emit_fake_zero_agreement(tmp_path: Path) -> None:
    summary = _run_evaluator(tmp_path, [_row(), _row(policy_label="ID")])

    assert summary["status"] == "pending_manual_labels"
    assert summary["annotated_rows"] == 0
    assert summary["manual_label_completion_pct"] == 0.0
    assert summary["agreement_pct"] is None
    assert summary["cohen_kappa"] is None
    assert summary["explicit_rule_agreement_pct"] is None
    assert summary["fallback_agreement_pct"] is None
    assert "routing-policy labels" in summary["label_semantics"]


def test_partial_labels_are_not_marked_ready(tmp_path: Path) -> None:
    summary = _run_evaluator(
        tmp_path,
        [_row(manual="VMR", policy_label="VMR"), _row(policy_label="ID")],
    )

    assert summary["status"] == "partial_manual_labels"
    assert summary["annotated_rows"] == 1
    assert summary["manual_label_completion_pct"] == 50.0
    assert summary["agreement_pct"] == 100.0


def test_ready_requires_all_manual_labels(tmp_path: Path) -> None:
    summary = _run_evaluator(
        tmp_path,
        [
            _row(manual="VMR", policy_label="VMR"),
            _row(manual="CF", policy_label="ID"),
        ],
    )

    assert summary["status"] == "ready"
    assert summary["manual_label_completion_pct"] == 100.0
    assert summary["rows_used_for_metrics"] == 2
    assert summary["agreement_pct"] == 50.0
