#!/usr/bin/env python3
"""
Evaluate manual adjudication of the CF/VMR/ID routing-policy labels.

Input:
  results/audit/compatibility_validation_sample.csv

Outputs:
  results/compatibility_validation_summary.json
  results/audit/compatibility_validation_confusion.csv
  results/audit/compatibility_validation_disagreements.csv

This script is deterministic and dependency-free. It is safe to run even when
manual labels are still empty; in that case it emits a "pending" summary with
undefined agreement statistics rather than a fabricated zero-accuracy value.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
RESULTS_DIR = ROOT / "results"
AUDIT_DIR = RESULTS_DIR / "audit"
SAMPLE_CSV = AUDIT_DIR / "compatibility_validation_sample.csv"
SUMMARY_JSON = RESULTS_DIR / "compatibility_validation_summary.json"
CONFUSION_CSV = AUDIT_DIR / "compatibility_validation_confusion.csv"
DISAGREEMENTS_CSV = AUDIT_DIR / "compatibility_validation_disagreements.csv"

CLASSES = ["CF", "VMR", "ID"]


def display_path(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def parse_bool(value: str) -> bool | None:
    v = (value or "").strip().lower()
    if v in {"1", "true", "yes", "y"}:
        return True
    if v in {"0", "false", "no", "n"}:
        return False
    return None


def safe_pct(num: int, den: int) -> float | None:
    """Return a percentage, or ``None`` when no observations exist."""
    return round((num / den) * 100.0, 1) if den else None


def cohen_kappa(confusion: dict[str, dict[str, int]], labels: list[str]) -> float | None:
    """Compute Cohen's kappa for a square confusion matrix."""
    n = sum(confusion[a][b] for a in labels for b in labels)
    if n == 0:
        return None

    po = sum(confusion[l][l] for l in labels) / n

    row_totals = {l: sum(confusion[l][b] for b in labels) for l in labels}
    col_totals = {l: sum(confusion[a][l] for a in labels) for l in labels}

    pe = sum((row_totals[l] / n) * (col_totals[l] / n) for l in labels)
    if pe >= 1.0:
        return None
    return round((po - pe) / (1.0 - pe), 4)


def main() -> None:
    if not SAMPLE_CSV.exists():
        raise SystemExit(f"[validation] missing sample CSV: {SAMPLE_CSV}")

    rows = []
    with SAMPLE_CSV.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)

    total_rows = len(rows)
    annotated = []
    for row in rows:
        manual = (row.get("manual_expected_class") or "").strip().upper()
        if manual in CLASSES:
            annotated.append(row)

    confusion = {a: {b: 0 for b in CLASSES} for a in CLASSES}
    disagreements = []

    explicit_total = 0
    explicit_match = 0
    fallback_total = 0
    fallback_match = 0

    for row in annotated:
        pred = (
            row.get("policy_label") or row.get("predicted_class") or ""
        ).strip().upper()
        manual = (row.get("manual_expected_class") or "").strip().upper()
        if pred not in CLASSES or manual not in CLASSES:
            continue

        confusion[pred][manual] += 1

        verdict = parse_bool(row.get("manual_verdict_match", ""))
        if verdict is None:
            verdict = pred == manual

        is_fallback = parse_bool(str(row.get("is_fallback", "")))
        if is_fallback is None:
            is_fallback = str(row.get("is_fallback", "")).strip().lower() == "true"

        if is_fallback:
            fallback_total += 1
            fallback_match += int(verdict)
        else:
            explicit_total += 1
            explicit_match += int(verdict)

        if not verdict:
            disagreements.append({
                "sample_class": row.get("sample_class", ""),
                "technique_name": row.get("technique_name", ""),
                "technique_stix_id": row.get("technique_stix_id", ""),
                "technique_external_id": row.get("technique_external_id", ""),
                "attack_url": row.get("attack_url", ""),
                "predicted_class": pred,
                "manual_expected_class": manual,
                "rule_id": row.get("rule_id", ""),
                "is_fallback": str(is_fallback),
                "manual_notes": row.get("manual_notes", ""),
                "reviewer": row.get("reviewer", ""),
            })

    compared_rows = sum(confusion[a][b] for a in CLASSES for b in CLASSES)
    matches = sum(confusion[l][l] for l in CLASSES)

    if compared_rows == 0:
        status = "pending_manual_labels"
    elif compared_rows < total_rows:
        status = "partial_manual_labels"
    else:
        status = "ready"

    summary = {
        "status": status,
        "label_semantics": (
            "CF/VMR/ID are heuristic routing-policy labels, not observed "
            "minimum-backend requirements or validated ground truth"
        ),
        "sample_csv": display_path(SAMPLE_CSV),
        "total_sample_rows": total_rows,
        "annotated_rows": len(annotated),
        "manual_label_completion_pct": safe_pct(len(annotated), total_rows),
        "rows_used_for_metrics": compared_rows,
        "pending_rows": max(total_rows - len(annotated), 0),
        "agreement_count": matches,
        "agreement_pct": safe_pct(matches, compared_rows),
        "cohen_kappa": cohen_kappa(confusion, CLASSES),
        "explicit_rule_rows": explicit_total,
        "explicit_rule_agreement_pct": safe_pct(explicit_match, explicit_total),
        "fallback_rows": fallback_total,
        "fallback_agreement_pct": safe_pct(fallback_match, fallback_total),
        "disagreement_rows": len(disagreements),
    }

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    AUDIT_DIR.mkdir(parents=True, exist_ok=True)

    with SUMMARY_JSON.open("w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    with CONFUSION_CSV.open("w", newline="", encoding="utf-8") as f:
        fieldnames = ["predicted_class"] + CLASSES + ["row_total"]
        writer = csv.DictWriter(f, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        for pred in CLASSES:
            row = {"predicted_class": pred}
            row_total = 0
            for manual in CLASSES:
                val = confusion[pred][manual]
                row[manual] = val
                row_total += val
            row["row_total"] = row_total
            writer.writerow(row)

    with DISAGREEMENTS_CSV.open("w", newline="", encoding="utf-8") as f:
        fieldnames = [
            "sample_class",
            "technique_name",
            "technique_stix_id",
            "technique_external_id",
            "attack_url",
            "predicted_class",
            "manual_expected_class",
            "rule_id",
            "is_fallback",
            "manual_notes",
            "reviewer",
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        for row in disagreements:
            writer.writerow(row)

    print("[validation] compatibility manual-validation summary")
    for k, v in summary.items():
        print(f"  {k}: {v}")
    print(f"[validation] wrote {SUMMARY_JSON}")
    print(f"[validation] wrote {CONFUSION_CSV}")
    print(f"[validation] wrote {DISAGREEMENTS_CSV}")


if __name__ == "__main__":
    main()
