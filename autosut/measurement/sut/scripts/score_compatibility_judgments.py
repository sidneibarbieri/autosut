#!/usr/bin/env python3
"""Score AutoSUT's routing labels against the consensus of independent LLM judges.

The reference label for an item is the judges' label when every judge agrees.
Items where the judges disagree are boundary cases: they are counted and reported,
never forced into a class. Metrics are reported overall and separately for the
explicit-rule and fallback strata.
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
AUDIT_DIR = SCRIPTS_DIR / "results" / "audit"
FRAME = AUDIT_DIR / "compatibility_validation_frame.csv"
SAMPLE_MANIFEST = AUDIT_DIR / "compatibility_validation_manifest.json"
JUDGMENT_ROOT = AUDIT_DIR / "compatibility_judgments"
OUTPUT = SCRIPTS_DIR / "results" / "compatibility_judge_validation.json"
LABELS = ("CF", "VMR", "ID")


def load_frame() -> dict[str, dict]:
    with FRAME.open(encoding="utf-8") as handle:
        return {row["item_id"]: row for row in csv.DictReader(handle)}


def load_judge_labels(judge: str) -> dict[str, str | None]:
    labels = {}
    for path in sorted((JUDGMENT_ROOT / judge).glob("CMP-*.json")):
        judgment = json.loads(path.read_text())["judgment"]
        labels[judgment["item_id"]] = judgment["label"]
    return labels


def cohen_kappa(pairs: list[tuple[str, str]]) -> float | None:
    if not pairs:
        return None
    observed = sum(first == second for first, second in pairs) / len(pairs)
    first_counts = Counter(first for first, _ in pairs)
    second_counts = Counter(second for _, second in pairs)
    expected = sum(first_counts[label] * second_counts[label] for label in LABELS) / len(pairs) ** 2
    return None if expected == 1 else round((observed - expected) / (1 - expected), 3)


def classification_metrics(pairs: list[tuple[str, str]]) -> dict:
    """Metrics for (reference, predicted) pairs."""
    confusion = {reference: {predicted: 0 for predicted in LABELS} for reference in LABELS}
    for reference, predicted in pairs:
        confusion[reference][predicted] += 1
    per_class = {}
    for label in LABELS:
        true_positive = confusion[label][label]
        predicted_total = sum(confusion[reference][label] for reference in LABELS)
        reference_total = sum(confusion[label].values())
        precision = true_positive / predicted_total if predicted_total else None
        recall = true_positive / reference_total if reference_total else None
        f1 = (2 * precision * recall / (precision + recall)
              if precision and recall else (0.0 if reference_total else None))
        per_class[label] = {
            "support": reference_total,
            "precision": None if precision is None else round(precision, 3),
            "recall": None if recall is None else round(recall, 3),
            "f1": None if f1 is None else round(f1, 3),
        }
    scored = [values["f1"] for values in per_class.values() if values["f1"] is not None]
    return {
        "items": len(pairs),
        "accuracy": round(sum(reference == predicted for reference, predicted in pairs) / len(pairs), 3)
        if pairs else None,
        "macro_f1": round(sum(scored) / len(scored), 3) if scored else None,
        "per_class": per_class,
        "confusion_reference_by_predicted": confusion,
    }


def consensus(labels_by_judge: dict[str, dict[str, str | None]], item_id: str) -> str | None:
    labels = {labels[item_id] for labels in labels_by_judge.values()}
    return labels.pop() if len(labels) == 1 and None not in labels else None


def population_estimate(frame: dict[str, dict], reference: dict[str, str | None],
                        population_strata: dict[str, int]) -> dict[str, float]:
    """Reweight each stratum's consensus labels by that stratum's population size."""
    shares = {label: 0.0 for label in (*LABELS, "boundary")}
    total = sum(population_strata.values())
    for stratum, size in population_strata.items():
        items = [item for item in frame if frame[item]["stratum"] == stratum]
        for item in items:
            shares[reference[item] or "boundary"] += size / len(items)
    return {label: round(100 * weight / total, 1) for label, weight in shares.items()}


def build_report(judges: list[str]) -> dict:
    frame = load_frame()
    labels_by_judge = {judge: load_judge_labels(judge) for judge in judges}
    missing = {judge: sorted(set(frame) - set(labels)) for judge, labels in labels_by_judge.items()}
    if any(missing.values()):
        raise ValueError(f"judgments missing for some items: {missing}")

    first, second = judges[0], judges[1]
    both_labeled = [item for item in frame
                    if labels_by_judge[first][item] and labels_by_judge[second][item]]
    reference = {item: consensus(labels_by_judge, item) for item in frame}
    agreed = [item for item in frame if reference[item] is not None]

    def autosut_vs_reference(items: list[str]) -> dict:
        return classification_metrics([(reference[item], frame[item]["autosut_class"]) for item in items])

    rule_items = [item for item in agreed if frame[item]["stratum"] != "fallback"]
    fallback_items = [item for item in agreed if frame[item]["stratum"] == "fallback"]
    return {
        "judges": judges,
        "sample_size": len(frame),
        "abstentions": {judge: sum(label is None for label in labels.values())
                        for judge, labels in labels_by_judge.items()},
        "judge_distribution": {judge: dict(Counter(label or "none" for label in labels.values()))
                               for judge, labels in labels_by_judge.items()},
        "inter_judge": {
            "items_labeled_by_both": len(both_labeled),
            "agreement": round(len(agreed) / len(frame), 3),
            "cohen_kappa": cohen_kappa([(labels_by_judge[first][item], labels_by_judge[second][item])
                                        for item in both_labeled]),
        },
        "boundary_items": len(frame) - len(agreed),
        "population_estimate_pct": population_estimate(
            frame, reference, json.loads(SAMPLE_MANIFEST.read_text())["population_stratum_sizes"]
        ),
        "autosut_vs_consensus": {
            "all": autosut_vs_reference(agreed),
            "explicit_rule_strata": autosut_vs_reference(rule_items),
            "fallback_stratum": autosut_vs_reference(fallback_items),
        },
        "autosut_vs_each_judge": {
            judge: classification_metrics([(labels[item], frame[item]["autosut_class"])
                                           for item in frame if labels[item]])
            for judge, labels in labels_by_judge.items()
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--judge", action="append", required=True)
    args = parser.parse_args()
    if len(args.judge) < 2:
        raise SystemExit("at least two judges are required")
    report = build_report(args.judge)
    OUTPUT.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: report[key] for key in
                      ("abstentions", "inter_judge", "boundary_items", "population_estimate_pct")}, indent=2))
    overall = report["autosut_vs_consensus"]
    for scope in ("all", "explicit_rule_strata", "fallback_stratum"):
        print(f"{scope:22} n={overall[scope]['items']:3} accuracy={overall[scope]['accuracy']} "
              f"macro_f1={overall[scope]['macro_f1']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
