from __future__ import annotations

import sys
from pathlib import Path

import pytest

SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "measurement" / "sut" / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

import judge_compatibility_labels as judge  # noqa: E402
import score_compatibility_judgments as score  # noqa: E402


@pytest.mark.parametrize(
    ("content", "label"),
    [
        ('{"label": "VMR", "reason": "kernel module"}', "VMR"),
        ('Thinking...\n{"label": "cf", "reason": "userspace"}', "CF"),
        ('{"label": "maybe", "reason": "unsure"}', None),
        ("no json here", None),
        ('{"label": "ID", "reason": ', None),
    ],
)
def test_reply_parsing_accepts_only_declared_labels(content, label) -> None:
    assert judge.parse_label(content)[0] == label


def test_the_judge_prompt_never_carries_the_autosut_label() -> None:
    row = {field: "x" for field in judge.ITEM_FIELDS}
    row.update(item_id="CMP-001", autosut_class="VMR", rule_id="R8_DEFAULT_VMR")
    prompt = judge.item_prompt(row)
    assert "autosut" not in prompt.lower()
    assert "R8_DEFAULT" not in prompt


def test_kappa_is_one_for_perfect_agreement_and_none_without_pairs() -> None:
    assert score.cohen_kappa([("CF", "CF"), ("VMR", "VMR"), ("ID", "ID")]) == 1.0
    assert score.cohen_kappa([]) is None


def test_metrics_report_per_class_precision_and_recall() -> None:
    pairs = [("CF", "VMR"), ("VMR", "VMR"), ("VMR", "VMR"), ("ID", "ID")]
    metrics = score.classification_metrics(pairs)
    assert metrics["accuracy"] == 0.75
    assert metrics["per_class"]["CF"]["recall"] == 0.0
    assert metrics["per_class"]["VMR"]["precision"] == round(2 / 3, 3)
    assert metrics["confusion_reference_by_predicted"]["CF"]["VMR"] == 1


def test_consensus_requires_every_judge_to_agree() -> None:
    labels = {"a": {"CMP-1": "CF", "CMP-2": "CF"}, "b": {"CMP-1": "CF", "CMP-2": "VMR"}}
    assert score.consensus(labels, "CMP-1") == "CF"
    assert score.consensus(labels, "CMP-2") is None


def test_population_estimate_reweights_each_stratum_by_its_population() -> None:
    frame = {"a": {"stratum": "rule"}, "b": {"stratum": "fallback"}, "c": {"stratum": "fallback"}}
    reference = {"a": "CF", "b": "VMR", "c": None}
    estimate = score.population_estimate(frame, reference, {"rule": 10, "fallback": 90})
    assert estimate == {"CF": 10.0, "VMR": 45.0, "ID": 0.0, "boundary": 45.0}
