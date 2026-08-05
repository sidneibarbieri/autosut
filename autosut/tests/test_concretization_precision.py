from __future__ import annotations

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from evaluation.concretization_precision import (
    CommittedBinding,
    GoldBinding,
    StepOutcome,
    measure_precision,
)


GOLD = [
    GoldBinding(technique_id="T1190", template_id="http-exploit", bindings={"port": "8265"}),
    GoldBinding(technique_id="T1059", template_id="run-python", bindings={"cmd": "id"}),
    GoldBinding(technique_id="T1005", template_id="read-file", bindings={"path": "/etc/passwd"}),
]


def test_correct_wrong_and_abstained_are_separated():
    committed = [
        # correct: matches gold exactly
        CommittedBinding(technique_id="T1190", committed=True, template_id="http-exploit",
                         bindings={"port": "8265"}),
        # wrong: committed but the binding differs
        CommittedBinding(technique_id="T1059", committed=True, template_id="run-python",
                         bindings={"cmd": "rm -rf /"}),
        # abstained: the verifier admitted nothing
        CommittedBinding(technique_id="T1005", committed=False),
    ]

    result = measure_precision("verifier_gated", committed, GOLD)

    outcomes = {j.technique_id: j.outcome for j in result.judgements}
    assert outcomes["T1190"] is StepOutcome.correct
    assert outcomes["T1059"] is StepOutcome.wrong
    assert outcomes["T1005"] is StepOutcome.abstained


def test_rates_reward_abstention_over_wrong_commitment():
    # One correct commit, one abstention, zero wrong: perfect precision, no unsafe commit.
    committed = [
        CommittedBinding(technique_id="T1190", committed=True, template_id="http-exploit",
                         bindings={"port": "8265"}),
        CommittedBinding(technique_id="T1059", committed=False),
        CommittedBinding(technique_id="T1005", committed=False),
    ]

    result = measure_precision("verifier_gated", committed, GOLD)

    assert result.correct == 1
    assert result.wrong == 0
    assert result.abstained == 2
    assert result.precision_on_commitments == 1.0
    assert result.wrong_commit_rate == 0.0
    assert result.commitment_rate == pytest.approx(1 / 3)
    assert result.abstention_rate == pytest.approx(2 / 3)


def test_missing_gold_is_a_real_error_not_skipped():
    committed = [CommittedBinding(technique_id="T9999", committed=True, template_id="x",
                                  bindings={})]
    with pytest.raises(ValueError, match="no gold standard"):
        measure_precision("verifier_gated", committed, GOLD)
