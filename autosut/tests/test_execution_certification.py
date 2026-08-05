from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from evaluation.execution_certification import (
    ExecutionOutcome,
    FailureMode,
    evaluate_all,
)


# A controlled failure-mode benchmark. effect_observed / evidence_predicate_met stand in
# for an independent observation of the contract-specified effect; a real campaign
# populates them from actual runtime evidence (marker files, response bodies).
BENCHMARK = [
    # ShadowRay class: transport error, but the shell that issued it exited 0.
    ExecutionOutcome(case_id="A", mode=FailureMode.transport_error,
                     http_status=400, exit_code=0, effect_observed=False,
                     evidence_predicate_met=False, truly_successful=False),
    # Accepted but nothing happened: HTTP 2xx with no effect.
    ExecutionOutcome(case_id="B", mode=FailureMode.accepted_no_effect,
                     http_status=202, exit_code=0, effect_observed=False,
                     evidence_predicate_met=False, truly_successful=False),
    # Command exited 0 but its postcondition never held.
    ExecutionOutcome(case_id="C", mode=FailureMode.zero_exit_no_postcondition,
                     http_status=None, exit_code=0, effect_observed=False,
                     evidence_predicate_met=False, truly_successful=False),
    # Timeout after a partial effect.
    ExecutionOutcome(case_id="D", mode=FailureMode.timeout,
                     http_status=None, exit_code=124, effect_observed=False,
                     evidence_predicate_met=False, truly_successful=False),
    # Genuine successes: the effect occurred and the evidence predicate held.
    ExecutionOutcome(case_id="E", mode=FailureMode.genuine_success,
                     http_status=200, exit_code=0, effect_observed=True,
                     evidence_predicate_met=True, truly_successful=True),
    ExecutionOutcome(case_id="F", mode=FailureMode.genuine_success,
                     http_status=200, exit_code=0, effect_observed=True,
                     evidence_predicate_met=True, truly_successful=True),
]


def _by_name(results):
    return {r.certifier: r for r in results}


def test_status_and_exit_code_admit_false_successes():
    results = _by_name(evaluate_all(BENCHMARK))
    # exit-code-only certifies A, B, C (exit 0 yet failed) -> 3 false successes.
    assert results["exit_code_only"].false_success == 3
    # status-only certifies B (HTTP 202 accepted, no effect) -> 1 false success.
    assert results["status_only"].false_success == 1


def test_evidence_gate_admits_no_false_success_and_retains_all_true_successes():
    results = _by_name(evaluate_all(BENCHMARK))
    evidence = results["evidence_gated"]
    assert evidence.false_success == 0
    assert evidence.false_success_rate == 0.0
    assert evidence.retained_success_rate == 1.0
    # It does not achieve zero false success by rejecting everything:
    assert evidence.certified == 2


def test_evidence_gate_is_the_only_certifier_with_zero_false_success():
    results = evaluate_all(BENCHMARK)
    zero_false = [r.certifier for r in results if r.false_success == 0]
    assert zero_false == ["evidence_gated"]
