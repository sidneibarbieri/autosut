"""Execution certification: certify success only from an observed effect.

An emulator that reads a completed transport response or a zero process exit code
as success will certify attempts that produced no effect -- the class of false
positive behind the ShadowRay HTTP-400-as-success bug. This module contrasts three
certifiers on the same execution outcomes and reports how many false successes each
admits and how many genuine successes each retains.

The certifiers are deliberately simple; the point is not a clever certifier but that
status- and exit-code-based certification, common in emulators, cannot separate an
attempted action from an achieved effect, while an evidence-gated certifier can.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class FailureMode(str, Enum):
    transport_error = "transport_error"          # e.g. HTTP 4xx/5xx
    accepted_no_effect = "accepted_no_effect"    # e.g. HTTP 2xx but nothing happened
    zero_exit_no_postcondition = "zero_exit_no_postcondition"
    timeout = "timeout"
    genuine_success = "genuine_success"


class ExecutionOutcome(StrictModel):
    """One attempted action's observable signals and its ground-truth label.

    ``truly_successful`` is the adjudicated ground truth for the benchmark; the three
    certifiers never see it -- it is used only to score them.
    """

    case_id: str
    mode: FailureMode
    http_status: int | None = None
    exit_code: int | None = None
    effect_observed: bool = False
    evidence_predicate_met: bool = False
    truly_successful: bool = False


def certify_status_only(outcome: ExecutionOutcome) -> bool:
    return outcome.http_status is not None and 200 <= outcome.http_status < 300


def certify_exit_code_only(outcome: ExecutionOutcome) -> bool:
    return outcome.exit_code == 0


def certify_evidence_gated(outcome: ExecutionOutcome) -> bool:
    return outcome.effect_observed and outcome.evidence_predicate_met


class CertifierResult(StrictModel):
    certifier: str
    certified: int
    false_success: int          # certified but truly failed
    missed_success: int         # not certified but truly succeeded
    false_success_rate: float   # over truly-failed outcomes
    retained_success_rate: float  # over truly-successful outcomes


def evaluate_certifier(
    name: str,
    certifier,
    outcomes: list[ExecutionOutcome],
) -> CertifierResult:
    failed = [o for o in outcomes if not o.truly_successful]
    succeeded = [o for o in outcomes if o.truly_successful]
    certified = [o for o in outcomes if certifier(o)]
    false_success = sum(1 for o in failed if certifier(o))
    missed_success = sum(1 for o in succeeded if not certifier(o))
    return CertifierResult(
        certifier=name,
        certified=len(certified),
        false_success=false_success,
        missed_success=missed_success,
        false_success_rate=(false_success / len(failed)) if failed else 0.0,
        retained_success_rate=(
            (len(succeeded) - missed_success) / len(succeeded)
        ) if succeeded else 0.0,
    )


CERTIFIERS = {
    "status_only": certify_status_only,
    "exit_code_only": certify_exit_code_only,
    "evidence_gated": certify_evidence_gated,
}


def evaluate_all(outcomes: list[ExecutionOutcome]) -> list[CertifierResult]:
    return [evaluate_certifier(name, fn, outcomes) for name, fn in CERTIFIERS.items()]
