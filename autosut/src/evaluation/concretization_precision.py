"""Measure verifier-gated concretization precision against an adjudicated gold standard.

The automation's value is not "fills every field" but "commits only correct bindings and
abstains otherwise". So each procedure step falls into exactly one outcome:

  - correct:   the system committed a binding and it matches the gold standard;
  - wrong:     the system committed a binding that differs from the gold standard (unsafe);
  - abstained: the verifier admitted nothing, so the step is flagged for a human.

precision-on-commitments and the wrong-commit rate are the safety-relevant numbers. A raw
LLM without the verifier trades abstentions for wrong commits; that is the contribution the
verifier makes, and it is what this module quantifies.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class StepOutcome(str, Enum):
    correct = "correct"
    wrong = "wrong"
    abstained = "abstained"


class GoldBinding(StrictModel):
    """The adjudicated-correct template and bindings for one procedure step."""

    technique_id: str
    template_id: str
    bindings: dict[str, str]


class CommittedBinding(StrictModel):
    """What one arm committed for a step after its verifier ran.

    ``committed`` is False when the verifier admitted no candidate; the template and
    bindings are then ignored, because the step abstains.
    """

    technique_id: str
    committed: bool
    template_id: str | None = None
    bindings: dict[str, str] = Field(default_factory=dict)


class StepJudgement(StrictModel):
    technique_id: str
    outcome: StepOutcome


class PrecisionResult(StrictModel):
    arm: str
    total_steps: int
    correct: int
    wrong: int
    abstained: int
    precision_on_commitments: float
    commitment_rate: float
    abstention_rate: float
    wrong_commit_rate: float
    judgements: list[StepJudgement]


def _judge_step(committed: CommittedBinding, gold: GoldBinding) -> StepOutcome:
    if not committed.committed:
        return StepOutcome.abstained
    matches = (
        committed.template_id == gold.template_id
        and committed.bindings == gold.bindings
    )
    return StepOutcome.correct if matches else StepOutcome.wrong


def measure_precision(
    arm: str,
    committed: list[CommittedBinding],
    gold: list[GoldBinding],
) -> PrecisionResult:
    """Judge each committed step against the gold standard and roll up the rates.

    Every committed step must have a gold entry; a missing one is a real setup error and
    is raised, never silently skipped.
    """

    gold_by_technique = {item.technique_id: item for item in gold}
    missing = {step.technique_id for step in committed} - set(gold_by_technique)
    if missing:
        raise ValueError(f"no gold standard for steps: {sorted(missing)}")

    judgements = [
        StepJudgement(
            technique_id=step.technique_id,
            outcome=_judge_step(step, gold_by_technique[step.technique_id]),
        )
        for step in committed
    ]
    correct = sum(1 for judgement in judgements if judgement.outcome is StepOutcome.correct)
    wrong = sum(1 for judgement in judgements if judgement.outcome is StepOutcome.wrong)
    abstained = sum(1 for judgement in judgements if judgement.outcome is StepOutcome.abstained)
    total = len(judgements)
    committed_count = correct + wrong

    return PrecisionResult(
        arm=arm,
        total_steps=total,
        correct=correct,
        wrong=wrong,
        abstained=abstained,
        precision_on_commitments=(correct / committed_count) if committed_count else 0.0,
        commitment_rate=(committed_count / total) if total else 0.0,
        abstention_rate=(abstained / total) if total else 0.0,
        wrong_commit_rate=(wrong / total) if total else 0.0,
        judgements=judgements,
    )
