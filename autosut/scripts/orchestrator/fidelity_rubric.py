"""Fidelity rubric for campaign replay realism.

AutoSUT classifies each technique execution as ``faithful``, ``adapted``, or
``inspired`` with a five-question rubric applied to :class:`TechniqueOutcome`
records produced by the orchestrator.

The rubric questions
--------------------

- **Q1** Was the central mechanism of the technique preserved?
- **Q2** Was the relevant substrate (OS / runtime / service) preserved?
- **Q3** Did the required preconditions arise operationally (not pre-staged)?
- **Q4** Does the observed effect follow from the mechanism, not a semantic shortcut?
- **Q5** Can the evidence be independently audited and verified?

Decision logic
--------------

- All five yes -> ``faithful``
- Q1 + Q2 + Q4 yes (lab usually has Q3 = no) -> ``adapted``
- Q1 yes + Q2 partial + Q4 partial -> ``adapted`` (borderline)
- Otherwise -> ``inspired``

Lab note
--------

The rubric forces Q3 to ``False`` for lab executions whose preconditions
(credentials, vulnerable services, staged files) are configured
by the SUT profile rather than discovered operationally. AutoSUT preserves
this honesty principle: a campaign that drives a *real CVE chain* with no
pre-staging (a rare and explicitly-tagged class) is the only path to
``faithful``.

Independent audit (Q5) is uniformly ``True`` for AutoSUT executions because
every outcome has a per-technique log path, and Caldera-driven outcomes have
``operation_id`` / ``link_id`` / ``ability_id`` cross-referenceable against
the live Caldera DB.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .models import ExecutionMode, FidelityLevel, Realization, TechniqueOutcome


@dataclass
class RubricAnswer:
    """One yes/no answer with structured justification."""

    question_id: str
    question: str
    answer: bool
    justification: str


@dataclass
class TechniqueRubric:
    """Full rubric scoring for one :class:`TechniqueOutcome`."""

    technique_id: str
    answers: list[RubricAnswer]
    computed_fidelity: FidelityLevel
    declared_fidelity: FidelityLevel
    consistent: bool

    @property
    def yes_count(self) -> int:
        return sum(1 for a in self.answers if a.answer)


RUBRIC_QUESTIONS: tuple[tuple[str, str], ...] = (
    ("Q1", "Was the central mechanism of the technique preserved?"),
    ("Q2", "Was the relevant substrate (OS / runtime / service) preserved?"),
    ("Q3", "Did the required preconditions arise operationally (not pre-staged)?"),
    ("Q4",
     "Does the observed effect follow from the mechanism, not a semantic shortcut?"),
    ("Q5", "Can the evidence be independently audited and verified?"),
)


def _compute(answers: list[RubricAnswer]) -> FidelityLevel:
    """Apply the frozen STICKS decision logic over the 5 answers."""
    by_id = {a.question_id: a.answer for a in answers}
    q1, q2, q3, q4, q5 = (by_id.get(q, False) for q in ("Q1", "Q2", "Q3", "Q4", "Q5"))
    if all((q1, q2, q3, q4, q5)):
        return FidelityLevel.faithful
    if q1 and q2 and q4:
        return FidelityLevel.adapted
    if q1 and (q2 or q4):
        return FidelityLevel.adapted
    return FidelityLevel.inspired


def score(outcome: TechniqueOutcome,
          realization_was_pre_staged: bool = True) -> TechniqueRubric:
    """Score one technique outcome against the rubric.

    The function reads the outcome's recorded execution mode, realization,
    and status to derive each Q1..Q5 answer. ``realization_was_pre_staged``
    lets a caller assert (for a rare campaign) that the precondition was
    *not* pre-staged — that lets Q3 become True and a faithful tier become
    reachable.
    """
    real_modes = {ExecutionMode.real_controlled,
                  ExecutionMode.caldera_driven,
                  ExecutionMode.atomic_red_team}
    is_real = outcome.executed_mode in real_modes
    is_caldera = outcome.executed_mode in {ExecutionMode.caldera_driven,
                                            ExecutionMode.atomic_red_team}
    is_success = outcome.status == "success"

    # Q1: Central mechanism preserved?
    q1_yes = is_real and is_success
    q1_just = (
        "Real execution mode produced the documented effect"
        if q1_yes else
        f"executed_mode={outcome.executed_mode.value}, status={outcome.status}: "
        f"mechanism not executed mechanistically")

    # Q2: Relevant substrate preserved? (We target Linux; if the canonical
    # technique is Linux-native the substrate matches. For Windows-native
    # techniques our Linux SUT is a substrate mismatch.)
    q2_yes = is_real and outcome.realization != Realization.generic_primitive
    if outcome.realization == Realization.real_cve:
        q2_just = "Real vulnerable product version exposed the exact protocol surface"
    elif outcome.realization == Realization.surrogate:
        q2_just = "Surrogate service preserves the wire-level protocol semantics"
    else:
        q2_just = ("Generic primitive substrate — not the specific product the "
                   "technique originally targets")

    # Q3: Preconditions operational? In lab context, almost always False.
    q3_yes = (not realization_was_pre_staged) and is_real
    q3_just = (
        "Precondition arose operationally during the run (no SUT pre-staging)"
        if q3_yes else
        "Lab pre-staging: SUT profile + injector configure preconditions, "
        "not the adversary's actions")

    # Q4: Effect from mechanism, not shortcut?
    q4_yes = is_real and is_success
    q4_just = (
        "Effect observable on target (file written, link executed, exit_code=0)"
        if q4_yes else
        "Marker-only or failure — no operational effect observed")

    # Q5: Evidence auditable?
    has_logs = bool(outcome.evidence_files)
    q5_yes = has_logs
    q5_just = (
        f"{len(outcome.evidence_files)} evidence file(s); "
        f"caldera_ability_id={outcome.caldera_ability_id or 'none'}"
        if q5_yes else
        "No evidence files attached to outcome")

    answers = [
        RubricAnswer("Q1", RUBRIC_QUESTIONS[0][1], q1_yes, q1_just),
        RubricAnswer("Q2", RUBRIC_QUESTIONS[1][1], q2_yes, q2_just),
        RubricAnswer("Q3", RUBRIC_QUESTIONS[2][1], q3_yes, q3_just),
        RubricAnswer("Q4", RUBRIC_QUESTIONS[3][1], q4_yes, q4_just),
        RubricAnswer("Q5", RUBRIC_QUESTIONS[4][1], q5_yes, q5_just),
    ]

    computed = _compute(answers)
    return TechniqueRubric(
        technique_id=outcome.technique_id,
        answers=answers,
        computed_fidelity=computed,
        declared_fidelity=outcome.declared_fidelity,
        consistent=(computed == outcome.executed_fidelity),
    )


def score_manifest(outcomes: list[TechniqueOutcome]) -> list[TechniqueRubric]:
    """Score every outcome in a manifest. Returns rubric records in order."""
    return [score(o) for o in outcomes]


def summarize(rubrics: list[TechniqueRubric]) -> dict:
    """Aggregate rubric results into a manifest-level summary."""
    distribution: dict[str, int] = {}
    for rubric in rubrics:
        distribution[rubric.computed_fidelity.value] = (
            distribution.get(rubric.computed_fidelity.value, 0) + 1)
    return {
        "total": len(rubrics),
        "consistent": sum(1 for rubric in rubrics if rubric.consistent),
        "mismatches": sum(1 for rubric in rubrics if not rubric.consistent),
        "fidelity_distribution": distribution,
        "questions": [{"id": question_id, "text": question_text}
                      for question_id, question_text in RUBRIC_QUESTIONS],
    }
