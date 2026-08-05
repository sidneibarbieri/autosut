"""Frozen Stage-2 campaign: one auditable record per (case, generator, run) cell.

The proposer (any LLM, local or hosted) is a swappable component; correctness comes
from the typed verifier and execution evidence. Each cell records its outcome through
an explicit taxonomy so infrastructure failure, malformed output, safety rejection, and
SUT failure are never conflated. The path is fail-closed: a malformed or non-conforming
proposal is recorded as rejected, never silently repaired.

Two rates carry the finding, and both are reported so neither can hide behind the other:
  - incorrect-commit rate: committed bindings that fail execution / all cells (safety);
  - useful-automation rate: correct executions with evidence / all cells (utility).
A system that abstains on everything scores zero on both.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ProposalStatus(str, Enum):
    provider_error = "provider_error"        # transient infra failure, not a model verdict
    empty_output = "empty_output"
    malformed_json = "malformed_json"
    schema_rejected = "schema_rejected"      # typed proposal shape rejected
    constraint_rejected = "constraint_rejected"  # declared-constraint check failed
    verifier_rejected = "verifier_rejected"
    committed = "committed"


class ExecutionStatus(str, Enum):
    not_run = "not_run"                      # proposal never reached execution
    abstained = "abstained"                  # verifier admitted nothing to run
    execution_failed = "execution_failed"
    evidence_failed = "evidence_failed"      # ran, but the evidence predicate was not met
    succeeded = "succeeded"                  # execution-valid AND evidence satisfied


class GeneratorId(StrictModel):
    """Frozen identity of a proposal generator. The digest, not the friendly tag,
    is what makes a run reproducible; tags may later point to different weights."""

    provider: str
    model_requested: str
    model_returned: str | None = None
    model_digest: str | None = None
    runtime_version: str | None = None


class CellRecord(StrictModel):
    campaign_id: str
    case_id: str
    generator: GeneratorId
    prompt_hash: str
    schema_hash: str
    raw_output_hash: str | None = None
    raw_response_path: str | None = None
    proposal_status: ProposalStatus
    execution_status: ExecutionStatus = ExecutionStatus.not_run
    pipeline_commit: str
    started_at: str
    finished_at: str


class GeneratorRollup(StrictModel):
    generator: str
    scheduled_cells: int          # every planned cell, including infra failures
    total_cells: int              # cells with a real generator verdict (excludes provider_error)
    committed: int
    correct: int
    incorrect_commit: int
    abstained: int
    provider_errors: int
    incorrect_commit_rate: float  # conditional: over total_cells
    useful_automation_rate: float # conditional: over total_cells
    end_to_end_yield: float       # over scheduled_cells, so instability cannot hide


def _is_correct(cell: CellRecord) -> bool:
    return (
        cell.proposal_status is ProposalStatus.committed
        and cell.execution_status is ExecutionStatus.succeeded
    )


def _is_incorrect_commit(cell: CellRecord) -> bool:
    return cell.proposal_status is ProposalStatus.committed and cell.execution_status in (
        ExecutionStatus.execution_failed,
        ExecutionStatus.evidence_failed,
    )


def _is_abstention(cell: CellRecord) -> bool:
    rejected = cell.proposal_status in (
        ProposalStatus.schema_rejected,
        ProposalStatus.constraint_rejected,
        ProposalStatus.verifier_rejected,
    )
    return rejected or cell.execution_status is ExecutionStatus.abstained


def _generator_key(cell: CellRecord) -> str:
    return cell.generator.provider + "/" + cell.generator.model_requested


def rollup_by_generator(cells: list[CellRecord]) -> list[GeneratorRollup]:
    """Aggregate cells per generator, reporting both a conditional and an end-to-end view.

    Conditional rates exclude provider errors (a transient infra failure is not a model
    verdict). End-to-end yield keeps them in the denominator, so an unstable service is not
    mistaken for a stable one. Both are reported; neither replaces the other.
    """

    scheduled: dict[str, list[CellRecord]] = {}
    for cell in cells:
        scheduled.setdefault(_generator_key(cell), []).append(cell)

    rollups: list[GeneratorRollup] = []
    for generator, all_cells in sorted(scheduled.items()):
        scored = [cell for cell in all_cells if cell.proposal_status is not ProposalStatus.provider_error]
        total = len(scored)
        correct = sum(1 for cell in scored if _is_correct(cell))
        incorrect = sum(1 for cell in scored if _is_incorrect_commit(cell))
        rollups.append(
            GeneratorRollup(
                generator=generator,
                scheduled_cells=len(all_cells),
                total_cells=total,
                committed=sum(1 for cell in scored if cell.proposal_status is ProposalStatus.committed),
                correct=correct,
                incorrect_commit=incorrect,
                abstained=sum(1 for cell in scored if _is_abstention(cell)),
                provider_errors=len(all_cells) - total,
                incorrect_commit_rate=(incorrect / total) if total else 0.0,
                useful_automation_rate=(correct / total) if total else 0.0,
                end_to_end_yield=(correct / len(all_cells)) if all_cells else 0.0,
            )
        )
    return rollups
