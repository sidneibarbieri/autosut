from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from evaluation.stage2_campaign import (
    CellRecord,
    ExecutionStatus,
    GeneratorId,
    ProposalStatus,
    rollup_by_generator,
)


def _cell(provider: str, model: str, proposal: ProposalStatus,
          execution: ExecutionStatus = ExecutionStatus.not_run) -> CellRecord:
    return CellRecord(
        campaign_id="stage2-frozen-v1",
        case_id="C0045",
        generator=GeneratorId(provider=provider, model_requested=model),
        prompt_hash="p", schema_hash="s",
        proposal_status=proposal, execution_status=execution,
        pipeline_commit="deadbeef", started_at="t0", finished_at="t1",
    )


def test_schema_rejection_is_abstention_not_incorrect_commit():
    cells = [_cell("ollama", "gpt-oss:20b", ProposalStatus.schema_rejected)]
    rollup = rollup_by_generator(cells)[0]
    assert rollup.incorrect_commit == 0
    assert rollup.abstained == 1
    assert rollup.incorrect_commit_rate == 0.0


def test_rates_capture_the_safety_utility_tradeoff():
    cells = [
        _cell("openai", "gpt-4o-mini", ProposalStatus.committed, ExecutionStatus.succeeded),
        _cell("openai", "gpt-4o-mini", ProposalStatus.committed, ExecutionStatus.evidence_failed),
        _cell("openai", "gpt-4o-mini", ProposalStatus.verifier_rejected),
        _cell("openai", "gpt-4o-mini", ProposalStatus.committed, ExecutionStatus.succeeded),
    ]
    rollup = rollup_by_generator(cells)[0]
    assert rollup.total_cells == 4
    assert rollup.correct == 2
    assert rollup.incorrect_commit == 1
    assert rollup.abstained == 1
    assert rollup.incorrect_commit_rate == 0.25
    assert rollup.useful_automation_rate == 0.5


def test_provider_error_splits_conditional_from_end_to_end():
    cells = [
        _cell("openrouter", "x:free", ProposalStatus.provider_error),
        _cell("openrouter", "x:free", ProposalStatus.committed, ExecutionStatus.succeeded),
    ]
    rollup = rollup_by_generator(cells)[0]
    assert rollup.scheduled_cells == 2
    assert rollup.total_cells == 1              # infra failure excluded from the model verdict
    assert rollup.provider_errors == 1
    assert rollup.useful_automation_rate == 1.0  # conditional: 1 correct of 1 scored
    assert rollup.end_to_end_yield == 0.5        # but instability is visible: 1 of 2 scheduled


def test_abstaining_on_everything_scores_zero_on_both_rates():
    cells = [_cell("ollama", "m", ProposalStatus.verifier_rejected) for _ in range(5)]
    rollup = rollup_by_generator(cells)[0]
    assert rollup.incorrect_commit_rate == 0.0
    assert rollup.useful_automation_rate == 0.0
