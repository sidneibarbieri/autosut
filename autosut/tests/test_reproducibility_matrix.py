from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = PROJECT_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from orchestrator.campaign_state import CampaignStateLedger
from run_reproducibility_matrix import semantic_hash, semantic_projection


def _ledger(run_id: str) -> CampaignStateLedger:
    return CampaignStateLedger(
        campaign_id="example",
        run_id=run_id,
        initial_facts=[],
        transitions=[],
        facts=[],
        contract_coverage="declared",
        declared_technique_ids=["T1"],
        executed_technique_ids=["T1"],
        content_sha256="not-used-by-projection",
    )


def test_semantic_hash_ignores_run_identity() -> None:
    assert semantic_projection(_ledger("run-a")) == semantic_projection(_ledger("run-b"))
    assert semantic_hash(_ledger("run-a")) == semantic_hash(_ledger("run-b"))
