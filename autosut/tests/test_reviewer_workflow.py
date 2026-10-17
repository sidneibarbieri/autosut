"""Unit contracts for the evaluator-facing reviewer workflow."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODULE_PATH = PROJECT_ROOT / "scripts" / "run_reviewer_workflow.py"
SPEC = importlib.util.spec_from_file_location("reviewer_workflow", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
reviewer_workflow = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = reviewer_workflow
SPEC.loader.exec_module(reviewer_workflow)


def test_claim_inspection_rejects_missing_required_claim(monkeypatch, tmp_path):
    monkeypatch.setattr(reviewer_workflow, "PROJECT_ROOT", tmp_path)
    release = tmp_path / "release"
    release.mkdir()
    (release / "claim_evidence_traceability.json").write_text(
        json.dumps({"claims": []}), encoding="utf-8"
    )

    step, claims = reviewer_workflow._inspect_claims()

    assert step.status is reviewer_workflow.StepStatus.FAILED
    assert "RQ1-MEASUREMENT" in step.detail
    assert claims == []


def test_claim_inspection_requires_evidence_and_command(monkeypatch, tmp_path):
    monkeypatch.setattr(reviewer_workflow, "PROJECT_ROOT", tmp_path)
    release = tmp_path / "release"
    release.mkdir()
    claims = [
        {
            "claim_id": claim_id,
            "status": "supported_bounded",
            "evidence_artifacts": ["evidence.json"],
            "reproduction_command": "bash run_review_check.sh",
        }
        for claim_id in reviewer_workflow._REQUIRED_CLAIMS
    ]
    (release / "claim_evidence_traceability.json").write_text(
        json.dumps({"claims": claims}), encoding="utf-8"
    )

    step, inspections = reviewer_workflow._inspect_claims()

    assert step.status is reviewer_workflow.StepStatus.PASSED
    assert {inspection.claim_id for inspection in inspections} == reviewer_workflow._REQUIRED_CLAIMS


def test_blocked_optional_backend_is_not_an_artifact_failure():
    steps = [
        reviewer_workflow.ReviewStep(
            name="host-preflight", status=reviewer_workflow.StepStatus.BLOCKED
        ),
        reviewer_workflow.ReviewStep(
            name="claim-evidence-ledger", status=reviewer_workflow.StepStatus.PASSED
        ),
    ]
    assert reviewer_workflow._final_status(steps) is reviewer_workflow.StepStatus.BLOCKED
