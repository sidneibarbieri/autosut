"""Contracts for the canonical public claim-surface validator."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODULE_PATH = PROJECT_ROOT / "scripts" / "validate_claim_surface.py"


def _load_module():
    specification = importlib.util.spec_from_file_location(
        "validate_claim_surface", MODULE_PATH
    )
    module = importlib.util.module_from_spec(specification)
    assert specification.loader is not None
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


def test_released_claim_surface_is_valid() -> None:
    module = _load_module()

    ledger = module.validate(PROJECT_ROOT)

    assert {claim.claim_id for claim in ledger.claims} >= module.REQUIRED_CLAIMS


def test_legacy_grouping_is_readable_but_not_exported_as_a_question() -> None:
    module = _load_module()
    payload = json.loads(
        (PROJECT_ROOT / "release" / "claim_evidence_traceability.json").read_text()
    )["claims"][0]
    payload.pop("evidence_dimension", None)
    payload["research_question"] = "RQ1"

    record = module.ClaimRecord.model_validate(payload)

    assert record.evidence_dimension == "RQ1"
    assert "research_question" not in record.model_dump()


def test_claim_requires_an_explicit_evidence_group() -> None:
    module = _load_module()
    payload = json.loads(
        (PROJECT_ROOT / "release" / "claim_evidence_traceability.json").read_text()
    )["claims"][0]
    payload.pop("evidence_dimension", None)
    payload.pop("research_question", None)

    with pytest.raises(ValueError, match="evidence_dimension"):
        module.ClaimRecord.model_validate(payload)


def test_claim_surface_rejects_a_missing_evidence_path(tmp_path: Path) -> None:
    module = _load_module()
    release = tmp_path / "release"
    dashboard = release / "dashboard"
    dashboard.mkdir(parents=True)
    claims = []
    for claim_id in module.REQUIRED_CLAIMS:
        claims.append(
            {
                "claim_id": claim_id,
                "research_question": "RQ",
                "claim": "Bounded claim.",
                "status": "supported_bounded",
                "scope": "One controlled case.",
                "measured_value": {},
                "evidence_artifacts": ["release/missing.json"],
                "reproduction_command": "bash run_review_check.sh",
                "caveat": "Not a population result.",
            }
        )
    ledger = {
        "schema_version": "test/v1",
        "generated_at": "2026-09-08T00:00:00+00:00",
        "measurement_detail": [{"claim_id": "test"}],
        "status_vocabulary": {"supported_bounded": "test"},
        "claims": claims,
        "blocked_interpretations": [{"claim": "universal", "reason": "bounded"}],
    }
    payload = json.dumps(ledger)
    (release / "claim_evidence_traceability.json").write_text(payload, encoding="utf-8")
    (release / "claims_evidence_matrix.json").write_text(payload, encoding="utf-8")
    (release / "CLAIM_EVIDENCE_TRACEABILITY.md").write_text("ledger\n", encoding="utf-8")
    (release / "CLAIMS_EVIDENCE_MATRIX.md").write_text("ledger\n", encoding="utf-8")
    (dashboard / "index.html").write_text("", encoding="utf-8")

    with pytest.raises(FileNotFoundError, match="claim evidence path is missing"):
        module.validate(tmp_path)
