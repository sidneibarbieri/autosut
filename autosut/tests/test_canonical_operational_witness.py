"""Regression tests for the public bounded Caldera dispatch witness."""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from evaluation.canonical_operational_witness import (  # noqa: E402
    CANONICAL_COLLECTION_RELATIVE,
    assess_caldera_dispatch_witness,
)


def _copy_collection(tmp_path: Path) -> Path:
    artifact_root = tmp_path / "artifact"
    source = PROJECT_ROOT / CANONICAL_COLLECTION_RELATIVE
    destination = artifact_root / CANONICAL_COLLECTION_RELATIVE
    shutil.copytree(source, destination)
    return artifact_root


def test_released_canonical_witness_is_supported_and_bounded() -> None:
    assessment = assess_caldera_dispatch_witness(PROJECT_ROOT)

    assert assessment.status == "supported_bounded"
    assert assessment.failure_reason is None
    assert assessment.witness is not None
    assert assessment.witness.campaign_id == "0.shadowray"
    assert assessment.witness.source_campaign_id == "C0045"
    assert assessment.witness.realization == "surrogate"
    assert assessment.witness.operation_link_count == 1
    assert all(path.startswith("release/experiments/") for path in assessment.evidence_artifacts)
    assert any(path.endswith("scenario/contract.json") for path in assessment.evidence_artifacts)
    assert "release/evidence/shadowray_caldera/milestone.json" not in assessment.evidence_artifacts


def test_missing_canonical_ledger_blocks_the_witness(tmp_path: Path) -> None:
    artifact_root = _copy_collection(tmp_path)
    (artifact_root / CANONICAL_COLLECTION_RELATIVE / "ledger.json").unlink()

    assessment = assess_caldera_dispatch_witness(artifact_root)

    assert assessment.status == "blocked_missing_evidence"
    assert assessment.witness is None
    assert assessment.failure_reason is not None


def test_tampered_effect_probe_blocks_the_witness(tmp_path: Path) -> None:
    artifact_root = _copy_collection(tmp_path)
    effect_probe = next(
        (artifact_root / CANONICAL_COLLECTION_RELATIVE / "bundles").glob(
            "shadowray*/scenario/effect-probe.json"
        )
    )
    effect_probe.write_text('{"returncode": 0, "stdout": "tampered"}\n', encoding="utf-8")

    assessment = assess_caldera_dispatch_witness(artifact_root)

    assert assessment.status == "blocked_execution_gate"
    assert assessment.witness is None
    assert assessment.failure_reason is not None
