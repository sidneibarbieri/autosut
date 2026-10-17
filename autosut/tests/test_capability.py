"""Capability levels are bounded by evidence and cannot be inflated by declaration.

A capability that claims real execution must cite runs; a capability that may back a claim must
cite evidence, run on the current revision, and have clean-room or independent reproduction.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from infrastructure.capability import (  # noqa: E402
    CapabilityLedger,
    CapabilityLevel,
    CapabilityRecord,
    ReproductionContext,
)


def test_component_tested_needs_neither_runs_nor_evidence():
    record = CapabilityRecord(
        capability="infrastructure.preflight", level=CapabilityLevel.COMPONENT_TESTED
    )
    assert not record.may_support_a_claim


def test_reproducible_requires_at_least_two_clean_runs():
    with pytest.raises(ValidationError):
        CapabilityRecord(
            capability="backend.docker",
            level=CapabilityLevel.REPRODUCIBLE,
            clean_runs_observed=1,
            implementation_revision="abc123",
            evidence_paths=["release/evidence/run1"],
        )


def test_a_reproduced_level_requires_evidence_paths():
    with pytest.raises(ValidationError):
        CapabilityRecord(
            capability="backend.docker",
            level=CapabilityLevel.REPRODUCIBLE,
            clean_runs_observed=5,
            implementation_revision="abc123",
            evidence_paths=[],
        )


def test_a_reproduced_level_requires_an_implementation_revision():
    with pytest.raises(ValidationError):
        CapabilityRecord(
            capability="backend.docker",
            level=CapabilityLevel.REPRODUCIBLE,
            clean_runs_observed=5,
            evidence_paths=["release/evidence/run1"],
        )


def test_only_a_reproduced_level_may_support_a_claim():
    supported = CapabilityRecord(
        capability="backend.docker",
        level=CapabilityLevel.REPRODUCIBLE,
        clean_runs_observed=5,
        implementation_revision="abc123",
        evidence_paths=["release/evidence/run1"],
        reproduction_context=ReproductionContext.CLEAN_ROOM,
    )
    end_to_end = CapabilityRecord(
        capability="caldera.operation",
        level=CapabilityLevel.END_TO_END_VALIDATED,
        clean_runs_observed=1,
    )
    assert supported.may_support_a_claim
    assert not end_to_end.may_support_a_claim


def test_a_mock_never_supports_a_claim():
    record = CapabilityRecord(capability="caldera.mock", level=CapabilityLevel.MOCK)
    assert not record.may_support_a_claim


def test_development_in_progress_never_supports_a_claim():
    record = CapabilityRecord(
        capability="backend.windows_x86_64",
        level=CapabilityLevel.DEVELOPMENT_IN_PROGRESS,
    )
    assert not record.may_support_a_claim


def test_the_ledger_rejects_duplicate_capabilities():
    with pytest.raises(ValidationError):
        CapabilityLedger(
            records=[
                CapabilityRecord(capability="backend.docker", level=CapabilityLevel.IMPLEMENTED),
                CapabilityRecord(capability="backend.docker", level=CapabilityLevel.SPECIFIED),
            ]
        )


def test_claim_supporting_filters_to_mature_capabilities():
    ledger = CapabilityLedger(
        records=[
            CapabilityRecord(
                capability="backend.docker",
                level=CapabilityLevel.REPRODUCIBLE,
                clean_runs_observed=5,
                implementation_revision="abc123",
                evidence_paths=["release/evidence/run1"],
                reproduction_context=ReproductionContext.CLEAN_ROOM,
            ),
            CapabilityRecord(
                capability="backend.qemu_linux_arm64", level=CapabilityLevel.IMPLEMENTED
            ),
        ]
    )
    assert [r.capability for r in ledger.claim_supporting()] == ["backend.docker"]


def test_author_environment_reproduction_is_not_claim_ready():
    record = CapabilityRecord(
        capability="backend.docker",
        level=CapabilityLevel.REPRODUCIBLE,
        clean_runs_observed=5,
        implementation_revision="abc123",
        evidence_paths=["release/evidence/run1"],
    )
    assert not record.may_support_a_claim
