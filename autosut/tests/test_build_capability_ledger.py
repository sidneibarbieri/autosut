"""Regression tests for generated capability-ledger policy wording."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = PROJECT_ROOT / "scripts" / "build_capability_ledger.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("build_capability_ledger", SCRIPT_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load capability ledger generator")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_windows_backend_is_development_in_progress_not_unsupported() -> None:
    module = _load_module()
    ledger = module._current_ledger()
    record = next(item for item in ledger.records if item.capability == "backend.windows_x86_64")

    assert record.level.value == "development_in_progress"
    assert record.evidence_paths == []
    assert "not qualified" in record.note
    assert "windows_backend_qualification" not in record.note
    assert not record.may_support_a_claim


def test_historical_experiment_does_not_apply_to_current_revision() -> None:
    module = _load_module()
    ledger = module._current_ledger()
    record = next(
        item
        for item in ledger.records
        if item.capability == "experiment.docker_isolated_caldera_integration"
    )

    assert record.implementation_revision is not None
    assert record.evidence_paths == ["release/experiments/caldera_experiment/qualification.json"]
    assert not record.applies_to_current_revision
    assert not record.may_support_a_claim


def test_unrevisioned_execution_cannot_apply_to_current_revision() -> None:
    module = _load_module()
    ledger = module._current_ledger()
    record = next(
        item
        for item in ledger.records
        if item.capability == "lifecycle.docker_sut_materialize_execute_teardown"
    )

    assert record.implementation_revision is None
    assert not record.applies_to_current_revision
    assert record.evidence_paths[0].endswith("docker_qualification/qualification.json")


def test_caldera_dispatch_uses_the_canonical_bounded_witness() -> None:
    module = _load_module()
    ledger = module._current_ledger()
    record = next(
        item for item in ledger.records if item.capability == "caldera.operation_dispatch"
    )

    assert record.level.value == "end_to_end_validated"
    assert record.clean_runs_observed == 1
    assert all(path.startswith("release/experiments/") for path in record.evidence_paths)
    assert not record.may_support_a_claim
