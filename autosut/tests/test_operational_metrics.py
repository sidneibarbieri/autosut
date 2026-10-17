from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from evaluation.operational_metrics import (  # noqa: E402
    AssetAcquisition,
    CellStatus,
    CriticalAsset,
    EnvironmentDefinition,
    EvidenceReference,
    ExperimentPlan,
    Intervention,
    InterventionActor,
    OperationalCell,
    OperationalLedger,
    ResourceAccounting,
    calculate_metrics,
)

DIGEST = "a" * 64
REVISION = "b" * 40


def _plan() -> ExperimentPlan:
    return ExperimentPlan.freeze(
        experiment_id="comparison-1",
        arms=("baseline", "admitted"),
        environments=(
            EnvironmentDefinition(
                environment_id="multi-host-1",
                topology_sha256=DIGEST,
                critical_assets=(
                    CriticalAsset(asset_id="db-1", description="first database"),
                    CriticalAsset(asset_id="db-2", description="second database"),
                ),
            ),
        ),
        seeds=(1, 2),
        implementation_revision=REVISION,
        protocol_sha256=DIGEST,
    )


def _accounting() -> ResourceAccounting:
    return ResourceAccounting(
        wall_seconds=10,
        active_compute_seconds=8,
        model_seconds=2,
        input_tokens=100,
        output_tokens=25,
        model_cost_usd=0.5,
    )


def _reference(path: str = "runs/run.json") -> EvidenceReference:
    return EvidenceReference(path=path, sha256=DIGEST)


def _cell(
    plan: ExperimentPlan,
    *,
    arm: str,
    seed: int,
    status: CellStatus = CellStatus.COMPLETED,
    asset_id: str | None = None,
    effect_verified: bool = True,
    lifecycle_qualified: bool = True,
    clean_teardown: bool = True,
) -> OperationalCell:
    acquisitions = ()
    if asset_id is not None:
        acquisitions = (
            AssetAcquisition(
                asset_id=asset_id,
                effect_verified=effect_verified,
                evidence=(_reference(f"runs/{arm}-{seed}-{asset_id}.json"),),
            ),
        )
    if status is CellStatus.PLANNED:
        return OperationalCell(
            experiment_id=plan.experiment_id,
            plan_sha256=plan.content_sha256,
            arm=arm,
            environment_id="multi-host-1",
            seed=seed,
            status=status,
        )
    return OperationalCell(
        experiment_id=plan.experiment_id,
        plan_sha256=plan.content_sha256,
        arm=arm,
        environment_id="multi-host-1",
        seed=seed,
        status=status,
        lifecycle_qualified=lifecycle_qualified,
        clean_teardown=clean_teardown,
        acquisitions=acquisitions,
        accounting=_accounting(),
        terminal_evidence=(_reference(f"runs/{arm}-{seed}.json"),),
        failure_reason="backend unavailable" if status is CellStatus.UNSUPPORTED else None,
    )


def _complete_cells(plan: ExperimentPlan) -> list[OperationalCell]:
    return [_cell(plan, arm=arm, seed=seed) for arm in plan.arms for seed in plan.seeds]


def test_metrics_keep_unobserved_cells_in_reliability_denominator() -> None:
    plan = _plan()
    ledger = OperationalLedger(
        plan=plan,
        cells=(
            _cell(plan, arm="baseline", seed=1, asset_id="db-1"),
            _cell(plan, arm="baseline", seed=2, status=CellStatus.PLANNED),
            _cell(plan, arm="admitted", seed=1, asset_id="db-1"),
            _cell(plan, arm="admitted", seed=2, asset_id="db-2"),
        ),
    )
    metrics = {(item.arm, item.environment_id): item for item in calculate_metrics(ledger)}

    assert metrics[("baseline", "multi-host-1")].success is True
    assert metrics[("baseline", "multi-host-1")].reliability == 0.5
    assert metrics[("baseline", "multi-host-1")].total_acquisition == 0.5
    assert metrics[("admitted", "multi-host-1")].reliability == 1.0
    assert metrics[("admitted", "multi-host-1")].total_acquisition == 1.0


def test_unverified_effect_and_dirty_teardown_cannot_count_as_success() -> None:
    plan = _plan()
    ledger = OperationalLedger(
        plan=plan,
        cells=(
            _cell(
                plan,
                arm="baseline",
                seed=1,
                asset_id="db-1",
                effect_verified=False,
            ),
            _cell(
                plan,
                arm="baseline",
                seed=2,
                asset_id="db-2",
                clean_teardown=False,
            ),
            _cell(plan, arm="admitted", seed=1, status=CellStatus.PLANNED),
            _cell(plan, arm="admitted", seed=2, status=CellStatus.PLANNED),
        ),
    )
    metric = calculate_metrics(ledger)[0]

    assert metric.success is False
    assert metric.reliability == 0
    assert metric.total_acquisition == 0


def test_unsupported_cell_cannot_count_even_with_claimed_acquisition() -> None:
    plan = _plan()
    ledger = OperationalLedger(
        plan=plan,
        cells=(
            _cell(
                plan,
                arm="baseline",
                seed=1,
                status=CellStatus.UNSUPPORTED,
                asset_id="db-1",
            ),
            _cell(plan, arm="baseline", seed=2, status=CellStatus.PLANNED),
            _cell(plan, arm="admitted", seed=1, status=CellStatus.PLANNED),
            _cell(plan, arm="admitted", seed=2, status=CellStatus.PLANNED),
        ),
    )

    assert calculate_metrics(ledger)[0].success is False


def test_ledger_rejects_missing_cells_and_undeclared_assets() -> None:
    plan = _plan()
    with pytest.raises(ValidationError, match="matrix mismatch"):
        OperationalLedger(plan=plan, cells=(_cell(plan, arm="baseline", seed=1),))

    cells = _complete_cells(plan)
    cells[0] = _cell(plan, arm="baseline", seed=1, asset_id="undeclared")
    with pytest.raises(ValidationError, match="undeclared critical assets"):
        OperationalLedger(plan=plan, cells=tuple(cells))


def test_plan_rejects_hash_tampering() -> None:
    plan = _plan()
    payload = plan.model_dump(mode="json")
    payload["arms"] = ["changed"]
    with pytest.raises(ValidationError, match="plan hash mismatch"):
        ExperimentPlan.model_validate(payload)


def test_accounting_and_human_intervention_are_aggregated() -> None:
    plan = _plan()
    human = Intervention(
        actor=InterventionActor.HUMAN,
        category="binding_review",
        active_seconds=7.5,
        reason="approve environment-specific binding",
    )
    first = _cell(plan, arm="baseline", seed=1, asset_id="db-1")
    first = first.model_copy(update={"interventions": (human,)})
    ledger = OperationalLedger(
        plan=plan,
        cells=(
            first,
            _cell(plan, arm="baseline", seed=2),
            _cell(plan, arm="admitted", seed=1, status=CellStatus.PLANNED),
            _cell(plan, arm="admitted", seed=2, status=CellStatus.PLANNED),
        ),
    )
    metric = calculate_metrics(ledger)[0]

    assert metric.human_interventions == 1
    assert metric.human_active_seconds == 7.5
    assert metric.wall_seconds == 20
    assert metric.input_tokens == 200
    assert metric.model_cost_usd == 1.0


def test_evidence_verification_detects_tampering(tmp_path: Path) -> None:
    evidence = tmp_path / "run.json"
    evidence.write_text(json.dumps({"effect": True}), encoding="utf-8")
    reference = EvidenceReference(
        path="run.json",
        sha256=hashlib.sha256(evidence.read_bytes()).hexdigest(),
    )
    reference.verify(tmp_path)
    evidence.write_text(json.dumps({"effect": False}), encoding="utf-8")

    with pytest.raises(ValueError, match="hash mismatch"):
        reference.verify(tmp_path)


def test_planned_cell_rejects_observation_fields() -> None:
    plan = _plan()
    with pytest.raises(ValidationError, match="planned cell cannot contain observations"):
        OperationalCell(
            experiment_id=plan.experiment_id,
            plan_sha256=plan.content_sha256,
            arm="baseline",
            environment_id="multi-host-1",
            seed=1,
            status=CellStatus.PLANNED,
            clean_teardown=True,
        )
