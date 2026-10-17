from __future__ import annotations

import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from evaluation.operational_collection import (  # noqa: E402
    CollectionBinding,
    OperationalCollectionProtocol,
)
from evaluation.operational_metrics import (  # noqa: E402
    CriticalAsset,
    EnvironmentDefinition,
    ExperimentPlan,
)

DIGEST = "a" * 64


def _plan() -> ExperimentPlan:
    return ExperimentPlan.freeze(
        experiment_id="operational-test",
        arms=("current",),
        environments=(
            EnvironmentDefinition(
                environment_id="single-host",
                critical_assets=(CriticalAsset(asset_id="effect", description="observed effect"),),
                topology_sha256=DIGEST,
            ),
        ),
        seeds=(1, 2),
        implementation_revision="b" * 40 + "+tree-" + "c" * 16,
        protocol_sha256=DIGEST,
    )


def _binding() -> CollectionBinding:
    return CollectionBinding(
        arm="current",
        environment_id="single-host",
        experiment="caldera",
        critical_asset_id="effect",
        effect_field="independent_effect_confirmed",
        driver_sha256=DIGEST,
        deadline_seconds=900,
    )


def test_collection_protocol_accepts_exact_serial_matrix() -> None:
    protocol = OperationalCollectionProtocol.freeze(plan=_plan(), bindings=(_binding(),))

    assert protocol.serial_execution is True
    assert protocol.fresh_control_plane_per_cell is True
    assert len(protocol.content_sha256) == 64


def test_collection_protocol_rejects_missing_binding() -> None:
    plan = _plan()
    payload = {
        "plan": plan.model_dump(mode="json"),
        "bindings": [],
        "serial_execution": True,
        "fresh_control_plane_per_cell": True,
        "content_sha256": DIGEST,
    }
    with pytest.raises(ValidationError):
        OperationalCollectionProtocol.model_validate(payload)


def test_collection_binding_must_name_declared_asset() -> None:
    invalid = _binding().model_copy(update={"critical_asset_id": "unknown"})

    with pytest.raises(ValidationError, match="undeclared critical asset"):
        OperationalCollectionProtocol.freeze(plan=_plan(), bindings=(invalid,))
