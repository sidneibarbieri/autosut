#!/usr/bin/env python3
"""Freeze the current supervised single-host and multi-host collection protocol."""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

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
    canonical_sha256,
)
from infrastructure.revision import current_revision  # noqa: E402


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    parser.add_argument("--seeds", type=int, default=5)
    args = parser.parse_args()
    if args.seeds < 1:
        parser.error("--seeds must be positive")
    if args.output.exists():
        raise FileExistsError(f"refusing to replace frozen protocol: {args.output}")

    caldera_driver = PROJECT_ROOT / "scripts" / "run_caldera_experiment.py"
    multihost_driver = PROJECT_ROOT / "scripts" / "run_caldera_experiment_multihost.py"
    caldera_hash = sha256_file(caldera_driver)
    multihost_hash = sha256_file(multihost_driver)
    revision = current_revision(PROJECT_ROOT)
    environments = (
        EnvironmentDefinition(
            environment_id="shadowray-single-host-surrogate",
            critical_assets=(
                CriticalAsset(
                    asset_id="ray-command-effect",
                    description="independently observed command effect in the isolated SUT",
                ),
            ),
            topology_sha256=canonical_sha256(
                {"scenario": "shadowray-single-host-surrogate", "driver": caldera_hash}
            ),
        ),
        EnvironmentDefinition(
            environment_id="multihost-caldera-fact-chain",
            critical_assets=(
                CriticalAsset(
                    asset_id="host-b-propagated-fact",
                    description="independently observed fact propagation from host A to host B",
                ),
            ),
            topology_sha256=canonical_sha256(
                {"scenario": "multihost-caldera-fact-chain", "driver": multihost_hash}
            ),
        ),
    )
    plan = ExperimentPlan.freeze(
        experiment_id="autosut-current-operational-v1",
        arms=("autosut-supervised",),
        environments=environments,
        seeds=tuple(range(1, args.seeds + 1)),
        implementation_revision=revision,
        protocol_sha256=canonical_sha256(
            {
                "serial_execution": True,
                "fresh_control_plane_per_cell": True,
                "caldera_driver": caldera_hash,
                "multihost_driver": multihost_hash,
            }
        ),
    )
    bindings = (
        CollectionBinding(
            arm="autosut-supervised",
            environment_id="shadowray-single-host-surrogate",
            experiment="caldera",
            critical_asset_id="ray-command-effect",
            effect_field="independent_effect_confirmed",
            driver_sha256=caldera_hash,
            deadline_seconds=1800,
        ),
        CollectionBinding(
            arm="autosut-supervised",
            environment_id="multihost-caldera-fact-chain",
            experiment="multihost",
            critical_asset_id="host-b-propagated-fact",
            effect_field="fact_propagated",
            driver_sha256=multihost_hash,
            deadline_seconds=1800,
        ),
    )
    protocol = OperationalCollectionProtocol.freeze(plan=plan, bindings=bindings)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(protocol.model_dump_json(indent=2) + "\n", encoding="utf-8")
    print(args.output)


if __name__ == "__main__":
    main()
