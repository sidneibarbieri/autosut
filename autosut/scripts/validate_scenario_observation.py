#!/usr/bin/env python3
"""Validate a pre-execution observation against the compiled campaign and SUT catalog."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from planning.binding_catalog import BindingCatalog  # noqa: E402
from planning.executable_contract import ExecutableCampaignContract  # noqa: E402
from planning.scenario_admission import ScenarioObservation, admit_scenario  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", required=True, type=Path)
    parser.add_argument("--catalog", required=True, type=Path)
    parser.add_argument("--observation", required=True, type=Path)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--evidence-root", required=True, type=Path)
    args = parser.parse_args()
    contract = ExecutableCampaignContract.model_validate_json(args.contract.read_text())
    catalog = BindingCatalog.model_validate_json(args.catalog.read_text())
    observation = ScenarioObservation.model_validate_json(args.observation.read_text())
    admit_scenario(
        contract,
        catalog,
        observation,
        run_id=args.run_id,
        goal_facts=tuple(catalog.goal_facts),
        evidence_root=args.evidence_root,
    )
    print("Scenario observation admitted; campaign execution has not been established.")


if __name__ == "__main__":
    main()
