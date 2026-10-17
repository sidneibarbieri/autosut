from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.planning.executable_contract import compile_executable_contract
from src.planning.procedural_plan import (
    ProceduralPlanInput,
    ProceduralPlanSourceInput,
    ProcedureStepInput,
)


def _plan() -> ProceduralPlanInput:
    return ProceduralPlanInput(
        schema_version="1",
        compiler_version="1",
        campaign_id="CTEST",
        campaign_name="test",
        source=ProceduralPlanSourceInput(
            bundle_sha256="source-bundle",
            object_count=1,
            campaign_stix_id="campaign--source",
            campaign_external_id="CTEST",
        ),
        ordering_policy="test",
        steps=[
            ProcedureStepInput(
                technique_id="T1",
                technique_stix_id="attack-pattern--T1",
                name="one",
                relationship_ids=["relationship--T1"],
            ),
            ProcedureStepInput(
                technique_id="T2",
                technique_stix_id="attack-pattern--T2",
                name="two",
                relationship_ids=["relationship--T2"],
            ),
        ],
        content_sha256="a" * 64,
    )


def _write_spec(path: Path, transitions: list[dict]) -> None:
    path.write_text(
        json.dumps(
            {
                "campaign_id": "0.test",
                "source_campaign_id": "CTEST",
                "execution_contract": {
                    "scope": "test",
                    "initial_facts": ["sut.ready"],
                    "techniques": transitions,
                },
            }
        ),
        encoding="utf-8",
    )


def test_contract_requires_exact_plan_order(tmp_path: Path) -> None:
    spec = tmp_path / "campaign.json"
    _write_spec(
        spec,
        [
            {"technique_id": "T2", "produces": ["two.ready"]},
            {"technique_id": "T1", "produces": ["one.ready"]},
        ],
    )
    with pytest.raises(ValueError, match="does not exactly match"):
        compile_executable_contract(_plan(), spec)


def test_contract_rejects_unbound_precondition(tmp_path: Path) -> None:
    spec = tmp_path / "campaign.json"
    _write_spec(
        spec,
        [
            {
                "technique_id": "T1",
                "requires": ["missing.fact"],
                "produces": ["one.ready"],
            },
            {"technique_id": "T2", "produces": ["two.ready"]},
        ],
    )
    with pytest.raises(ValueError, match="not previously"):
        compile_executable_contract(_plan(), spec)
