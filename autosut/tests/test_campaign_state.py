from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = PROJECT_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from orchestrator.campaign_state import build_ledger, validate_ledger
from orchestrator.models import (
    AttackerProfile,
    ExecutionMode,
    FidelityLevel,
    Realization,
    RunResult,
    SUTProfile,
    TechniqueOutcome,
)


def _result(
    techniques: list[TechniqueOutcome],
    campaign_id: str = "0.shadowray",
) -> RunResult:
    return RunResult(
        campaign_id=campaign_id,
        run_id="test-run",
        attacker=AttackerProfile(profile_id="test"),
        sut=SUTProfile(sut_id="test-sut", base_image="python:3.11-slim"),
        techniques=techniques,
    )


def _outcome(
    technique_id: str,
    status: str = "success",
    mode: ExecutionMode = ExecutionMode.real_controlled,
) -> TechniqueOutcome:
    return TechniqueOutcome(
        technique_id=technique_id,
        declared_fidelity=FidelityLevel.adapted,
        executed_fidelity=FidelityLevel.adapted,
        declared_mode=mode,
        executed_mode=mode,
        realization=Realization.surrogate,
        status=status,
        evidence_files=[f"techniques/{technique_id}.log"],
    )


def test_shadowray_contract_records_ordered_state() -> None:
    ledger = build_ledger(
        _result([
            _outcome("T1588.002"),
            _outcome("T1190"),
            _outcome("T1059.006"),
            _outcome("T1546.004"),
            _outcome("T1068"),
            _outcome("T1027.013"),
            _outcome("T1003.008"),
            _outcome("T1016"),
            _outcome("T1105"),
            _outcome("T1496.001"),
        ])
    )

    assert ledger.contract_coverage == "declared"
    assert [transition.missing_requirements for transition in ledger.transitions] == [[]] * 10
    assert [fact.fact_id for fact in ledger.facts] == [
        "sut.ready",
        "actor.ready",
        "sut.ray_dashboard.reachable",
        "actor.toolkit.ready",
        "access.target.shell",
        "execution.target.python",
        "persistence.target.shell_config",
        "assessment.target.privilege_boundary",
        "artifact.target.encoded",
        "collection.target.credential_files",
        "discovery.target.network",
        "transfer.target.payload",
        "impact.target.compute",
    ]
    assert len(ledger.content_sha256) == 64


def test_shadowray_contract_rejects_unproduced_requirement() -> None:
    ledger = build_ledger(_result([_outcome("T1059.006")]))

    assert ledger.transitions[0].missing_requirements == ["access.target.shell"]
    assert ledger.transitions[0].produced_fact_ids == []


def test_contract_rejects_partial_execution() -> None:
    ledger = build_ledger(_result([_outcome("T1190"), _outcome("T1082")]))

    assert validate_ledger(ledger) == [
        "executed technique sequence does not match the declared contract"
    ]


def test_pivot_contract_preserves_cross_host_dependencies() -> None:
    sequence = [
        "T1046",
        "T1110.001",
        "T1021.004",
        "T1083",
        "T1570",
        "T1059.004",
    ]
    ledger = build_ledger(
        _result([_outcome(technique_id) for technique_id in sequence], "0.pivot_demo")
    )

    assert validate_ledger(ledger) == []
    assert ledger.executed_technique_ids == sequence
    assert ledger.facts[-1].fact_id == "execution.target2.shell"


def test_dmz_contract_requires_segmentation_before_pivot() -> None:
    sequence = ["T1018", "T1135", "T1021.004", "T1210"]
    ledger = build_ledger(
        _result(
            [_outcome(technique_id) for technique_id in sequence],
            "0.dmz_segmentation_demo",
        )
    )

    assert validate_ledger(ledger) == []
    assert ledger.facts[-1].fact_id == "access.db.shell"


def test_context_observation_is_hashed_and_validated(tmp_path: Path) -> None:
    context_dir = tmp_path / "context"
    context_dir.mkdir()
    (context_dir / "context_observations.json").write_text(
        json.dumps(
            [
                {
                    "activity_id": "wazuh_agent_heartbeat",
                    "source_host": "target1",
                    "destination_host": "target2",
                    "protocol": "tcp",
                    "port": 1514,
                    "purpose": "Declared telemetry.",
                    "status": "failure",
                    "evidence_files": ["context/wazuh_verify.log"],
                }
            ]
        ),
        encoding="utf-8",
    )
    result = _result(
        [_outcome(technique_id) for technique_id in [
            "T1046",
            "T1110.001",
            "T1021.004",
            "T1083",
            "T1570",
            "T1059.004",
        ]],
        "0.pivot_demo",
    )
    result.manifest_path = str(tmp_path / "manifest.json")
    ledger = build_ledger(result)

    assert ledger.context_observations[0].activity_id == "wazuh_agent_heartbeat"
    assert validate_ledger(ledger) == [
        "context activity wazuh_agent_heartbeat did not complete"
    ]


def test_marker_only_outcome_does_not_produce_state() -> None:
    ledger = build_ledger(
        _result(
            [
                _outcome(
                    "T1588.002",
                    mode=ExecutionMode.naive_simulated,
                )
            ]
        )
    )

    assert ledger.transitions[0].produced_fact_ids == []
    assert ledger.transitions[0].status == "marker_only"
    assert "actor.toolkit.ready" not in {
        fact.fact_id for fact in ledger.facts
    }
