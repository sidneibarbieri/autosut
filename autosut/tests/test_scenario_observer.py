from __future__ import annotations

from pathlib import Path

import pytest

from infrastructure.scenario_observer import ProbeResult, ProbeSpec, collect_scenario_observation
from planning.binding_catalog import BindingCatalog
from planning.executable_contract import ExecutableCampaignContract
from planning.scenario_admission import admit_scenario
from planning.scenario_slice import derive_scenario_slice

PROJECT_ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    "returncode,stdout,expected", [(0, "false\n", False), (0, "true\n", True), (1, "true\n", False)]
)
def test_running_state_requires_success_and_true_output(returncode, stdout, expected):
    result = ProbeResult(
        subject_id="sut.ready",
        argv=("docker", "inspect"),
        returncode=returncode,
        stdout=stdout,
        stderr="",
        expected_stdout="true",
    )
    assert result.observed is expected


def _slice() -> tuple[ExecutableCampaignContract, BindingCatalog]:
    contract = ExecutableCampaignContract.model_validate_json(
        (PROJECT_ROOT / "release/plans/C0045.verified-executable-contract.json").read_text()
    )
    catalog = BindingCatalog.model_validate_json(
        (PROJECT_ROOT / "release/plans/C0045.binding-catalog.json").read_text()
    )
    return derive_scenario_slice(contract, catalog, ("T1190",))


def _success(subject_id: str) -> ProbeSpec:
    return ProbeSpec(subject_id=subject_id, argv=("true",))


def test_probe_backed_observation_is_admitted(tmp_path: Path) -> None:
    contract, catalog = _slice()
    observation = collect_scenario_observation(
        contract=contract,
        catalog=catalog,
        run_id="run-1",
        binding_probes=tuple(
            _success(binding_id)
            for binding_id in ("actor.primary", "endpoint.public_service", "target.primary")
        ),
        fact_probes=tuple(_success(fact_id) for fact_id in contract.initial_facts),
        goal_absence_probes=tuple(_success(fact_id) for fact_id in catalog.goal_facts),
        evidence_root=tmp_path,
    )

    admit_scenario(
        contract,
        catalog,
        observation,
        run_id="run-1",
        goal_facts=tuple(catalog.goal_facts),
        evidence_root=tmp_path,
    )
    assert (tmp_path / "scenario/probes.json").is_file()


def test_failed_probe_blocks_admission(tmp_path: Path) -> None:
    contract, catalog = _slice()
    observation = collect_scenario_observation(
        contract=contract,
        catalog=catalog,
        run_id="run-1",
        binding_probes=(
            _success("actor.primary"),
            ProbeSpec(subject_id="endpoint.public_service", argv=("false",)),
            _success("target.primary"),
        ),
        fact_probes=tuple(_success(fact_id) for fact_id in contract.initial_facts),
        goal_absence_probes=tuple(_success(fact_id) for fact_id in catalog.goal_facts),
        evidence_root=tmp_path,
    )

    with pytest.raises(ValueError, match="required binding is absent"):
        admit_scenario(
            contract,
            catalog,
            observation,
            run_id="run-1",
            goal_facts=tuple(catalog.goal_facts),
            evidence_root=tmp_path,
        )


def test_probe_set_must_exactly_match_slice(tmp_path: Path) -> None:
    contract, catalog = _slice()

    with pytest.raises(ValueError, match="exactly cover"):
        collect_scenario_observation(
            contract=contract,
            catalog=catalog,
            run_id="run-1",
            binding_probes=(_success("actor.primary"),),
            fact_probes=tuple(_success(fact_id) for fact_id in contract.initial_facts),
            goal_absence_probes=tuple(_success(fact_id) for fact_id in catalog.goal_facts),
            evidence_root=tmp_path,
        )


def test_report_cannot_escape_through_symlink(tmp_path: Path) -> None:
    contract, catalog = _slice()
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    (evidence_root / "scenario").symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(ValueError, match="within its evidence root"):
        collect_scenario_observation(
            contract=contract,
            catalog=catalog,
            run_id="run-1",
            binding_probes=(),
            fact_probes=(),
            goal_absence_probes=(),
            evidence_root=evidence_root,
        )
    assert not (tmp_path / "probes.json").exists()


def test_existing_report_is_preserved(tmp_path: Path) -> None:
    contract, catalog = _slice()
    report = tmp_path / "scenario" / "probes.json"
    report.parent.mkdir()
    report.write_text("original evidence", encoding="utf-8")
    with pytest.raises(FileExistsError, match="overwrite"):
        collect_scenario_observation(
            contract=contract,
            catalog=catalog,
            run_id="run-1",
            binding_probes=(),
            fact_probes=(),
            goal_absence_probes=(),
            evidence_root=tmp_path,
        )
    assert report.read_text(encoding="utf-8") == "original evidence"


def test_unconfirmed_goal_absence_blocks_admission(tmp_path: Path) -> None:
    contract, catalog = _slice()
    observation = collect_scenario_observation(
        contract=contract,
        catalog=catalog,
        run_id="run-1",
        binding_probes=tuple(
            _success(binding_id)
            for binding_id in ("actor.primary", "endpoint.public_service", "target.primary")
        ),
        fact_probes=tuple(_success(fact_id) for fact_id in contract.initial_facts),
        goal_absence_probes=tuple(
            ProbeSpec(subject_id=fact_id, argv=("false",)) for fact_id in catalog.goal_facts
        ),
        evidence_root=tmp_path,
    )

    with pytest.raises(ValueError, match="absence was not established"):
        admit_scenario(
            contract,
            catalog,
            observation,
            run_id="run-1",
            goal_facts=tuple(catalog.goal_facts),
            evidence_root=tmp_path,
        )
