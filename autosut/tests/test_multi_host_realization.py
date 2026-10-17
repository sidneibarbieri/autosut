import pytest

from scripts.orchestrator import host_fleet
from scripts.orchestrator.models import SUTHost, SUTProfile
from scripts.orchestrator.models import Realization
from scripts.orchestrator.multi_host_executor import (
    _outcome_failure,
    _outcome_success,
)


def test_multi_host_outcome_defaults_to_generic_primitive():
    outcome = _outcome_success("T0000", ["evidence.log"], "test", 0.1)

    assert outcome.realization == Realization.generic_primitive


def test_multi_host_outcome_records_declared_target_realization():
    success = _outcome_success(
        "T1190",
        ["evidence.log"],
        "test",
        0.1,
        realization=Realization.real_cve,
    )
    failure = _outcome_failure(
        "T1190",
        ["evidence.log"],
        "test",
        0.1,
        realization=Realization.real_cve,
    )

    assert success.realization == Realization.real_cve
    assert failure.realization == Realization.real_cve


@pytest.mark.parametrize("backend", ["qemu", "windows-qemu", "tart"])
def test_non_docker_fleet_fails_before_creating_networks(tmp_path, monkeypatch, backend):
    profile = SUTProfile(
        sut_id="vm-fleet", backend=backend, base_image="guest.qcow2",
        hosts=[SUTHost(name=name, base_image="guest.qcow2") for name in ("first", "second")],
    )
    monkeypatch.setattr(host_fleet, "_create_networks", lambda *args: pytest.fail("no Docker network may be created"))

    with pytest.raises(ValueError, match="multi-host backend"):
        host_fleet.HostFleet.bring_up(profile, tmp_path)
