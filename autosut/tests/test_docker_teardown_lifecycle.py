from types import SimpleNamespace

from scripts.orchestrator.docker_lifecycle import (
    DockerTeardownReceipt,
    remove_network,
    stop_container,
)
from scripts.orchestrator.environment import DockerEnvironment
from scripts.orchestrator.host_fleet import HostFleet
from scripts.orchestrator.models import SUTProfile


def _process(return_code: int, *, stdout: str = "", stderr: str = ""):
    return SimpleNamespace(
        returncode=return_code,
        stdout=stdout,
        stderr=stderr,
    )


def _receipt(*, clean: bool) -> DockerTeardownReceipt:
    return DockerTeardownReceipt(
        command=("docker", "network", "rm", "autosut-net-test"),
        return_code=0,
        stdout="",
        stderr="",
        absent=clean,
        verification_error="" if clean else "still present",
    )


def test_stop_container_requires_confirmed_absence(monkeypatch) -> None:
    observations = iter([
        _process(0, stdout="autosut-test\n"),
        _process(0, stdout="[]"),
        _process(1, stderr="Error: No such container: autosut-test"),
    ])
    monkeypatch.setattr(
        "scripts.orchestrator.docker_lifecycle.subprocess.run",
        lambda *args, **kwargs: next(observations),
    )
    monkeypatch.setattr(
        "scripts.orchestrator.docker_lifecycle.time.sleep",
        lambda _seconds: None,
    )

    receipt = stop_container("autosut-test", grace_seconds=1.0)

    assert receipt.clean is True
    assert receipt.absent is True


def test_stop_container_fails_closed_when_inspection_is_unavailable(
    monkeypatch,
) -> None:
    observations = iter([
        _process(0, stdout="autosut-test\n"),
        _process(1, stderr="Cannot connect to the Docker daemon"),
    ])
    monkeypatch.setattr(
        "scripts.orchestrator.docker_lifecycle.subprocess.run",
        lambda *args, **kwargs: next(observations),
    )

    receipt = stop_container("autosut-test", grace_seconds=0.0)

    assert receipt.clean is False
    assert receipt.absent is False
    assert "Docker inspection failed" in receipt.verification_error


def test_docker_context_records_verified_teardown(monkeypatch, tmp_path) -> None:
    environment = DockerEnvironment(
        "autosut-test",
        SUTProfile(sut_id="test", base_image="alpine:3.19"),
        tmp_path,
    )
    monkeypatch.setattr(
        "scripts.orchestrator.environment.stop_container",
        lambda _name: _receipt(clean=True),
    )

    with environment:
        pass

    assert environment.last_teardown_clean is True


def test_unrelated_not_found_error_does_not_certify_network_absence(monkeypatch) -> None:
    observations = iter([
        _process(0),
        _process(1, stderr="Error: authorization plugin not found"),
    ])
    monkeypatch.setattr(
        "scripts.orchestrator.docker_lifecycle.subprocess.run",
        lambda *args, **kwargs: next(observations),
    )

    assert remove_network("autosut-test", grace_seconds=0).clean is False


def test_fleet_context_combines_host_and_network_teardown(monkeypatch, tmp_path) -> None:
    host = SimpleNamespace(teardown=lambda: True)
    fleet = HostFleet(
        hosts={"target": host},
        network_names={"zone": "autosut-net-test"},
        run_dir=tmp_path,
        sut=SUTProfile(sut_id="test", base_image="alpine:3.19"),
    )
    monkeypatch.setattr(
        "scripts.orchestrator.host_fleet.remove_network",
        lambda _name: _receipt(clean=False),
    )

    with fleet:
        pass

    assert fleet.last_teardown_clean is False
