"""A failed Windows lifecycle still produces an explicit negative verdict."""

import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts" / "infra"))
from infrastructure.evidence_bundle import validate_bundle
from windows_cyber_gate import _build_bundle, _failure_verdict


def test_stage_start_events_are_append_only_and_parseable(tmp_path):
    from windows_cyber_gate import _record_stage_start

    _record_stage_start(tmp_path, "materialize")
    _record_stage_start(tmp_path, "teardown_guest")

    events = [json.loads(line) for line in (tmp_path / "stage-starts.jsonl").read_text().splitlines()]
    assert [event["stage"] for event in events] == ["materialize", "teardown_guest"]
    assert all(isinstance(event["started_ns"], int) for event in events)


def test_partial_boot_teardown_skips_agent_commands():
    from windows_cyber_gate import _teardown_windows_guest

    environment = Mock()
    _teardown_windows_guest(environment, guest_ready=False)

    environment.run_shell.assert_not_called()
    environment.teardown.assert_called_once_with()


@pytest.mark.parametrize(
    ("exit_code", "stdout", "accepted"),
    [(0, "panther-answer-absent\r\n", True), (1, "", False), (0, "", False)],
)
def test_panther_answer_cleanup_requires_explicit_guest_confirmation(
    exit_code, stdout, accepted,
):
    from windows_cyber_gate import _teardown_windows_guest

    environment = Mock()
    environment.run_shell.side_effect = [
        SimpleNamespace(exit_code=exit_code, stdout=stdout),
        SimpleNamespace(exit_code=0, stdout=""),
    ]
    if accepted:
        _teardown_windows_guest(environment, guest_ready=True, clear_panther_answer=True)
        assert environment.run_shell.call_count == 2
        command = environment.run_shell.call_args_list[0].args[0]
        assert "Remove-Item" in command
        assert "-ErrorAction Stop" in command
        assert "Panther\\unattend.xml" in command
    else:
        with pytest.raises(RuntimeError, match="cleanup was not confirmed"):
            _teardown_windows_guest(environment, guest_ready=True, clear_panther_answer=True)
        assert environment.run_shell.call_count == 1
    environment.teardown.assert_called_once_with()


def test_caldera_readiness_precedes_api_key_access(monkeypatch):
    import windows_cyber_gate as gate

    class StartingCaldera:
        ready = False
        base_url = "http://127.0.0.1:8888"
        container_name = "synthetic-caldera"

        def wait_until_ready(self, timeout_seconds):
            assert timeout_seconds == 300
            self.ready = True

        def read_red_api_key(self):
            assert self.ready, "configuration is unavailable before readiness"
            return "synthetic-only"

    monkeypatch.setattr(gate, "_load_caldera_client", lambda: lambda url, key, name: (url, key, name))
    client = gate._ready_caldera_client(StartingCaldera())
    assert client == ("http://127.0.0.1:8888", "synthetic-only", "synthetic-caldera")


def test_caldera_readiness_failure_prevents_key_access():
    import windows_cyber_gate as gate

    class UnreadyCaldera:
        def wait_until_ready(self, timeout_seconds):
            raise RuntimeError("synthetic readiness failure")

        def read_red_api_key(self):
            pytest.fail("key access cannot precede successful readiness")

    with pytest.raises(RuntimeError, match="synthetic readiness failure"):
        gate._ready_caldera_client(UnreadyCaldera())


@pytest.mark.parametrize("inspect_exit", [0, 1])
def test_container_diagnostic_retains_only_safe_state(monkeypatch, tmp_path, inspect_exit):
    import windows_cyber_gate as gate

    state = {"Status": "exited", "Running": False, "Restarting": False,
             "OOMKilled": True, "ExitCode": 137, "Error": "synthetic-secret"}
    monkeypatch.setattr(gate.subprocess, "run", lambda command, **options:
                        SimpleNamespace(returncode=inspect_exit, stdout=json.dumps(state), stderr="synthetic-secret"))
    output = tmp_path / "container-state.json"
    if inspect_exit:
        with pytest.raises(RuntimeError, match="Caldera state inspection failed"):
            gate._record_caldera_state("synthetic-container", output)
    else:
        gate._record_caldera_state("synthetic-container", output)
    report = json.loads(output.read_text())
    assert report["inspection_completed"] is (inspect_exit == 0)
    assert report["inspect_exit_code"] == inspect_exit
    assert "synthetic-secret" not in output.read_text()
    if inspect_exit == 0:
        assert report["oom_killed"] is True
        assert report["container_exit_code"] == 137


@pytest.mark.parametrize(
    ("exit_code", "stdout", "completed", "expected"),
    [
        (0, "", True, []),
        (0, "synthetic-container\n", True, ["caldera-container:synthetic-container"]),
        (1, "", False, ["caldera-container-inventory-incomplete:1"]),
    ],
)
def test_caldera_residual_probe_fails_closed(
    monkeypatch, exit_code, stdout, completed, expected,
):
    import windows_cyber_gate as gate

    monkeypatch.setattr(
        gate.subprocess, "run",
        lambda command, **options: SimpleNamespace(returncode=exit_code, stdout=stdout),
    )
    inventory = gate._caldera_container_residual("synthetic-container")
    assert inventory.completed is completed
    assert inventory.residual_resources == expected


def test_agent_cleanup_error_remains_visible_after_guest_teardown():
    from windows_cyber_gate import _teardown_windows_guest

    environment = Mock()
    environment.run_shell.side_effect = RuntimeError("WinRM transport failed")

    with pytest.raises(RuntimeError, match="WinRM transport failed"):
        _teardown_windows_guest(environment, guest_ready=True)

    environment.teardown.assert_called_once_with()


def test_unready_backend_creates_no_execution_resources(monkeypatch, tmp_path):
    import windows_cyber_gate as gate

    monkeypatch.setattr(
        gate.WindowsQemuEnvironment, "check",
        lambda: SimpleNamespace(ready=False, gaps=["missing WinRM dependency"]),
    )

    def forbid_materialization(*args, **kwargs):
        pytest.fail("preflight refusal must precede execution resource creation")

    monkeypatch.setattr(gate.RunContext, "create", forbid_materialization)
    monkeypatch.setattr(gate.CalderaInstance, "materialize", forbid_materialization)
    monkeypatch.setattr(gate, "_serve_directory", forbid_materialization)

    with pytest.raises(RuntimeError, match="missing WinRM dependency"):
        gate.run_cyber_gate(tmp_path / "base", tmp_path / "agent", tmp_path / "evidence", "test")

    assert not (tmp_path / "evidence").exists()


def test_missing_winrm_credential_creates_no_execution_resources(monkeypatch, tmp_path):
    import windows_cyber_gate as gate

    monkeypatch.setattr(
        gate.WindowsQemuEnvironment, "check",
        lambda: SimpleNamespace(ready=True, gaps=[]),
    )
    monkeypatch.delenv("AUTOSUT_WIN_PASSWORD", raising=False)

    def forbid_materialization(*args, **kwargs):
        pytest.fail("missing credential must be detected before resource creation")

    monkeypatch.setattr(gate.RunContext, "create", forbid_materialization)
    monkeypatch.setattr(gate.CalderaInstance, "materialize", forbid_materialization)
    monkeypatch.setattr(gate, "_serve_directory", forbid_materialization)

    with pytest.raises(RuntimeError, match="AUTOSUT_WIN_PASSWORD is required"):
        gate.run_cyber_gate(tmp_path / "base", tmp_path / "agent", tmp_path / "evidence", "test")


def test_failure_verdict_never_promotes_a_missing_oracle():
    verdict = _failure_verdict("a" * 64, "a" * 64, "b" * 64, "AA64")

    assert not verdict.science_passed
    assert not verdict.scientific_claim_eligible
    assert not verdict.negative_control_absent_before
    assert not verdict.independent_effect_observed


def test_failed_materialization_has_a_sealable_negative_bundle():
    verdict = _failure_verdict("a" * 64, "a" * 64, "b" * 64, "AA64")
    context = SimpleNamespace(run_id="test-run", label="test", created_at="2026-10-02T00:00:00Z")
    result = SimpleNamespace(
        run_id="test-run", label="test", total_seconds=1.0, forward_completed=False,
        final_state=SimpleNamespace(value="failed_dirty"), stages=[],
        residual=SimpleNamespace(scope="test", residual_resources=["inventory-incomplete"]),
    )

    bundle = _build_bundle(context, "test-revision", result,
                           {"verdict": verdict, "inventory_completed": False}, "b" * 64, "nonce")

    assert not bundle.procedure.dispatched
    assert not bundle.oracle.matches
    assert not validate_bundle(bundle).admissible


def test_bundle_distinguishes_immutable_base_from_prepared_overlay():
    verdict = _failure_verdict("a" * 64, "a" * 64, "b" * 64, "AA64")
    context = SimpleNamespace(run_id="test-run", label="test", created_at="t")
    result = SimpleNamespace(
        run_id="test-run", label="test", total_seconds=1.0, forward_completed=False,
        final_state=SimpleNamespace(value="failed_dirty"), stages=[],
        residual=SimpleNamespace(scope="test", residual_resources=[]),
    )

    bundle = _build_bundle(
        context, "test-revision", result,
        {"verdict": verdict, "inventory_completed": False}, "b" * 64, "nonce",
        immutable_base_sha256="c" * 64,
    )

    assert bundle.provenance.base_image_sha256 == "a" * 64
    assert bundle.provenance.image_digests["immutable_base_sha256"] == "c" * 64
