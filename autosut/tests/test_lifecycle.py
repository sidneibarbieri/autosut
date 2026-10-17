"""The lifecycle controller always tears down, records failures, and gates on readiness.

A clean forward path ends CLEAN. A forward failure runs teardown and preserves
its error. Residual resources or unfinished workers make the state DIRTY.
A not-ready backend refuses to materialize.
"""

from __future__ import annotations

import sys
import signal
import os
import threading
import time
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from infrastructure.lifecycle import (  # noqa: E402
    FinalState,
    LifecycleController,
    ResidualReport,
    Stage,
)
from infrastructure.run_context import RunContext  # noqa: E402
from infrastructure import lifecycle  # noqa: E402


def _controller(tmp_path, ready=True):
    return LifecycleController(RunContext.create(tmp_path), backend_readiness=lambda: ready)


def _clean_residual():
    return ResidualReport(scope="docker", residual_resources=[])


def test_a_clean_forward_path_ends_clean(tmp_path):
    ran = []
    result = _controller(tmp_path).run(
        label="run1",
        forward_stages=[Stage("materialize", lambda: ran.append("materialize"))],
        teardown_stages=[Stage("destroy", lambda: ran.append("destroy"), is_teardown=True)],
        inspect_residual=_clean_residual,
    )
    assert result.final_state is FinalState.CLEAN
    assert ran == ["materialize", "destroy"]
    assert result.forward_completed


def test_stage_start_callback_records_the_stage_before_its_action(tmp_path):
    observed = []

    result = _controller(tmp_path).run(
        label="callback",
        forward_stages=[
            Stage(
                "materialize",
                lambda: observed.append("action"),
                on_started=lambda name: observed.append(name),
            )
        ],
        teardown_stages=[],
        inspect_residual=_clean_residual,
    )

    assert result.final_state is FinalState.CLEAN
    assert observed == ["materialize", "action"]


def test_a_forward_failure_still_runs_teardown_and_records_the_error(tmp_path):
    torn_down = []

    def failing_materialize():
        raise RuntimeError("container did not start")

    result = _controller(tmp_path).run(
        label="run1",
        forward_stages=[Stage("materialize", failing_materialize)],
        teardown_stages=[Stage("destroy", lambda: torn_down.append(True), is_teardown=True)],
        inspect_residual=_clean_residual,
    )
    assert result.final_state is FinalState.FAILED_CLEAN
    assert torn_down == [True]
    failed = next(stage for stage in result.stages if stage.name == "materialize")
    assert failed.succeeded is False
    assert "container did not start" in failed.error


def test_residual_resources_make_the_state_dirty(tmp_path):
    result = _controller(tmp_path).run(
        label="run1",
        forward_stages=[Stage("materialize", lambda: None)],
        teardown_stages=[Stage("destroy", lambda: None, is_teardown=True)],
        inspect_residual=lambda: ResidualReport(
            scope="docker", residual_resources=["autosut-abc-target"]
        ),
    )
    assert result.final_state is FinalState.DIRTY
    assert result.residual.clean is False


def test_failed_teardown_cannot_be_reported_clean(tmp_path):
    def failing_destroy():
        raise RuntimeError("guest disk acquisition failed")

    result = _controller(tmp_path).run(
        label="failed-teardown",
        forward_stages=[Stage("dispatch", lambda: None)],
        teardown_stages=[Stage("destroy", failing_destroy, is_teardown=True)],
        inspect_residual=_clean_residual,
    )

    assert result.final_state is FinalState.DIRTY
    assert "unverified-teardown-stage:destroy" in result.residual.residual_resources
    assert result.stages[-1].error == "RuntimeError: guest disk acquisition failed"


def test_forward_failure_does_not_masquerade_as_same_named_teardown_failure(tmp_path):
    def failing_forward():
        raise RuntimeError("forward stage failed")

    result = _controller(tmp_path).run(
        label="shared-stage-name",
        forward_stages=[Stage("stop", failing_forward)],
        teardown_stages=[Stage("stop", lambda: None, is_teardown=True)],
        inspect_residual=_clean_residual,
    )

    assert result.final_state is FinalState.FAILED_CLEAN
    assert result.residual.residual_resources == []


def test_a_stage_that_exceeds_its_timeout_is_recorded_and_teardown_still_runs(tmp_path):
    import time as _time

    torn_down = []
    result = _controller(tmp_path).run(
        label="run1",
        forward_stages=[Stage("hang", lambda: _time.sleep(30), timeout_seconds=0.2)],
        teardown_stages=[Stage("destroy", lambda: torn_down.append(True), is_teardown=True)],
        inspect_residual=_clean_residual,
    )
    assert torn_down == [True]
    hung = next(stage for stage in result.stages if stage.name == "hang")
    assert hung.succeeded is False
    assert "timeout" in hung.error
    assert result.final_state is FinalState.FAILED_DIRTY
    assert "unverified-stage-worker:hang" in result.residual.residual_resources


def test_a_not_ready_backend_refuses_to_materialize(tmp_path):
    with pytest.raises(RuntimeError):
        _controller(tmp_path, ready=False).run(
            label="run1",
            forward_stages=[Stage("materialize", lambda: None)],
            teardown_stages=[],
            inspect_residual=_clean_residual,
        )


def test_signal_between_forward_stages_runs_teardown(monkeypatch, tmp_path):
    observed = []
    run_stage = lifecycle._run_stage

    def signal_after_first_stage(stage, *args, **kwargs):
        timing = run_stage(stage, *args, **kwargs)
        if stage.name == "materialize":
            signal.raise_signal(signal.SIGINT)
        return timing

    monkeypatch.setattr(lifecycle, "_run_stage", signal_after_first_stage)
    result = _controller(tmp_path).run(
        label="interrupted-between-stages",
        forward_stages=[
            Stage("materialize", lambda: observed.append("materialize")),
            Stage("dispatch", lambda: observed.append("dispatch")),
        ],
        teardown_stages=[Stage("destroy", lambda: observed.append("destroy"), is_teardown=True)],
        inspect_residual=_clean_residual,
    )

    assert observed == ["materialize", "destroy"]
    assert result.final_state is FinalState.INTERRUPTED_CLEAN
    assert not result.forward_completed


def test_signal_between_teardown_stages_does_not_skip_cleanup(monkeypatch, tmp_path):
    observed = []
    run_stage = lifecycle._run_stage

    def signal_after_first_teardown(stage, *args, **kwargs):
        timing = run_stage(stage, *args, **kwargs)
        if stage.name == "stop":
            signal.raise_signal(signal.SIGTERM)
        return timing

    monkeypatch.setattr(lifecycle, "_run_stage", signal_after_first_teardown)
    result = _controller(tmp_path).run(
        label="interrupted-during-teardown",
        forward_stages=[Stage("dispatch", lambda: observed.append("dispatch"))],
        teardown_stages=[
            Stage("stop", lambda: observed.append("stop"), is_teardown=True),
            Stage("destroy", lambda: observed.append("destroy"), is_teardown=True),
        ],
        inspect_residual=_clean_residual,
    )

    assert observed == ["dispatch", "stop", "destroy"]
    assert result.final_state is FinalState.INTERRUPTED_CLEAN


def test_signal_during_forward_worker_still_runs_teardown(tmp_path):
    started = threading.Event()
    observed = []

    def running_stage():
        started.set()
        time.sleep(0.2)

    def send_signal():
        assert started.wait(timeout=1)
        os.kill(os.getpid(), signal.SIGINT)

    sender = threading.Thread(target=send_signal)
    sender.start()
    try:
        result = _controller(tmp_path).run(
            label="interrupted-worker",
            forward_stages=[Stage("dispatch", running_stage)],
            teardown_stages=[Stage("destroy", lambda: observed.append("destroy"), is_teardown=True)],
            inspect_residual=_clean_residual,
        )
    finally:
        sender.join(timeout=1)

    assert observed == ["destroy"]
    assert result.final_state is FinalState.INTERRUPTED_CLEAN
    assert not result.forward_completed
    assert any(timing.error and "received signal" in timing.error for timing in result.stages)
