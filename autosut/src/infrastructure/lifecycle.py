"""The one canonical lifecycle every experiment runs through, timed and sealed.

The controller owns sequencing, per-stage timing, the fail-closed preflight gate, and the run
bundle. It does not know how any stage materializes resources: each stage is an injected callable,
so the same controller drives a real backend in production and a fake one in tests. Teardown stages
always run after a forward failure. An unfinished worker prevents a clean verdict.
"""

from __future__ import annotations

import signal
import threading
import time
import traceback as traceback_module
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum

from pydantic import BaseModel, ConfigDict

from .run_context import RunContext


# A signalled main thread cannot kill an active stage worker. Wait for it before teardown.
_INTERRUPT_GRACE_SECONDS = 180
_INTERRUPT_POLL_SECONDS = 0.1


class FinalState(str, Enum):
    """Where a run ended, from the two axes that matter: did it work, is it clean."""

    CLEAN = "clean"                # forward path completed, environment verified clean
    FAILED_CLEAN = "failed_clean"  # a forward stage failed, but teardown still reached clean
    DIRTY = "dirty"                # forward path completed, but residual resources remain
    FAILED_DIRTY = "failed_dirty"  # a forward stage failed and residual resources remain
    INTERRUPTED_CLEAN = "interrupted_clean"  # a signal arrived, teardown still reached clean
    INTERRUPTED_DIRTY = "interrupted_dirty"  # a signal arrived and residual resources remain


class StageTiming(BaseModel):
    """How long one lifecycle stage took, whether it succeeded, and its failure trace if not."""

    model_config = ConfigDict(extra="forbid")

    name: str
    seconds: float
    succeeded: bool
    worker_finished: bool = True
    error: str | None = None
    traceback: str | None = None


class ResidualReport(BaseModel):
    """What, if anything, the run left behind after teardown."""

    model_config = ConfigDict(extra="forbid")

    scope: str
    residual_resources: list[str]

    @property
    def clean(self) -> bool:
        return not self.residual_resources


class LifecycleResult(BaseModel):
    """The timed, sealed outcome of one run through the canonical lifecycle."""

    model_config = ConfigDict(extra="forbid")

    run_id: str
    label: str
    stages: list[StageTiming]
    total_seconds: float
    forward_completed: bool
    residual: ResidualReport
    final_state: FinalState
    evidence_dir: str
    implementation_revision: str | None = None


@dataclass
class Stage:
    """One named step in the lifecycle.

    ``timeout_seconds`` bounds how long the step may run before it is treated as stalled; None
    leaves it unbounded. Teardown steps run even after a forward step fails or times out.
    """

    name: str
    action: Callable[[], None]
    is_teardown: bool = False
    timeout_seconds: float | None = None
    on_started: Callable[[str], None] | None = None


def _run_stage(
    stage: Stage, interrupt_reason: Callable[[], str | None] | None = None,
) -> StageTiming:
    """Run one stage in a worker thread, bounding it by its timeout and recording any failure.

    Running the action off the main thread lets the controller detect a stalled stage: if the
    thread does not finish within the timeout, the stage is recorded as timed out and the run
    proceeds to teardown instead of hanging. A raised exception is preserved with its traceback; a
    SIGINT/SIGTERM is polled during forward stages so teardown cannot be skipped
    by a signal delivered between stages. No failure is swallowed into success.
    """
    started = time.monotonic()
    outcome: dict = {}

    def target() -> None:
        try:
            if stage.on_started is not None:
                stage.on_started(stage.name)
            stage.action()
            outcome["succeeded"] = True
        except Exception as failure:  # noqa: BLE001 - preserved as evidence, surfaced in state
            outcome["error"] = f"{type(failure).__name__}: {failure}"
            outcome["traceback"] = traceback_module.format_exc()

    worker = threading.Thread(target=target, daemon=True)
    worker.start()
    deadline = started + stage.timeout_seconds if stage.timeout_seconds is not None else None
    while worker.is_alive():
        reason = interrupt_reason() if interrupt_reason is not None else None
        if reason is not None:
            worker.join(timeout=_INTERRUPT_GRACE_SECONDS)
            return StageTiming(
                name=stage.name, seconds=round(time.monotonic() - started, 3),
                succeeded=False, worker_finished=not worker.is_alive(),
                error=f"{reason}; worker_finished_within_grace={not worker.is_alive()}",
            )
        remaining = deadline - time.monotonic() if deadline is not None else None
        if remaining is not None and remaining <= 0:
            break
        wait_seconds = (
            min(_INTERRUPT_POLL_SECONDS, remaining)
            if remaining is not None else _INTERRUPT_POLL_SECONDS
        )
        worker.join(timeout=wait_seconds)
    elapsed = round(time.monotonic() - started, 3)
    if worker.is_alive():
        return StageTiming(
            name=stage.name, seconds=elapsed, succeeded=False, worker_finished=False,
            error=f"stage exceeded its {stage.timeout_seconds}s timeout without completing",
        )
    if "error" in outcome:
        return StageTiming(
            name=stage.name, seconds=elapsed, succeeded=False,
            error=outcome["error"], traceback=outcome.get("traceback"),
        )
    return StageTiming(name=stage.name, seconds=elapsed, succeeded=True)


class LifecycleController:
    """Drives one experiment through its stages, always tearing down, always sealing."""

    def __init__(self, run_context: RunContext, backend_readiness: Callable[[], bool]):
        self.run_context = run_context
        self.backend_readiness = backend_readiness
        self._interrupted = False
        self._interrupt_signal: int | None = None

    def run(
        self,
        label: str,
        forward_stages: list[Stage],
        teardown_stages: list[Stage],
        inspect_residual: Callable[[], ResidualReport],
    ) -> LifecycleResult:
        """Gate on readiness, run forward stages until one fails, then always tear down.

        A SIGINT or SIGTERM during a forward stage is converted into an interruption that still
        runs teardown. The interrupted result remains dirty when a stage worker
        cannot be confirmed stopped.
        """
        if not self.backend_readiness():
            raise RuntimeError(
                "preflight gate: the selected backend is not ready on this host; "
                "materialization refused"
            )

        self._interrupted = False
        self._interrupt_signal = None
        restore = self._install_signal_handlers()
        timings: list[StageTiming] = []
        teardown_timings: list[StageTiming] = []
        started = time.monotonic()
        forward_completed = True
        try:
            for stage in forward_stages:
                if self._interrupted:
                    forward_completed = False
                    break
                timing = _run_stage(stage, self._interruption_reason)
                timings.append(timing)
                if not timing.succeeded or self._interrupted:
                    forward_completed = False
                    break
            for stage in teardown_stages:
                timing = _run_stage(stage)
                timings.append(timing)
                teardown_timings.append(timing)
            residual = inspect_residual()
        finally:
            restore()

        unresolved_workers = [
            f"unverified-stage-worker:{timing.name}"
            for timing in timings if not timing.worker_finished
        ]
        failed_teardowns = [
            f"unverified-teardown-stage:{timing.name}"
            for timing in teardown_timings if not timing.succeeded
        ]
        if unresolved_workers or failed_teardowns:
            residual = residual.model_copy(update={
                "residual_resources": [
                    *residual.residual_resources, *unresolved_workers, *failed_teardowns,
                ],
            })
        if self._interrupted:
            forward_completed = False
            if not any(timing.error and "received signal" in timing.error for timing in timings):
                timings.append(StageTiming(
                    name="interruption", seconds=0, succeeded=False,
                    error=self._interruption_reason(),
                ))
        total_seconds = round(time.monotonic() - started, 3)
        final_state = self._final_state(forward_completed, residual.clean, self._interrupted)
        return LifecycleResult(
            run_id=self.run_context.run_id,
            label=label,
            stages=timings,
            total_seconds=total_seconds,
            forward_completed=forward_completed,
            residual=residual,
            final_state=final_state,
            evidence_dir=str(self.run_context.run_dir),
        )

    def _install_signal_handlers(self) -> Callable[[], None]:
        """Record SIGINT/SIGTERM without raising across teardown boundaries.

        Handlers can only be set on the main thread; off the main thread (some test runners) this
        is a no-op, which is safe because those contexts do not deliver these signals to the run.
        """
        if threading.current_thread() is not threading.main_thread():
            return lambda: None

        def handle(signum, _frame):
            self._interrupted = True
            self._interrupt_signal = signum

        previous = {sig: signal.signal(sig, handle) for sig in (signal.SIGINT, signal.SIGTERM)}

        def restore() -> None:
            for sig, original in previous.items():
                signal.signal(sig, original)

        return restore

    def _interruption_reason(self) -> str | None:
        if self._interrupt_signal is None:
            return None
        return f"received signal {self._interrupt_signal}"

    def _final_state(
        self, forward_completed: bool, clean: bool, interrupted: bool
    ) -> FinalState:
        if interrupted:
            return FinalState.INTERRUPTED_CLEAN if clean else FinalState.INTERRUPTED_DIRTY
        if forward_completed and clean:
            return FinalState.CLEAN
        if forward_completed and not clean:
            return FinalState.DIRTY
        if clean:
            return FinalState.FAILED_CLEAN
        return FinalState.FAILED_DIRTY
