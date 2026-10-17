"""Out-of-process supervision that can actually terminate a wedged run.

The in-process lifecycle watchdog detects a stalled stage and records it, but it cannot kill the
worker thread running that stage: a Python thread has no forced termination. When a run wedges so
badly that its own teardown cannot complete, only the operating system can stop it.

This supervisor runs an experiment as a child in its own process group and enforces a wall-clock
deadline. On breach it escalates SIGTERM -> a bounded grace window -> SIGKILL over the whole group,
then invokes a caller-supplied sweep and records whatever the run's namespace still left behind.
Termination here is real: the OS kills a process group, it is not a thread asked to stop. SIGKILL
cannot be trapped, so a child that ignores SIGTERM is still terminated within the grace window.

The supervisor knows nothing about Docker, QEMU, or Caldera. The sweep -- how to force-remove a
run's resources and report residuals -- is injected, so the supervisor stays decoupled from any
backend and is testable without one.
"""

from __future__ import annotations

import os
import signal
import subprocess
import time
from collections.abc import Callable, Sequence
from typing import Any

from pydantic import BaseModel, ConfigDict


class SupervisionOutcome(BaseModel):
    """What the supervisor observed: how the child ended and what, if anything, it left behind."""

    model_config = ConfigDict(extra="forbid")

    command: list[str]
    pid: int
    pgid: int
    completed_naturally: bool
    exit_code: int | None
    # The signals actually sent to the group, in order: [] when the child exited on its own,
    # ["SIGTERM"] when it stopped within grace, ["SIGTERM", "SIGKILL"] when it had to be forced.
    escalation: list[str]
    grace_deadline_exceeded: bool
    duration_seconds: float
    residual_after_termination: list[str]
    cleanup_completed: bool
    # Structured diagnostic supplied by the sweep when it cannot authoritatively inspect cleanup.
    # It is deliberately generic: the supervisor remains independent of Docker and other backends.
    cleanup_error: dict[str, Any] | None = None
    supervisor_interruption: str | None = None

    @property
    def terminated_clean(self) -> bool:
        return self.cleanup_completed and not self.residual_after_termination


def _signal_group(pgid: int, sig: int) -> bool:
    """Deliver a signal to the whole group; return False if the group is already gone.

    killpg reaches the child and every descendant in the group at once. A dead-but-unreaped group
    leader answers ESRCH on Linux and EPERM on macOS/BSD; both mean there is nothing left to signal.
    """
    try:
        os.killpg(pgid, sig)
        return True
    except (ProcessLookupError, PermissionError):
        return False


def _cleanup_error_payload(error: Exception) -> dict[str, Any]:
    """Serialize a structured sweep diagnostic without coupling the supervisor to a backend."""
    diagnostic = getattr(error, "diagnostic", None)
    if isinstance(diagnostic, BaseModel):
        return diagnostic.model_dump(mode="json")
    if isinstance(diagnostic, dict):
        return diagnostic
    return {"error_type": type(error).__name__}


def _inspect_cleanup(
    sweep: Callable[[], list[str]],
) -> tuple[list[str], bool, dict[str, Any] | None]:
    """Run the post-exit sweep; an uninspectable namespace is incomplete, never clean."""
    try:
        return sweep(), True, None
    except Exception as error:  # noqa: BLE001 - preserved in the returned supervision evidence
        return [], False, _cleanup_error_payload(error)


def _complete_outcome(
    *,
    command: Sequence[str],
    process: subprocess.Popen,
    pgid: int,
    completed_naturally: bool,
    escalation: list[str],
    grace_deadline_exceeded: bool,
    started: float,
    sweep: Callable[[], list[str]],
    supervisor_interruption: str | None = None,
) -> SupervisionOutcome:
    """Build one outcome after attempting the authoritative post-exit cleanup inspection."""
    residual, cleanup_completed, cleanup_error = _inspect_cleanup(sweep)
    return SupervisionOutcome(
        command=list(command),
        pid=process.pid,
        pgid=pgid,
        completed_naturally=completed_naturally,
        exit_code=process.returncode,
        escalation=escalation,
        grace_deadline_exceeded=grace_deadline_exceeded,
        duration_seconds=round(time.monotonic() - started, 3),
        residual_after_termination=residual,
        cleanup_completed=cleanup_completed,
        cleanup_error=cleanup_error,
        supervisor_interruption=supervisor_interruption,
    )


class SupervisorInterrupted(RuntimeError):
    """The supervisor itself received an interrupt and must terminate its child before exiting."""

    def __init__(self, signum: int):
        self.signum = signum
        super().__init__(f"supervisor received signal {signum}")


def _install_interrupt_handlers() -> Callable[[], None]:
    """Turn SIGINT/SIGTERM delivered to the supervisor into child-group cleanup.

    A child is intentionally in a different process session.  Without these handlers a signal sent
    to the wrapper could terminate the wrapper while leaving the child alive.  The handlers run
    only in the main thread; test/background callers retain their normal signal behavior.
    """
    import threading

    if threading.current_thread() is not threading.main_thread():
        return lambda: None

    def handle(signum: int, _frame) -> None:
        raise SupervisorInterrupted(signum)

    previous = {sig: signal.signal(sig, handle) for sig in (signal.SIGINT, signal.SIGTERM)}

    def restore() -> None:
        for sig, original in previous.items():
            signal.signal(sig, original)

    return restore


def supervise(
    command: Sequence[str],
    deadline_seconds: float,
    grace_seconds: float,
    sweep: Callable[[], list[str]],
    poll_seconds: float = 0.1,
    arm_deadline: Callable[[], bool] | None = None,
    setup_deadline_seconds: float = 600.0,
    on_started: Callable[[int, int], None] | None = None,
) -> SupervisionOutcome:
    """Run ``command`` as a supervised child; enforce the deadline; sweep residuals after it ends.

    ``sweep`` is called once the child is gone and returns the resources the run's namespace still
    holds -- empty when the run cleaned up after itself, non-empty when the supervisor had to. A
    sweep error is preserved as ``cleanup_error`` and makes ``terminated_clean`` false.
    """
    started = time.monotonic()
    restore_handlers = _install_interrupt_handlers()
    process: subprocess.Popen | None = None
    pgid: int | None = None
    try:
        # start_new_session makes the child a process-group and session leader, so a later killpg
        # reaches the child and every descendant it spawned (container clients, ssh, qemu), not
        # just the child.
        process = subprocess.Popen(list(command), start_new_session=True)
        pgid = os.getpgid(process.pid)
        if on_started is not None:
            on_started(process.pid, pgid)
        deadline: float | None = started + deadline_seconds if arm_deadline is None else None
        setup_deadline = started + setup_deadline_seconds
        while deadline is None or time.monotonic() < deadline:
            if process.poll() is not None:
                return _complete_outcome(
                    command=command,
                    process=process,
                    pgid=pgid,
                    completed_naturally=True,
                    escalation=[],
                    grace_deadline_exceeded=False,
                    started=started,
                    sweep=sweep,
                )
            if deadline is None and arm_deadline is not None:
                if arm_deadline():
                    deadline = time.monotonic() + deadline_seconds
                elif time.monotonic() >= setup_deadline:
                    escalation = _terminate_group(process, pgid, grace_seconds, poll_seconds)
                    return _complete_outcome(
                        command=command,
                        process=process,
                        pgid=pgid,
                        completed_naturally=False,
                        escalation=escalation,
                        grace_deadline_exceeded="SIGKILL" in escalation,
                        started=started,
                        sweep=sweep,
                    )
            time.sleep(poll_seconds)

        escalation = _terminate_group(process, pgid, grace_seconds, poll_seconds)
        return _complete_outcome(
            command=command,
            process=process,
            pgid=pgid,
            completed_naturally=False,
            escalation=escalation,
            grace_deadline_exceeded="SIGKILL" in escalation,
            started=started,
            sweep=sweep,
        )
    except SupervisorInterrupted as interruption:
        if process is None or pgid is None:
            raise
        escalation = _terminate_group(process, pgid, grace_seconds, poll_seconds)
        return _complete_outcome(
            command=command,
            process=process,
            pgid=pgid,
            completed_naturally=False,
            escalation=escalation,
            grace_deadline_exceeded="SIGKILL" in escalation,
            started=started,
            sweep=sweep,
            supervisor_interruption=signal.Signals(interruption.signum).name,
        )
    finally:
        restore_handlers()


def _terminate_group(
    process: subprocess.Popen, pgid: int, grace_seconds: float, poll_seconds: float
) -> list[str]:
    """Escalate SIGTERM -> grace -> SIGKILL over the group; return the signals actually sent.

    Liveness is judged from the direct child (``process.poll``), which is authoritative because the
    child is ours to reap; the group is only the target of delivery, so a descendant is reached too.
    """
    if not _signal_group(pgid, signal.SIGTERM):
        # The child exited on its own between the deadline check and now; nothing to terminate.
        process.wait()
        return []

    grace_deadline = time.monotonic() + grace_seconds
    while time.monotonic() < grace_deadline:
        if process.poll() is not None:
            return ["SIGTERM"]
        time.sleep(poll_seconds)

    # The child did not exit within the grace window (it trapped or ignored SIGTERM, or could not
    # unwind). SIGKILL cannot be trapped, so this ends it.
    _signal_group(pgid, signal.SIGKILL)
    process.wait()
    return ["SIGTERM", "SIGKILL"]
