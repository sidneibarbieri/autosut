"""The one supervised entrypoint for a qualifying run: no experiment starts infrastructure unsupervised.

This wraps a canonical experiment entrypoint in the out-of-process supervisor. The experiment runs as a
child in its own process group under a wall-clock deadline; if it overruns, the group is terminated
(SIGTERM -> bounded grace -> SIGKILL) and a Docker namespace sweep force-removes every resource the run
created, then confirms none remain. The supervision record (pid, pgid, escalation, exit code, swept
residuals, timings) is persisted, so an interrupted run leaves proof of clean termination, not orphans.

A qualifying batch must launch runs through this entrypoint. Calling the experiment script directly
bypasses the termination guarantee and the sweep, and is not a qualifying path.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from infrastructure.docker_namespace import NamespaceSweep  # noqa: E402
from infrastructure.process_supervisor import supervise  # noqa: E402
from infrastructure.run_context import ExecutionLock  # noqa: E402
from infrastructure.supervision_evidence import (  # noqa: E402
    build_receipt,
    utc_now,
    write_json_atomic,
)

_EXPERIMENTS = {
    "caldera": PROJECT_ROOT / "scripts" / "run_caldera_experiment.py",
    "lifecycle": PROJECT_ROOT / "scripts" / "run_lifecycle.py",
    "multihost": PROJECT_ROOT / "scripts" / "run_caldera_experiment_multihost.py",
}
_SUPERVISION_DIR = PROJECT_ROOT / "release" / "evidence" / "raw" / "supervision"
_LOCK_PATH = PROJECT_ROOT / "release" / "experiments" / "lifecycle" / "experiment.lock"


def _write_json_atomic(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    temporary.replace(path)


def _within_project_root(path: Path) -> Path:
    """Resolve a receipt/handoff path without allowing an external evidence location."""
    resolved = (path if path.is_absolute() else PROJECT_ROOT / path).resolve()
    try:
        resolved.relative_to(PROJECT_ROOT.resolve())
    except ValueError as failure:
        raise ValueError("supervision evidence path must stay under the artifact root") from failure
    return resolved


def _stage_has_started(path: Path, expected_stage: str) -> bool:
    if not path.is_file():
        return False
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return False
    return record.get("stage") == expected_stage


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--experiment", choices=sorted(_EXPERIMENTS), default="caldera")
    parser.add_argument("--label", default="run")
    parser.add_argument("--deadline-seconds", type=float, default=1200.0)
    parser.add_argument("--grace-seconds", type=float, default=30.0)
    parser.add_argument("--setup-deadline-seconds", type=float, default=600.0)
    parser.add_argument(
        "--arm-deadline-after-stage",
        help="start the external deadline only after this canonical lifecycle stage begins",
    )
    parser.add_argument(
        "--arm-deadline-after-boundary-file",
        type=Path,
        help="start the external deadline only after this semantic-boundary record exists",
    )
    parser.add_argument(
        "--stage-status-file",
        type=Path,
        help="status file written by the canonical Caldera lifecycle",
    )
    parser.add_argument(
        "--semantic-boundary-dir",
        type=Path,
        help="directory passed to the Caldera lifecycle for semantic-boundary records",
    )
    parser.add_argument(
        "--supervisor-status-file",
        type=Path,
        help="write child PID/PGID before the supervisor waits",
    )
    parser.add_argument(
        "--supervision-receipt-file",
        type=Path,
        help="parent-owned receipt written after the child exits; default is raw supervision evidence",
    )
    parser.add_argument(
        "--campaign",
        help="campaign identifier required for the supervised lifecycle entrypoint",
    )
    parser.add_argument(
        "--qualification-protocol-version",
        help="opt in to a final qualification protocol; requires revision and topology",
    )
    parser.add_argument(
        "--qualification-revision",
        help="immutable clean git commit required by the opted-in qualification protocol",
    )
    parser.add_argument(
        "--qualification-topology",
        help="declared topology required by the opted-in qualification protocol",
    )
    parser.add_argument(
        "--experiment-arg", action="append", default=[],
        help="an argument forwarded verbatim to the experiment entrypoint; repeatable",
    )
    args = parser.parse_args()

    if args.arm_deadline_after_stage and args.arm_deadline_after_boundary_file:
        parser.error("choose either a stage-entry or semantic-boundary deadline trigger")
    if (args.arm_deadline_after_stage or args.arm_deadline_after_boundary_file) and args.experiment != "caldera":
        parser.error("stage-triggered deadlines are currently defined only for the Caldera lifecycle")
    if args.arm_deadline_after_stage and args.stage_status_file is None:
        parser.error("--arm-deadline-after-stage requires --stage-status-file")
    if args.arm_deadline_after_boundary_file and args.semantic_boundary_dir is None:
        parser.error("--arm-deadline-after-boundary-file requires --semantic-boundary-dir")

    if args.experiment == "lifecycle" and not args.campaign:
        parser.error("--campaign is required when --experiment lifecycle")
    if args.experiment != "lifecycle" and args.campaign:
        parser.error("--campaign is valid only when --experiment lifecycle")
    qualification_values = (
        args.qualification_protocol_version,
        args.qualification_revision,
        args.qualification_topology,
    )
    if any(value is not None for value in qualification_values) and not all(
        isinstance(value, str) and value.strip() for value in qualification_values
    ):
        parser.error(
            "--qualification-protocol-version, --qualification-revision, and "
            "--qualification-topology must be supplied together"
        )

    command = [sys.executable, str(_EXPERIMENTS[args.experiment])]
    if args.experiment == "lifecycle":
        command.append(args.campaign)
    command.extend(["--label", args.label, *args.experiment_arg])
    if args.stage_status_file is not None and args.experiment == "caldera":
        command.extend(["--stage-status-file", str(args.stage_status_file)])
    if args.semantic_boundary_dir is not None and args.experiment == "caldera":
        command.extend(["--semantic-boundary-dir", str(args.semantic_boundary_dir)])
    supervision_id = uuid.uuid4().hex
    receipt_path = _within_project_root(
        args.supervision_receipt_file
        if args.supervision_receipt_file is not None
        else _SUPERVISION_DIR / f"{supervision_id}.json"
    )
    handoff_path = receipt_path.with_name(f"{receipt_path.stem}.handoff.json")
    command.extend([
        "--supervision-id", supervision_id,
        "--supervision-receipt-file", str(receipt_path),
        "--supervision-handoff-file", str(handoff_path),
        "--supervision-lock-held",
    ])
    if args.qualification_protocol_version is not None:
        command.extend([
            "--qualification-protocol-version", args.qualification_protocol_version,
            "--qualification-revision", args.qualification_revision,
            "--qualification-topology", args.qualification_topology,
        ])
    started_at = utc_now()
    outcome = None
    supervisor_error: str | None = None

    def on_started(pid: int, pgid: int) -> None:
        if args.supervisor_status_file is not None:
            _write_json_atomic(args.supervisor_status_file, {
                "supervision_id": supervision_id,
                "pid": pid,
                "pgid": pgid,
                "receipt_relative_path": receipt_path.relative_to(PROJECT_ROOT).as_posix(),
            })

    arm_deadline = None
    if args.arm_deadline_after_stage:
        arm_deadline = lambda: _stage_has_started(
            args.stage_status_file, args.arm_deadline_after_stage
        )
    elif args.arm_deadline_after_boundary_file:
        boundary_path = _within_project_root(args.arm_deadline_after_boundary_file)
        arm_deadline = boundary_path.is_file

    sweep: NamespaceSweep | None = None
    try:
        # The lock starts before the resource baseline is captured and remains held through the
        # supervisor sweep. The child receives --supervision-lock-held, so it cannot deadlock by
        # acquiring the same lock a second time. Direct execution still acquires this lock itself.
        with ExecutionLock(_LOCK_PATH):
            sweep = NamespaceSweep.capture()
            outcome = supervise(
                command,
                deadline_seconds=args.deadline_seconds,
                grace_seconds=args.grace_seconds,
                sweep=sweep.sweep,
                arm_deadline=arm_deadline,
                setup_deadline_seconds=args.setup_deadline_seconds,
                on_started=on_started,
            )
    except BaseException as failure:  # preserved in the independent parent receipt
        supervisor_error = f"{type(failure).__name__}: {failure}"
    finally:
        receipt = build_receipt(
            project_root=PROJECT_ROOT,
            supervision_id=supervision_id,
            experiment=args.experiment,
            entrypoint=_EXPERIMENTS[args.experiment].name,
            label=args.label,
            command=command,
            supervisor_pid=os.getpid(),
            started_at=started_at,
            outcome=outcome.model_dump() if outcome is not None else None,
            handoff_path=handoff_path,
            supervisor_error=supervisor_error,
        )
        write_json_atomic(receipt_path, receipt)

    if supervisor_error is not None or outcome is None:
        print(f"[supervised] failed before a complete outcome: {supervisor_error}", file=sys.stderr)
        print(f"[supervised] supervision receipt: {receipt_path.relative_to(PROJECT_ROOT)}")
        return 1

    print(f"[supervised] completed_naturally={outcome.completed_naturally} "
          f"exit_code={outcome.exit_code} escalation={outcome.escalation}")
    print(f"[supervised] terminated_clean={outcome.terminated_clean} "
          f"residual={outcome.residual_after_termination or 'none'}")
    print(f"[supervised] supervision receipt: {receipt_path.relative_to(PROJECT_ROOT)}")

    # A natural run passes through its own exit code only after cleanup was authoritatively checked.
    # An interrupted child is still a failed experiment even when the supervisor cleaned it up;
    # returning success there would let an orchestration layer mistake recovery evidence for a
    # successful campaign execution.
    if outcome.completed_naturally:
        return (outcome.exit_code or 0) if outcome.terminated_clean else 1
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
