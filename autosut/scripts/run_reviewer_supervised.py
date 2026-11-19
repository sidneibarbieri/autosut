"""Supervise the public operational commands with the existing lifecycle components."""

from __future__ import annotations

import os
from pathlib import Path
import signal
import sys
import uuid

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from infrastructure.docker_namespace import DockerInventoryError, NamespaceSweep  # noqa: E402
from infrastructure.process_supervisor import SupervisionOutcome, supervise  # noqa: E402
from infrastructure.run_context import ExecutionLock, ExecutionLockHeld  # noqa: E402
from infrastructure.supervision_evidence import write_json_atomic  # noqa: E402

DEADLINES = {"replay": 8 * 3600, "witness": 1200, "all": 1800}
CANONICAL_LOCK = PROJECT_ROOT / "release/experiments/lifecycle/experiment.lock"


def outcome_status(outcome: SupervisionOutcome) -> int:
    if not outcome.terminated_clean:
        print(
            "[supervision] cleanup is incomplete; inspect the saved receipt before retrying",
            file=sys.stderr,
        )
        return 1
    if outcome.supervisor_interruption:
        return 128 + signal.Signals[outcome.supervisor_interruption].value
    if not outcome.completed_naturally:
        return 124
    if outcome.exit_code is None:
        raise ValueError("A completed supervised command must have an exit code")
    return outcome.exit_code if outcome.exit_code >= 0 else 128 - outcome.exit_code


def run(arguments: list[str]) -> int:
    cache = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
    with (
        ExecutionLock(cache / "autosut/reviewer-operation.lock"),
        ExecutionLock(CANONICAL_LOCK),
    ):
        namespace = NamespaceSweep.capture()
        if namespace.baseline:
            print(
                "[supervision] AutoSUT resources already exist; run bash run.sh doctor "
                "and inspect their owner before retrying. No resources were removed.",
                file=sys.stderr,
            )
            return 2
        outcome = supervise(
            ["bash", str(PROJECT_ROOT / "run.sh"), *arguments],
            deadline_seconds=DEADLINES[arguments[0]],
            grace_seconds=30,
            sweep=namespace.sweep,
        )
        receipt = (
            PROJECT_ROOT
            / "release/evidence/_reviewer_runs/supervision"
            / (uuid.uuid4().hex + ".json")
        )
        write_json_atomic(
            receipt,
            {
                "evidence_kind": "reviewer_operational_run",
                "baseline_resources": namespace.baseline,
                "deadline_seconds": DEADLINES[arguments[0]],
                "grace_seconds": 30,
                "outcome": outcome.model_dump(mode="json"),
            },
        )
        print(f"[supervision] receipt: {receipt}")
        return outcome_status(outcome)


def main() -> int:
    arguments = sys.argv[1:]
    if not arguments or arguments[0] not in DEADLINES:
        print(
            "usage: run_reviewer_supervised.py replay|witness|all [arguments]",
            file=sys.stderr,
        )
        return 2
    options = set(arguments[1:])
    if arguments[0] in {"replay", "witness"} and (
        options.intersection({"--help", "-h"})
        or (arguments[0] == "replay" and "--list" in options)
    ):
        os.execvp("bash", ["bash", str(PROJECT_ROOT / "run.sh"), *arguments])
    try:
        return run(arguments)
    except (DockerInventoryError, ExecutionLockHeld) as error:
        print(
            f"[supervision] {error}; inspect bash run.sh doctor before retrying",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
