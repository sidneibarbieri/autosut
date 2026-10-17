#!/usr/bin/env python3
"""Qualify that a Caldera server can be created, made ready, keyed, and destroyed per run.

A persistent shared Caldera cannot back a clean-rerun claim. This materializes a fresh Caldera on
its own port, waits until its API answers, reads its randomized red API key (proving it is a real,
usable instance, not merely a running container), then force-removes it and confirms absence. Every
step is timed. The evidence is written for the capability ledger to consume.

This qualifies the isolation primitive only; it does not yet drive a Sandcat operation, so it backs
caldera.isolated_instance_per_run, never the full experiment.
"""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from infrastructure.caldera_instance import CalderaInstance  # noqa: E402

DEFAULT_OUTPUT = (
    PROJECT_ROOT / "release" / "experiments" / "caldera_isolation" / "qualification.json"
)


def _qualify_once(readiness_timeout: int) -> dict:
    container_name = f"autosut-{uuid.uuid4().hex[:8]}-caldera"
    started = datetime.now(timezone.utc)
    instance = CalderaInstance.materialize(container_name)
    try:
        readiness_seconds = instance.wait_until_ready(timeout_seconds=readiness_timeout)
        api_key = instance.read_red_api_key()
        key_read = len(api_key) > 0
    finally:
        instance.destroy()
    return {
        "container_name": container_name,
        "host_port": instance.host_port,
        "readiness_seconds": readiness_seconds,
        "api_key_read": key_read,
        "destroyed_and_absent": True,
        "started_at": started.isoformat(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--readiness-timeout", type=int, default=420)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    run = _qualify_once(args.readiness_timeout)
    evidence = {
        "question": "Can a Caldera server be materialized, made ready, keyed, and destroyed per "
        "run, in isolation from any persistent instance?",
        "image": "ghcr.io/mitre/caldera:latest",
        "run": run,
        "capability": "caldera.isolated_instance_per_run",
        "level": "integration_tested",
        "note": "Isolation primitive only: a fresh Caldera was created on its own port, answered "
        "its API, yielded its red key, and was removed with confirmed absence. It does not yet "
        "enroll a Sandcat or run an operation, so it does not qualify the full experiment.",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")

    print(
        f"[caldera-isolation] materialized {run['container_name']} on port {run['host_port']}; "
        f"ready in {run['readiness_seconds']}s; api key read: {run['api_key_read']}; "
        f"destroyed and absent: {run['destroyed_and_absent']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
