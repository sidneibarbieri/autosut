#!/usr/bin/env python3
"""Qualify this host and print which experiment backends are usable here.

Run before any campaign materializes infrastructure. Exits non-zero when no backend is usable,
so a pipeline can gate on it. The written report is a live host snapshot, not frozen evidence.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from infrastructure.preflight import BackendStatus, run_preflight  # noqa: E402

DEFAULT_OUTPUT = PROJECT_ROOT / "release" / "experiments" / "preflight" / "host_qualification.json"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--require-backend",
        choices=("docker", "qemu_linux_arm64", "windows_x86_64"),
        help="Require this backend to be available for an attempt, not boot-qualified.",
    )
    args = parser.parse_args()

    report = run_preflight()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(report.model_dump_json(indent=2) + "\n", encoding="utf-8")

    print(
        f"[preflight] {report.host.operating_system} {report.host.architecture}, "
        f"{report.host.cpu_count} vCPU, {report.host.memory_gib} GiB RAM, "
        f"{report.host.free_disk_gib} GiB free"
    )
    for backend in report.backends:
        gaps = f" -- {'; '.join(backend.requirement_gaps)}" if backend.requirement_gaps else ""
        print(f"[preflight] {backend.backend}: {backend.status.value}{gaps}")

    candidates = [
        backend for backend in report.backends
        if args.require_backend is None or backend.backend == args.require_backend
    ]
    usable = [backend for backend in candidates if backend.status is not BackendStatus.BLOCKED]
    return 0 if usable else 1


if __name__ == "__main__":
    raise SystemExit(main())
