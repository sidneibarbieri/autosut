"""End-to-end smoke for the QEMU backend.

Brings up a one-VM Vagrant project under a temp evidence dir, runs a few
``whoami`` / ``uname -a`` style commands via ``vagrant ssh``, then tears
the VM down with ``vagrant destroy -f``. Records timings and a small
provenance breadcrumb so reviewers can audit the cold-start cost of the
extended-realism path.

This is **deliberately not** part of the pytest suite because the first
invocation downloads the Vagrant box (multiple hundred MB) and can take
several minutes on a slow connection. Re-runs that hit the cached box are
typically 60-120 s on Apple Silicon.

Usage::

    .venv/bin/python scripts/qemu_backend_smoke.py
"""

from __future__ import annotations

import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from orchestrator.models import SUTProfile  # noqa: E402
from orchestrator.qemu_environment import QEMUEnvironment  # noqa: E402


def run() -> int:
    run_id = f"qemu_smoke_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
    run_dir = Path("release/evidence") / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    profile = SUTProfile(
        sut_id="qemu_smoke",
        base_image="ubuntu-2204-arm64",
        services=[],
        memory_mb=2048,
        smp=2,
        backend="qemu",
        notes="QEMU smoke — one-shot vagrant-qemu boot under a temp project.",
    )

    print(f"[qemu-smoke] run_id={run_id}")
    print(f"[qemu-smoke] bringing up VM (first run may download box) ...")

    t0 = time.monotonic()
    env = QEMUEnvironment.bring_up(profile, run_dir)
    bring_up_s = time.monotonic() - t0
    print(f"[qemu-smoke] vagrant up: {bring_up_s:.1f} s")

    try:
        for command in ("whoami", "uname -a", "cat /etc/os-release | head -3"):
            r = env.run_shell(command, log_name=f"qemu/{command.split()[0]}.log")
            print(f"[qemu-smoke] $ {command!r} -> exit={r.exit_code}")
            print(f"    stdout: {r.stdout.strip()[:200]}")
            if r.stderr.strip():
                print(f"    stderr: {r.stderr.strip()[:200]}")
    finally:
        t0 = time.monotonic()
        ok = env.teardown()
        teardown_s = time.monotonic() - t0
        print(f"[qemu-smoke] vagrant destroy: {teardown_s:.1f} s "
              f"(clean={ok})")

    print(f"[qemu-smoke] evidence: {run_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(run())
