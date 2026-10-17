#!/usr/bin/env python3
"""Run one campaign through the canonical, timed, sealed lifecycle.

This is the single canonical entrypoint. It gates on the backend's own readiness check, holds the
single-experiment lock, drives the real campaign (real container materialization, real technique
execution, real teardown), then independently verifies the environment is clean and seals the run
bundle. Nothing here is a mock, a dry run, or a simulation; a residual container is reported as
residual, and teardown returning is never taken as proof the environment is clean.

Usage:
    python3 scripts/run_lifecycle.py 0.c0010 --label _run1
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from contextlib import nullcontext
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPTS_DIR.parent
for import_root in (SCRIPTS_DIR, PROJECT_ROOT / "src"):
    if str(import_root) not in sys.path:
        sys.path.insert(0, str(import_root))

from infrastructure.lifecycle import (  # noqa: E402
    LifecycleController,
    ResidualReport,
    Stage,
)
from infrastructure.docker_namespace import (  # noqa: E402
    DockerInventoryError,
    autosut_resources,
)
from infrastructure.revision import current_revision  # noqa: E402
from infrastructure.run_context import ExecutionLock, RunContext, seal_directory  # noqa: E402
from infrastructure.qualification import (  # noqa: E402
    prepare_supervised_qualification_metadata,
    write_qualification_metadata,
)
from infrastructure.supervision_evidence import bind_child_run  # noqa: E402
from infrastructure.verify_clean import sample_until_clean  # noqa: E402
from orchestrator import build_default  # noqa: E402
from orchestrator.environment import DockerEnvironment  # noqa: E402

EVIDENCE_ROOT = PROJECT_ROOT / "release" / "evidence"
LOCK_PATH = PROJECT_ROOT / "release" / "experiments" / "lifecycle" / "experiment.lock"


def _autosut_containers() -> set[str]:
    """Every container whose name carries the autosut prefix, running or exited."""
    return {
        resource.split(":", 1)[1]
        for resource in autosut_resources()
        if resource.startswith("container:")
    }


def _autosut_resources() -> set[str]:
    """Every autosut-prefixed docker resource, labelled by kind, across containers/networks/volumes."""
    return autosut_resources()


def _force_remove(containers: set[str]) -> None:
    """Best-effort force-remove; absence is confirmed separately, so exit codes are not read.

    The campaign tears its own containers down, but the ``--rm`` flag removes them asynchronously,
    so a container can still be present here. Force-removing is idempotent against one already
    gone or mid-removal; the success criterion is confirmed absence, not this command's result.
    """
    for name in sorted(containers):
        subprocess.run(
            ["docker", "rm", "-f", name],
            capture_output=True, text=True, check=False, timeout=60,
        )


def _await_absence(containers: set[str], timeout_seconds: int = 30) -> set[str]:
    """Poll until none of the named containers remain, returning any that survive the timeout."""
    deadline = time.monotonic() + timeout_seconds
    remaining = containers & _autosut_containers()
    while remaining and time.monotonic() < deadline:
        time.sleep(1)
        remaining = containers & _autosut_containers()
    return remaining


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("campaign", help="campaign id, e.g. 0.c0010")
    parser.add_argument("--label", default="run", help="tag to distinguish reruns, e.g. run1")
    parser.add_argument(
        "--evidence-root",
        type=Path,
        default=EVIDENCE_ROOT,
        help="directory for this run's sealed bundle; defaults to release/evidence",
    )
    parser.add_argument("--fidelity", default="real_then_surrogate")
    parser.add_argument(
        "--inject-failure",
        action="store_true",
        help="materialize a real container then fail, to prove teardown still reaches clean",
    )
    parser.add_argument("--supervision-id", help="opaque identifier created by run_supervised.py")
    parser.add_argument(
        "--supervision-receipt-file",
        type=Path,
        help="supervisor-owned receipt path; required with --supervision-id",
    )
    parser.add_argument(
        "--supervision-handoff-file",
        type=Path,
        help="child-to-supervisor handoff path; required with --supervision-id",
    )
    parser.add_argument(
        "--supervision-lock-held",
        action="store_true",
        help="the parent supervisor holds the canonical execution lock",
    )
    parser.add_argument(
        "--qualification-protocol-version",
        help="opt in to a final supervised qualification protocol; requires revision and topology",
    )
    parser.add_argument(
        "--qualification-revision",
        help="immutable clean git commit required by the opted-in qualification protocol",
    )
    parser.add_argument(
        "--qualification-topology",
        help="declared topology required by the opted-in qualification protocol",
    )
    args = parser.parse_args()

    supervision_values = (
        args.supervision_id,
        args.supervision_receipt_file,
        args.supervision_handoff_file,
    )
    if any(value is not None for value in supervision_values) and not all(
        value is not None for value in supervision_values
    ):
        parser.error("supervision id, receipt file, and handoff file must be supplied together")
    if args.supervision_lock_held and args.supervision_id is None:
        parser.error("--supervision-lock-held requires supervision evidence arguments")

    observed_revision = current_revision(PROJECT_ROOT)
    try:
        qualification_metadata = prepare_supervised_qualification_metadata(
            protocol_version=args.qualification_protocol_version,
            required_revision=args.qualification_revision,
            topology=args.qualification_topology,
            observed_revision=observed_revision,
            supervised=args.supervision_id is not None,
        )
    except ValueError as error:
        parser.error(str(error))

    run_context = RunContext.create(args.evidence_root, label=f"{args.campaign}_{args.label}")
    if args.supervision_id is not None:
        bind_child_run(
            project_root=PROJECT_ROOT,
            run_dir=run_context.run_dir,
            run_id=run_context.run_id,
            experiment="lifecycle",
            entrypoint=Path(__file__).name,
            supervision_id=args.supervision_id,
            receipt_path=args.supervision_receipt_file,
            handoff_path=args.supervision_handoff_file,
        )
    write_qualification_metadata(run_context.run_dir, qualification_metadata)
    controller = LifecycleController(
        run_context=run_context,
        backend_readiness=lambda: DockerEnvironment.check().ready,
    )

    baseline = _autosut_containers()

    def materialize_and_execute() -> None:
        if args.inject_failure:
            _materialize_injected_container(run_context.namespaced("injected"))
            raise RuntimeError("injected failure after materialization")
        build_default().run_campaign(
            args.campaign, fidelity_preference=args.fidelity, run_dir=run_context.run_dir
        )

    def verified_teardown() -> None:
        appeared = _autosut_containers() - baseline
        if not appeared:
            return
        _force_remove(appeared)
        survivors = _await_absence(appeared)
        if survivors:
            raise RuntimeError(f"containers survived force-removal: {sorted(survivors)}")

    resource_baseline = _autosut_resources()

    def inspect_residual() -> ResidualReport:
        # Sample over a grace period: teardown is asynchronous, so a single glance cannot tell a
        # real leak from a removal still in flight. The full timeline is persisted for audit.
        try:
            temporal = sample_until_clean(
                scope="docker.autosut",
                inventory=lambda: sorted(_autosut_resources() - resource_baseline),
            )
        except DockerInventoryError as error:
            run_context.path("verify-clean-inventory-error.json").write_text(
                error.diagnostic.model_dump_json(indent=2), encoding="utf-8"
            )
            return ResidualReport(
                scope="docker.autosut",
                residual_resources=[
                    f"inventory-unavailable:{error.diagnostic.failure_kind.value}"
                ],
            )
        run_context.path("verify-clean.json").write_text(
            temporal.model_dump_json(indent=2), encoding="utf-8"
        )
        final_sample = temporal.samples[-1].resources if temporal.samples else []
        return ResidualReport(scope=temporal.scope, residual_resources=final_sample)

    lock_context = nullcontext() if args.supervision_lock_held else ExecutionLock(LOCK_PATH)
    with lock_context:
        result = controller.run(
            label=args.label,
            forward_stages=[Stage("materialize_execute_teardown", materialize_and_execute)],
            teardown_stages=[Stage("verified_teardown", verified_teardown, is_teardown=True)],
            inspect_residual=inspect_residual,
        )

    # Store the bundle location relative to the project root so a published bundle carries no
    # host-specific absolute path, and tie the run to the code revision it executed on. An evidence
    # root outside the project (a test tmp dir) has no meaningful relative path, so keep it absolute.
    try:
        result.evidence_dir = str(run_context.run_dir.relative_to(PROJECT_ROOT))
    except ValueError:
        result.evidence_dir = str(run_context.run_dir)
    result.implementation_revision = observed_revision
    run_dir = _persist_lifecycle_artifacts(result, run_context.run_dir)
    manifest = seal_directory(run_dir, result.run_id, run_context.created_at)

    print(f"[lifecycle] campaign: {args.campaign} label: {args.label}")
    for stage in result.stages:
        mark = "ok" if stage.succeeded else f"FAILED ({stage.error})"
        print(f"[lifecycle]   {stage.name}: {stage.seconds}s {mark}")
    print(f"[lifecycle] total: {result.total_seconds}s")
    print(f"[lifecycle] residual containers: {result.residual.residual_resources or 'none'}")
    print(f"[lifecycle] final state: {result.final_state.value}")
    print(f"[lifecycle] sealed bundle: {run_dir} ({manifest.file_count} files)")
    return 0 if result.final_state.value == "clean" else 2


def _materialize_injected_container(name: str) -> None:
    """Create one real, short-lived container so an injected failure has something to clean up."""
    subprocess.run(
        ["docker", "run", "-d", "--name", name, "alpine:3.20", "sleep", "120"],
        capture_output=True, text=True, check=True, timeout=120,
    )


def _persist_lifecycle_artifacts(result, run_dir: Path) -> Path:
    """Write the lifecycle timing, residual, and result records into the run bundle."""
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "stage-timings.json").write_text(
        json.dumps([stage.model_dump() for stage in result.stages], indent=2), encoding="utf-8"
    )
    (run_dir / "residual-resources.json").write_text(
        result.residual.model_dump_json(indent=2), encoding="utf-8"
    )
    (run_dir / "lifecycle-result.json").write_text(
        result.model_dump_json(indent=2), encoding="utf-8"
    )
    return run_dir


if __name__ == "__main__":
    raise SystemExit(main())
