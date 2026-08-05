#!/usr/bin/env python3
"""
Canonical VM-backed campaign orchestration for STICKS.

This script turns the existing lab helpers into one explicit realism path:

    up_lab -> run_campaign -> collect_evidence -> generate_corpus_state -> teardown

The host-only smoke path remains the baseline validation contract. This script is
the provider-aware entry point for campaigns that need a concrete VM substrate.
It preserves honest failure semantics: failed campaigns still refresh the
evidence summary and corpus state before teardown.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Sequence


PROJECT_ROOT = Path(__file__).resolve().parent.parent
UP_LAB_SCRIPT = PROJECT_ROOT / "scripts" / "up_lab.sh"
DESTROY_LAB_SCRIPT = PROJECT_ROOT / "scripts" / "destroy_lab.sh"
RUN_CAMPAIGN_SCRIPT = PROJECT_ROOT / "scripts" / "run_campaign.py"
COLLECT_EVIDENCE_SCRIPT = PROJECT_ROOT / "scripts" / "collect_evidence.sh"
GENERATE_CORPUS_STATE_SCRIPT = PROJECT_ROOT / "scripts" / "generate_corpus_state.py"
EVIDENCE_DIR = PROJECT_ROOT / "release" / "evidence"
SNAPSHOT_ROOTS = (
    PROJECT_ROOT / "release",
    PROJECT_ROOT / "results",
)
RUNTIME_ONLY_DIRS = (
    PROJECT_ROOT / "release" / "realistic_data",
    PROJECT_ROOT / "release" / "sut_reports",
)
SNAPSHOT_SKIP_DIRS = (
    PROJECT_ROOT / "release" / "evidence",
    PROJECT_ROOT / "results" / "evidence",
    *RUNTIME_ONLY_DIRS,
)


def _log(message: str) -> None:
    print(f"[RUN-LAB] {message}", flush=True)


def _build_up_command(campaign_id: str, provider: str | None) -> list[str]:
    command = ["bash", str(UP_LAB_SCRIPT), "--campaign", campaign_id]
    if provider:
        command.extend(["--provider", provider])
    return command


def _build_destroy_command(campaign_id: str) -> list[str]:
    return ["bash", str(DESTROY_LAB_SCRIPT), "--campaign", campaign_id]


def _run_command(command: Sequence[str], label: str) -> None:
    _log(f"Starting: {label}")
    subprocess.run(
        list(command),
        cwd=str(PROJECT_ROOT),
        check=True,
        env=os.environ.copy(),
    )
    _log(f"Completed: {label}")


def _raise_errors(errors: list[BaseException]) -> None:
    if not errors:
        return
    if len(errors) == 1:
        raise errors[0]
    raise ExceptionGroup("VM-backed execution encountered multiple failures", errors)


def _evidence_available() -> bool:
    return EVIDENCE_DIR.exists() and any(EVIDENCE_DIR.iterdir())


def _is_within(path: Path, candidate_root: Path) -> bool:
    return path == candidate_root or candidate_root in path.parents


def _iter_snapshot_files() -> list[Path]:
    files: list[Path] = []
    for root in SNAPSHOT_ROOTS:
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if any(_is_within(path, skip_dir) for skip_dir in SNAPSHOT_SKIP_DIRS):
                continue
            files.append(path)
    return files


def _remove_empty_directories(root: Path) -> None:
    if not root.exists():
        return
    for directory in sorted(
        (path for path in root.rglob("*") if path.is_dir()),
        key=lambda path: len(path.parts),
        reverse=True,
    ):
        if any(_is_within(directory, skip_dir) for skip_dir in SNAPSHOT_SKIP_DIRS):
            continue
        try:
            directory.rmdir()
        except OSError:
            continue


class _DerivedStateSnapshot:
    def __init__(self, temp_dir: tempfile.TemporaryDirectory[str], files: dict[Path, Path]):
        self._temp_dir = temp_dir
        self._files = files
        self._restored = False

    @classmethod
    def capture(cls) -> "_DerivedStateSnapshot":
        temp_dir = tempfile.TemporaryDirectory(prefix="sticks_derived_state_")
        snapshot_root = Path(temp_dir.name)
        files: dict[Path, Path] = {}

        for source_path in _iter_snapshot_files():
            relative_path = source_path.relative_to(PROJECT_ROOT)
            snapshot_path = snapshot_root / relative_path
            snapshot_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source_path, snapshot_path)
            files[source_path] = snapshot_path

        return cls(temp_dir, files)

    def restore(self) -> None:
        if self._restored:
            return

        original_paths = set(self._files.keys())
        current_paths = set(_iter_snapshot_files())

        for extra_path in current_paths - original_paths:
            extra_path.unlink()

        for live_path, snapshot_path in self._files.items():
            live_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(snapshot_path, live_path)

        for root in SNAPSHOT_ROOTS:
            _remove_empty_directories(root)

        self._temp_dir.cleanup()
        self._restored = True


def _capture_derived_state() -> _DerivedStateSnapshot:
    return _DerivedStateSnapshot.capture()


def _cleanup_runtime_outputs() -> None:
    for runtime_dir in RUNTIME_ONLY_DIRS:
        shutil.rmtree(runtime_dir, ignore_errors=True)


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Canonical VM-backed campaign execution for STICKS."
    )
    parser.add_argument("--campaign", required=True, help="Campaign ID to execute.")
    parser.add_argument(
        "--provider",
        choices=["qemu", "libvirt", "virtualbox"],
        help="Explicit Vagrant provider. Omit to use host-aware detection in up_lab.sh.",
    )
    parser.add_argument(
        "--keep-lab",
        action="store_true",
        help="Keep the lab running after execution for manual inspection.",
    )
    parser.add_argument(
        "--skip-collect-evidence",
        action="store_true",
        help="Skip evidence/report refresh after the campaign run.",
    )
    parser.add_argument(
        "--assume-lab-running",
        action="store_true",
        help=(
            "Opt-in development mode: skip infrastructure startup and assume a "
            "compatible lab is already running."
        ),
    )
    parser.add_argument(
        "--persist-derived-state",
        action="store_true",
        help=(
            "Keep refreshed release/results summaries and runtime-only outputs in the "
            "checkout after the run."
        ),
    )
    return parser.parse_args(argv)


def run_lab_campaign(args: argparse.Namespace) -> int:
    errors: list[BaseException] = []
    lab_started = bool(args.assume_lab_running)
    snapshot = None if args.persist_derived_state else _capture_derived_state()

    if args.persist_derived_state:
        _log("Preserving derived state because --persist-derived-state was requested")

    try:
        if args.assume_lab_running:
            _log("Skipping lab startup because --assume-lab-running was requested")
        else:
            try:
                _run_command(_build_up_command(args.campaign, args.provider), "bring up lab")
                lab_started = True
            except BaseException as error:
                errors.append(error)

        if not errors:
            try:
                _run_command(
                    [sys.executable, str(RUN_CAMPAIGN_SCRIPT), "--campaign", args.campaign],
                    "execute campaign",
                )
            except BaseException as error:
                errors.append(error)

        if not args.skip_collect_evidence and not errors:
            try:
                _run_command(
                    ["bash", str(COLLECT_EVIDENCE_SCRIPT)],
                    "refresh evidence summary",
                )
            except BaseException as error:
                errors.append(error)

            try:
                _run_command(
                    [sys.executable, str(GENERATE_CORPUS_STATE_SCRIPT)],
                    "refresh corpus state",
                )
            except BaseException as error:
                errors.append(error)

        elif not args.skip_collect_evidence and lab_started and _evidence_available():
            _log(
                "Execution failed after lab startup; refreshing evidence and corpus state"
            )
            try:
                _run_command(
                    ["bash", str(COLLECT_EVIDENCE_SCRIPT)],
                    "refresh evidence summary",
                )
            except BaseException as error:
                errors.append(error)

            try:
                _run_command(
                    [sys.executable, str(GENERATE_CORPUS_STATE_SCRIPT)],
                    "refresh corpus state",
                )
            except BaseException as error:
                errors.append(error)
        elif errors:
            _log(
                "Skipping evidence refresh because the lab did not reach an evidence-producing state"
            )
    finally:
        if args.keep_lab:
            _log("Keeping lab running because --keep-lab was requested")
        else:
            try:
                _run_command(_build_destroy_command(args.campaign), "tear down lab")
            except BaseException as error:
                errors.append(error)

        if snapshot is not None:
            try:
                snapshot.restore()
                _cleanup_runtime_outputs()
                _log("Restored tracked derived state and cleaned runtime-only outputs")
            except BaseException as error:
                errors.append(error)

    _raise_errors(errors)
    _log("VM-backed execution path completed successfully")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    return run_lab_campaign(args)


if __name__ == "__main__":
    raise SystemExit(main())
