"""The run context isolates, namespaces, and seals one experiment run.

Each run gets a unique id and directory, every resource name carries the run's prefix, the sealed
manifest hashes every file, and the execution lock refuses a second concurrent holder instead of
blocking or proceeding silently.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from infrastructure.run_context import (  # noqa: E402
    ExecutionLock,
    ExecutionLockHeld,
    RunContext,
)


def test_two_runs_get_distinct_ids_and_directories(tmp_path):
    first = RunContext.create(tmp_path)
    second = RunContext.create(tmp_path)
    assert first.run_id != second.run_id
    assert first.run_dir != second.run_dir
    assert first.run_dir.is_dir() and second.run_dir.is_dir()


def test_resource_names_are_namespaced_to_the_run(tmp_path):
    run = RunContext.create(tmp_path)
    name = run.namespaced("caldera")
    assert name.startswith("autosut-")
    assert name.endswith("-caldera")
    assert run.run_id.rsplit("-", 1)[-1] in name


def test_seal_hashes_every_file_and_excludes_the_manifest(tmp_path):
    run = RunContext.create(tmp_path)
    run.path("sut", "setup.log").write_text("boot ok\n", encoding="utf-8")
    run.path("probe.json").write_text("{}\n", encoding="utf-8")
    manifest = run.seal()
    assert manifest.file_count == 2
    assert {entry.path for entry in manifest.files} == {"sut/setup.log", "probe.json"}
    assert all(len(entry.sha256) == 64 for entry in manifest.files)
    assert (run.run_dir / "manifest.json").is_file()
    assert "manifest.json" not in {entry.path for entry in manifest.files}


def test_seal_total_bytes_equals_the_sum_of_entry_sizes(tmp_path):
    run = RunContext.create(tmp_path)
    run.path("a.txt").write_text("hello", encoding="utf-8")
    run.path("b.txt").write_text("world!", encoding="utf-8")
    manifest = run.seal()
    assert manifest.total_bytes == sum(entry.bytes for entry in manifest.files)


def test_the_execution_lock_refuses_a_second_concurrent_holder(tmp_path):
    lock_path = tmp_path / "experiment.lock"
    with ExecutionLock(lock_path):
        with pytest.raises(ExecutionLockHeld):
            with ExecutionLock(lock_path):
                pass


def test_the_execution_lock_is_reacquirable_after_release(tmp_path):
    lock_path = tmp_path / "experiment.lock"
    with ExecutionLock(lock_path):
        pass
    with ExecutionLock(lock_path):
        pass
