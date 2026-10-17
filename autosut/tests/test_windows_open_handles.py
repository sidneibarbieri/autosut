"""Unlinked provisioning-file inventory must fail closed."""

from __future__ import annotations

import sys
from pathlib import Path
from subprocess import CompletedProcess

import pytest

ARTIFACT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ARTIFACT_ROOT / "scripts"))
from infra import windows_open_handles as module


def test_lists_only_deleted_guestfish_provisioning_files(tmp_path, monkeypatch):
    base_directory = tmp_path / "images"
    base_directory.mkdir()
    candidate = base_directory / "guestfish-overlay-abc" / "answer.xml"
    unrelated = tmp_path / "other" / "guestfish-overlay-abc" / "answer.xml"
    output = (
        "p204\nf22\n" + f"n{candidate}\n" +
        "f23\n" + f"n{unrelated}\n" +
        "f24\n" + f"n{base_directory / 'candidate.qcow2'}\n"
    )
    monkeypatch.setattr(module.subprocess, "run", lambda *args, **kwargs:
                        CompletedProcess(args[0], 0, output, ""))

    handles = module.list_open_deleted_provisioning_files(base_directory)

    assert [(handle.pid, handle.descriptor, handle.path) for handle in handles] == [
        (204, "22", candidate)
    ]


def test_open_answer_file_blocks_new_windows_run(tmp_path, monkeypatch):
    base_directory = tmp_path / "images"
    base_directory.mkdir()
    answer = base_directory / "guestfish-overlay-abc" / "answer.xml"
    monkeypatch.setattr(module.subprocess, "run", lambda *args, **kwargs:
                        CompletedProcess(args[0], 0, f"p204\nf22\nn{answer}\n", ""))

    with pytest.raises(RuntimeError, match="unlinked provisioning files remain open"):
        module.require_closed_provisioning_files(base_directory)


def test_inventory_error_is_not_treated_as_clean(tmp_path, monkeypatch):
    monkeypatch.setattr(module.subprocess, "run", lambda *args, **kwargs:
                        CompletedProcess(args[0], 1, "", "permission denied"))

    with pytest.raises(RuntimeError, match="did not complete"):
        module.require_closed_provisioning_files(tmp_path)


def test_retained_provisioning_directory_blocks_new_run(tmp_path, monkeypatch):
    (tmp_path / "guestfish-overlay-abcd").mkdir()
    monkeypatch.setattr(module.subprocess, "run", lambda *args, **kwargs:
                        CompletedProcess(args[0], 1, "", ""))

    with pytest.raises(RuntimeError, match="provisioning directories remain"):
        module.require_closed_provisioning_files(tmp_path)


def test_no_open_files_is_clean(tmp_path, monkeypatch):
    monkeypatch.setattr(module.subprocess, "run", lambda *args, **kwargs:
                        CompletedProcess(args[0], 1, "", ""))

    module.require_closed_provisioning_files(tmp_path)
