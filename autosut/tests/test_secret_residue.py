"""The secret-residue scan finds planted secrets, stays fail-closed, and never leaks the secret."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from infrastructure.secret_residue import scan_for_secret

_SENTINEL = "AUTOSUT_SENTINEL_c0ffee1234567890deadbeef"


def test_a_clean_tree_reports_clean(tmp_path: Path):
    (tmp_path / "a.txt").write_text("nothing sensitive here\n", encoding="utf-8")
    report = scan_for_secret(_SENTINEL, [tmp_path], "run-secret")
    assert report.clean
    assert report.scan_completed
    assert report.matches == []
    assert report.files_scanned == 1


def test_a_planted_secret_is_found_and_makes_the_report_not_clean(tmp_path: Path):
    (tmp_path / "bundle.log").write_text(f"password={_SENTINEL} was used\n", encoding="utf-8")
    report = scan_for_secret(_SENTINEL, [tmp_path], "run-secret")
    assert not report.clean
    assert len(report.matches) == 1
    assert report.matches[0].line == 1


def test_the_report_never_contains_the_secret(tmp_path: Path):
    (tmp_path / "bundle.log").write_text(f"secret {_SENTINEL} here\n", encoding="utf-8")
    report = scan_for_secret(_SENTINEL, [tmp_path], "run-secret")
    assert _SENTINEL not in report.model_dump_json()
    assert "<REDACTED-SENTINEL>" in report.matches[0].redacted_context


def test_an_unreadable_root_fails_closed(tmp_path: Path, monkeypatch):
    (tmp_path / "a.txt").write_text("data\n", encoding="utf-8")

    real_read_bytes = Path.read_bytes

    def exploding_read_bytes(self: Path):
        if self.name == "a.txt":
            raise PermissionError("cannot read")
        return real_read_bytes(self)

    monkeypatch.setattr(Path, "read_bytes", exploding_read_bytes)
    report = scan_for_secret(_SENTINEL, [tmp_path], "run-secret")
    assert report.scan_completed is False
    assert report.clean is False
    assert report.roots_unreadable


def test_an_absent_root_is_recorded_not_a_failure(tmp_path: Path):
    present = tmp_path / "present"
    present.mkdir()
    (present / "a.txt").write_text("clean\n", encoding="utf-8")
    absent = tmp_path / "was-destroyed-on-teardown"
    report = scan_for_secret(_SENTINEL, [present, absent], "run-secret")
    assert report.clean
    assert str(absent) in report.roots_absent


def test_scanning_for_an_empty_sentinel_is_refused(tmp_path: Path):
    with pytest.raises(ValueError):
        scan_for_secret("", [tmp_path], "run-secret")


def test_binary_files_are_scanned_and_reported_without_decoding(tmp_path: Path):
    (tmp_path / "blob.bin").write_bytes(b"\x00\x01" + _SENTINEL.encode() + b"\xff\xfe")
    report = scan_for_secret(_SENTINEL, [tmp_path], "run-secret")
    assert not report.clean
    assert report.matches[0].line is None
    assert report.matches[0].redacted_context == "<binary match>"


@pytest.mark.parametrize("encoding", ["utf-16le", "utf-16be"])
def test_utf16_residue_is_not_reported_clean(tmp_path: Path, encoding: str):
    (tmp_path / "answer.xml").write_bytes(f"secret={_SENTINEL}".encode(encoding))

    report = scan_for_secret(_SENTINEL, [tmp_path], "run-secret")

    assert not report.clean
    assert report.matches
    assert _SENTINEL not in report.model_dump_json()


@pytest.mark.parametrize("scan_link_as_root", [False, True])
def test_directory_symlink_fails_closed(tmp_path: Path, scan_link_as_root: bool):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "residue.txt").write_text(_SENTINEL, encoding="utf-8")
    root = tmp_path / "scan"
    root.mkdir()
    link = root / "linked-directory"
    link.symlink_to(outside, target_is_directory=True)

    report = scan_for_secret(_SENTINEL, [link if scan_link_as_root else root], "run-secret")

    assert not report.scan_completed
    assert not report.clean
    assert report.roots_unreadable


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="requires POSIX FIFO support")
def test_nonregular_file_fails_closed_without_opening_it(tmp_path: Path):
    os.mkfifo(tmp_path / "pipe")

    report = scan_for_secret(_SENTINEL, [tmp_path], "run-secret")

    assert not report.scan_completed
    assert not report.clean


def test_directory_enumeration_failure_is_not_silently_omitted(tmp_path: Path, monkeypatch):
    blocked = tmp_path / "blocked"
    blocked.mkdir()
    original_scandir = os.scandir

    def guarded_scandir(path):
        if Path(path) == blocked:
            raise PermissionError("synthetic directory enumeration failure")
        return original_scandir(path)

    monkeypatch.setattr(os, "scandir", guarded_scandir)

    report = scan_for_secret(_SENTINEL, [tmp_path], "run-secret")

    assert not report.scan_completed
    assert not report.clean
    assert report.roots_unreadable


def test_credential_in_filename_is_detected_without_report_leakage(tmp_path: Path):
    (tmp_path / f"{_SENTINEL}.txt").write_text("clean content", encoding="utf-8")

    report = scan_for_secret(_SENTINEL, [tmp_path], "run-secret")

    assert not report.clean
    assert report.matches
    assert _SENTINEL not in report.model_dump_json()


def test_credential_in_requested_metadata_is_redacted(tmp_path: Path):
    absent = tmp_path / _SENTINEL

    report = scan_for_secret(_SENTINEL, [absent], _SENTINEL)

    assert _SENTINEL not in report.model_dump_json()
    assert report.roots_absent


def test_match_report_does_not_copy_adjacent_credentials(tmp_path: Path):
    adjacent_secret = "SECOND_SYNTHETIC_SECRET_0123456789abcdef"
    (tmp_path / "credentials.log").write_text(
        f"password={_SENTINEL} other_password={adjacent_secret}\n", encoding="utf-8",
    )

    report = scan_for_secret(_SENTINEL, [tmp_path], "run-secret")

    assert not report.clean
    assert _SENTINEL not in report.model_dump_json()
    assert adjacent_secret not in report.model_dump_json()
