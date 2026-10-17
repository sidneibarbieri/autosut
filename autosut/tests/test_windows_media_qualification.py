"""Native media qualification has an explicit dependency and scope boundary."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMMAND = ROOT / "scripts/qualify_windows_media.py"


def test_missing_media_tools_fail_before_running_tests(tmp_path):
    environment = {**os.environ, "PATH": str(tmp_path)}
    result = subprocess.run(
        [sys.executable, str(COMMAND)], env=environment, cwd=ROOT,
        capture_output=True, text=True, check=False,
    )

    assert result.returncode == 2
    for tool in ("qemu-img", "mformat", "mcopy", "mtype", "xorriso"):
        assert tool in result.stderr
    assert "passed" not in result.stdout


def test_preflight_is_readiness_not_media_qualification(tmp_path):
    for name in ("qemu-img", "mformat", "mcopy", "mtype", "xorriso"):
        executable = tmp_path / name
        executable.write_text("#!/bin/sh\nexit 97\n", encoding="utf-8")
        executable.chmod(0o700)
    result = subprocess.run(
        [sys.executable, str(COMMAND), "--preflight-only"],
        env={**os.environ, "PATH": str(tmp_path)}, cwd=ROOT,
        capture_output=True, text=True, check=False,
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "ready"
    assert payload["scope"] == "media_files_only"
    assert payload["qualified"] is False


def test_native_selection_keeps_both_real_media_checks():
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/test_windows_base_builder.py",
         "-m", "windows_media", "--collect-only", "-q", "-p", "no:cacheprovider"],
        env={**os.environ, "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1"}, cwd=ROOT,
        capture_output=True, text=True, check=False,
    )

    assert result.returncode == 0
    collected = [line for line in result.stdout.splitlines() if "::test_" in line]
    assert len(collected) == 2
    assert any("test_answer_disk_is_fat_and_contains_no_account_credential" in item
               for item in collected)
    assert any("test_setup_answer_is_on_separate_cdrom_without_account_credential" in item
               for item in collected)


def test_failed_native_media_checks_cannot_report_qualification(tmp_path):
    for name in ("qemu-img", "mformat", "mcopy", "mtype", "xorriso"):
        executable = tmp_path / name
        executable.write_text("#!/bin/sh\nexit 97\n", encoding="utf-8")
        executable.chmod(0o700)
    result = subprocess.run(
        [sys.executable, str(COMMAND)], env={**os.environ, "PATH": str(tmp_path)},
        cwd=ROOT, capture_output=True, text=True, check=False,
    )

    assert result.returncode == 1
    assert "2 failed" in result.stdout
    assert '"qualified": true' not in result.stdout
