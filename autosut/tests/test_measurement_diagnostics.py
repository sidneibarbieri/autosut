"""Measurement diagnostics stay local and distinct for each invocation."""

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import re
import subprocess

import pytest

from scripts.measurement_diagnostics import LOG_NAMES

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts" / "measurement_log_directory.sh"


def _invoke(artifact: Path, result: int) -> tuple[Path, subprocess.CompletedProcess[str]]:
    command = (
        'set -euo pipefail; source "$1"; '
        'directory="$(create_measurement_log_directory "$2")"; '
        'printf "%s\\n" "$directory"; '
        'printf "diagnostic\\n" > "$directory/measurement_pipeline_release.log"; '
        'exit "$3"'
    )
    process = subprocess.run(
        ["bash", "-c", command, "diagnostic-test", str(HELPER), str(artifact), str(result)],
        capture_output=True, text=True, check=False,
    )
    return Path(process.stdout.strip()), process


@pytest.mark.parametrize("exit_code", [0, 7])
def test_diagnostics_retained_on_success_and_failure(tmp_path, exit_code):
    directory, process = _invoke(tmp_path, exit_code)
    assert process.returncode == exit_code
    assert directory.parent == tmp_path / "results" / "reviewer_runtime"
    assert (directory / "measurement_pipeline_release.log").read_text() == "diagnostic\n"


def test_concurrent_diagnostics_do_not_overwrite_each_other(tmp_path):
    with ThreadPoolExecutor(max_workers=4) as workers:
        futures = [workers.submit(_invoke, tmp_path, 0) for invocation_index in range(4)]
        outcomes = [future.result() for future in futures]
    assert all(process.returncode == 0 for directory, process in outcomes)
    assert len({directory for directory, process in outcomes}) == 4
    assert all((directory / "measurement_pipeline_release.log").is_file()
               for directory, process in outcomes)


def test_release_check_has_no_shared_diagnostic_paths():
    source = (ROOT / "measurement" / "sut" / "release_check.sh").read_text()
    assert "/tmp/measurement_" not in source
    assert 'create_measurement_log_directory "$AUTOSUT_ROOT"' in source


def test_diagnostics_reject_symlink_destination(tmp_path):
    external = tmp_path / "external"
    external.mkdir()
    (tmp_path / "results").symlink_to(external, target_is_directory=True)
    directory, process = _invoke(tmp_path, 0)
    assert process.returncode != 0
    assert "symlink" in process.stderr
    assert list(external.iterdir()) == []


def test_release_log_names_match_declared_layout():
    source = (ROOT / "measurement" / "sut" / "release_check.sh").read_text()
    names = set(re.findall(r'\$MEASUREMENT_LOG_DIR/(measurement_[a-z_]+\.log)', source))
    assert names == LOG_NAMES
