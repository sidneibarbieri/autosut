"""Exercise the public Bash entry point with real processes and a fake Docker CLI."""

import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time

import pytest

PACKAGE = Path(__file__).resolve().parents[2]

DOCKER = """import os,sys
from pathlib import Path
root=Path(os.environ['CLI_FIXTURE'])
arguments=sys.argv[1:]
if arguments[0]=='ps' and (root/'resource').exists():
    print('autosut-fixture')
if arguments[0]=='ps' and (root/'foreign').exists():
    print('unrelated-reviewer-resource')
if arguments[0]=='rm':
    assert arguments[-1]=='autosut-fixture'
    (root/'resource').unlink(missing_ok=True)
    (root/'swept').write_text('yes')
"""
STAGE = """import os,signal
from pathlib import Path
root=Path(os.environ['CLI_FIXTURE'])
(root/'resource').write_text('fixture container')
(root/'ready').write_text(str(os.getpid()))
signal.pause()
"""


@pytest.fixture
def public_cli(tmp_path):
    project = tmp_path / "autosut"
    scripts = project / "scripts"
    scripts.mkdir(parents=True)
    shutil.copyfile(PACKAGE / "run.sh", tmp_path / "run.sh")
    shutil.copyfile(PACKAGE / "autosut/run.sh", project / "run.sh")
    shutil.copytree(
        PACKAGE / "autosut/src/infrastructure", project / "src/infrastructure"
    )
    supervisor = PACKAGE / "autosut/scripts/run_reviewer_supervised.py"
    if supervisor.exists():
        shutil.copyfile(supervisor, scripts / supervisor.name)
    (scripts / "python_env.sh").write_text(
        'autosut_resolve_python() { printf "%s\\n" "$FIXTURE_PYTHON"; }\n'
    )
    for name in ("run_all_orchestrated_campaigns.py", "prove_subdetermination.py"):
        (scripts / name).write_text(STAGE)
    for name in ("demo.py", "doctor.py"):
        (scripts / name).write_text("raise SystemExit(0)\n")
    (project / "run_review_check.sh").write_text("exit 0\n")
    binaries = tmp_path / "bin"
    binaries.mkdir()
    docker = binaries / "docker"
    docker.write_text("#!" + sys.executable + "\n" + DOCKER)
    docker.chmod(0o700)
    (tmp_path / "foreign").write_text("preserve")
    environment = {
        "PATH": str(binaries) + os.pathsep + os.environ["PATH"],
        "HOME": str(tmp_path),
        "FIXTURE_PYTHON": sys.executable,
        "CLI_FIXTURE": str(tmp_path),
    }
    return tmp_path, environment


@pytest.mark.parametrize("command", ["replay", "witness", "all"])
@pytest.mark.parametrize("stop_signal", [signal.SIGINT, signal.SIGTERM])
def test_stop_reaches_owned_stage_and_sweeps_resources(
    public_cli, command, stop_signal
):
    directory, environment = public_cli
    process = subprocess.Popen(
        ["bash", "run.sh", command],
        cwd=directory,
        env=environment,
        start_new_session=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        deadline = time.monotonic() + 10
        while (
            not (directory / "ready").exists()
            and process.poll() is None
            and time.monotonic() < deadline
        ):
            time.sleep(0.01)
        assert (directory / "ready").exists(), process.communicate(timeout=1)
        os.kill(process.pid, stop_signal)
        stdout, stderr = process.communicate(timeout=5)
        assert process.returncode == 128 + stop_signal, (stdout, stderr)
        assert not (directory / "resource").exists()
        assert (directory / "swept").exists()
        assert (directory / "foreign").read_text() == "preserve"
        receipts = list(
            directory.glob("autosut/release/evidence/_reviewer_runs/supervision/*.json")
        )
        assert len(receipts) == 1
        receipt = json.loads(receipts[0].read_text())
        assert receipt["outcome"]["cleanup_completed"]
        assert receipt["outcome"]["supervisor_interruption"] == stop_signal.name
    finally:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        process.communicate(timeout=5)


def test_existing_namespace_is_refused_without_removing_it(public_cli):
    directory, environment = public_cli
    (directory / "resource").write_text("preexisting")
    result = subprocess.run(
        ["bash", "run.sh", "replay"],
        cwd=directory,
        env=environment,
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert result.returncode == 2
    assert (directory / "resource").read_text() == "preexisting"
    assert not (directory / "ready").exists()
    assert "doctor" in result.stderr


def test_child_failure_status_is_preserved(public_cli):
    directory, environment = public_cli
    stage = directory / "autosut/scripts/run_all_orchestrated_campaigns.py"
    stage.write_text("raise SystemExit(2)\n")
    result = subprocess.run(
        ["bash", "run.sh", "replay"],
        cwd=directory,
        env=environment,
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert result.returncode == 2
    receipt = next(
        directory.glob("autosut/release/evidence/_reviewer_runs/supervision/*.json")
    )
    outcome = json.loads(receipt.read_text())["outcome"]
    assert outcome["completed_naturally"]
    assert outcome["exit_code"] == 2


def test_second_operation_cannot_sweep_the_first_operation(public_cli):
    directory, environment = public_cli
    first = subprocess.Popen(
        ["bash", "run.sh", "witness"],
        cwd=directory,
        env=environment,
        start_new_session=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        deadline = time.monotonic() + 10
        while (
            not (directory / "ready").exists()
            and first.poll() is None
            and time.monotonic() < deadline
        ):
            time.sleep(0.01)
        assert (directory / "ready").exists()
        second = subprocess.run(
            ["bash", "run.sh", "replay"],
            cwd=directory,
            env=environment,
            capture_output=True,
            text=True,
            timeout=5,
        )
        assert second.returncode == 2
        assert "holder pid" in second.stderr
        assert (directory / "resource").exists()
        assert not (directory / "swept").exists()
        os.kill(first.pid, signal.SIGTERM)
        first.communicate(timeout=5)
        assert first.returncode == 143
        assert not (directory / "resource").exists()
    finally:
        try:
            os.killpg(first.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        first.communicate(timeout=5)
