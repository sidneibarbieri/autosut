"""The root run.sh is the single reviewer entry point; each command delegates to one path."""

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
# macOS ships bash 3.2, where an empty array under `set -u` is an error.
SYSTEM_BASH = "/bin/bash" if Path("/bin/bash").exists() else "bash"


@pytest.fixture
def fake_python(tmp_path):
    """An interpreter stand-in that records its arguments and fails on request."""
    executable = tmp_path / "python-fixture"
    executable.write_text(
        "#!/usr/bin/env python3\n"
        "import json, os, sys\n"
        "with open(os.environ['AUTOSUT_TEST_CALLS'], 'a') as stream:\n"
        "    stream.write(json.dumps(sys.argv[1:]) + '\\n')\n"
        "if sys.argv[1:2] == [os.environ.get('AUTOSUT_TEST_FAIL')]:\n"
        "    raise SystemExit(9)\n"
    )
    executable.chmod(0o700)
    calls = tmp_path / "calls.jsonl"
    environment = {"PATH": os.environ["PATH"], "HOME": str(tmp_path),
                   "AUTOSUT_TEST_CALLS": str(calls)}
    return executable, calls, environment


def front_door(environment, *arguments):
    return subprocess.run([SYSTEM_BASH, "run.sh", *arguments], cwd=ROOT, env=environment,
                          capture_output=True, text=True)


def sourced(script_root, environment, body):
    """Source run.sh, replace the expensive steps, then run ``body``."""
    script = f'source "{script_root}/run.sh"\n{body}\n'
    return subprocess.run([SYSTEM_BASH, "-c", script], cwd=script_root, env=environment,
                          capture_output=True, text=True)


def recorded(calls):
    return [json.loads(line) for line in calls.read_text().splitlines()] if calls.exists() else []


def test_help_lists_every_command_with_its_cost(fake_python):
    _, calls, environment = fake_python
    result = front_door(environment)
    assert result.returncode == 0
    for command in ("demo", "review", "doctor", "replay", "witness", "windows-media",
                    "workbench", "dashboard", "all"):
        assert f"\n  {command} " in result.stdout
    assert "@" not in result.stdout  # every time placeholder was replaced by a measurement
    assert not recorded(calls)


def test_unknown_command_is_refused_without_side_effects(fake_python):
    _, calls, environment = fake_python
    assert front_door(environment, "deploy").returncode == 2
    assert not recorded(calls)


def test_replay_isolates_every_campaign_and_forwards_the_selection(fake_python):
    executable, calls, environment = fake_python
    result = sourced(ROOT, environment, f'python_bin() {{ echo "{executable}"; }}\n'
                                        "cmd_replay --campaign 0.web_demo")
    assert result.returncode == 0, result.stderr
    [call] = recorded(calls)
    assert call[0] == "scripts/run_all_orchestrated_campaigns.py"
    assert "--isolate-campaigns" in call
    assert call[-2:] == ["--campaign", "0.web_demo"]


def test_doctor_defaults_to_the_replay_path(fake_python):
    executable, calls, environment = fake_python
    sourced(ROOT, environment, f'python_bin() {{ echo "{executable}"; }}\ncmd_doctor')
    assert recorded(calls) == [["scripts/doctor.py", "--path", "replay"]]


def test_all_does_not_start_docker_work_when_the_preflight_fails(fake_python):
    executable, calls, environment = fake_python
    environment["AUTOSUT_TEST_FAIL"] = "scripts/doctor.py"
    result = sourced(ROOT, environment, f'python_bin() {{ echo "{executable}"; }}\n'
                                        "cmd_review() { return 0; }\ncmd_all")
    assert result.returncode == 1
    scripts = [call[0] for call in recorded(calls)]
    assert "scripts/prove_subdetermination.py" not in scripts
    assert "failed: doctor" in result.stdout


def test_all_reports_success_with_an_empty_failure_list(fake_python):
    executable, calls, environment = fake_python
    result = sourced(ROOT, environment, f'python_bin() {{ echo "{executable}"; }}\n'
                                        "cmd_review() { return 0; }\ncmd_all")
    assert result.returncode == 0, result.stderr
    assert "all passed: demo, review, doctor, witness" in result.stdout
    assert [call[0] for call in recorded(calls)] == [
        "scripts/demo.py", "scripts/doctor.py", "scripts/prove_subdetermination.py"]


def test_review_inside_the_public_package_uses_the_manifest_wrapper(fake_python, tmp_path):
    executable, _, environment = fake_python
    package = tmp_path / "package"
    (package / "autosut").mkdir(parents=True)
    shutil.copy(ROOT / "run.sh", package / "autosut" / "run.sh")
    (package / "ARTIFACT_MANIFEST.md").write_text("")
    (package / "run_review_check.sh").write_text("echo packaged-wrapper\n")
    result = sourced(package / "autosut", environment,
                     f'python_bin() {{ echo "{executable}"; }}\ncmd_review')
    assert result.returncode == 0, result.stderr
    assert "packaged-wrapper" in result.stdout


def test_python_environment_failure_does_not_abort_the_remaining_steps(fake_python):
    executable, calls, environment = fake_python
    # A failing interpreter bootstrap inside one step must not exit the whole run
    # (python_env.sh sets -e; sourcing it in the front door used to leak that).
    result = sourced(ROOT, environment, f'python_bin() {{ return 1; }}\n'
                                        "cmd_review() { return 0; }\ncmd_all")
    assert result.returncode == 1
    assert "failed: demo doctor" in result.stdout
