from __future__ import annotations

import subprocess
import pytest
import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_artifact_run_help_has_no_docker_side_effects() -> None:
    result = subprocess.run(
        ["bash", str(PROJECT_ROOT / "artifact" / "run.sh"), "--help"],
        cwd=PROJECT_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )

    assert "without contacting Docker" in result.stdout
    assert "Docker daemon:" not in result.stdout
    assert "pulling target image" not in result.stdout


@pytest.mark.parametrize('locked', [False, True])
def test_replay_wrapper_routes_optional_lock_on_system_bash(tmp_path, locked) -> None:
    import os
    import shutil
    project = tmp_path / 'project'
    (project / 'artifact').mkdir(parents=True)
    (project / 'scripts').mkdir()
    shutil.copy2(PROJECT_ROOT / 'artifact/run.sh', project / 'artifact/run.sh')
    calls = tmp_path / 'calls.log'
    launcher = tmp_path / 'python-stub'
    launcher.write_text(
        '#!/usr/bin/env python3\nimport json,os,sys\n'
        'with open(os.environ["CALLS_FILE"],"a") as output: output.write(json.dumps(sys.argv[1:])+"\\n")\n'
    )
    launcher.chmod(0o755)
    (project / 'scripts/python_env.sh').write_text(
        'autosut_resolve_python() { printf "%s" "$PYTHON_STUB"; }\n'
    )
    executables = tmp_path / 'bin'
    executables.mkdir()
    docker = executables / 'docker'
    docker.write_text('#!/bin/bash\nif [[ "$1" == info ]]; then echo test-daemon; fi\nexit 0\n')
    docker.chmod(0o755)
    env = dict(os.environ, PATH=str(executables) + ':' + os.environ['PATH'],
               CALLS_FILE=str(calls), PYTHON_STUB=str(launcher))
    env.pop('AUTOSUT_DOCKER_IMAGE_LOCK', None)
    lock_path = tmp_path / 'image lock.json'
    lock_path.write_text('{}')
    command = ['/bin/bash', str(project / 'artifact/run.sh')]
    if locked:
        command += ['--image-lock', lock_path.name]
    result = subprocess.run(command, env=env,
                            cwd=tmp_path, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    recorded = [json.loads(line) for line in calls.read_text().splitlines()]
    extra = ['--docker-image-lock', str(lock_path)] if locked else []
    assert ['scripts/run_orchestrated_campaign.py', '0.c0017', *extra] in recorded
    assert ['scripts/run_orchestrated_campaign.py', '0.shadowray', '--fidelity', 'surrogate', *extra] in recorded
