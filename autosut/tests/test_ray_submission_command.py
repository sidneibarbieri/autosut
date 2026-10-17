from __future__ import annotations

import os
import shlex
import subprocess
import sys
from pathlib import Path


ARTIFACT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ARTIFACT_ROOT / "scripts"))

from orchestrator.executor import _ray_submission_command  # noqa: E402
from orchestrator.injector import _ray_jobs_preflight_command  # noqa: E402


def _run_generated_submission(tmp_path: Path, fake_requests_source: str) -> subprocess.CompletedProcess[str]:
    (tmp_path / "requests.py").write_text(fake_requests_source, encoding="utf-8")
    command = _ray_submission_command("127.0.0.1", "echo ok")
    script = shlex.split(command)[2]
    compile(script, "<ray-submit>", "exec")
    env = {**os.environ, "PYTHONPATH": str(tmp_path)}
    return subprocess.run(
        [sys.executable, "-c", script],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )


def test_ray_submission_fails_on_http_error(tmp_path: Path) -> None:
    completed = _run_generated_submission(
        tmp_path,
        """
class Response:
    status_code = 400
    text = "bad request"
    def raise_for_status(self):
        raise RuntimeError("http 400")
    def json(self):
        return {}

def post(*args, **kwargs):
    return Response()
""",
    )

    assert completed.returncode != 0
    assert "post_status=400" in completed.stdout


def test_ray_submission_waits_for_succeeded_status(tmp_path: Path) -> None:
    completed = _run_generated_submission(
        tmp_path,
        """
class Response:
    def __init__(self, status_code, text, body):
        self.status_code = status_code
        self.text = text
        self._body = body
    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError("http error")
    def json(self):
        return self._body

def post(*args, **kwargs):
    return Response(200, '{"submission_id":"sid1"}', {"submission_id": "sid1"})

def get(*args, **kwargs):
    return Response(200, '{"status":"SUCCEEDED"}', {"status": "SUCCEEDED"})
""",
    )

    assert completed.returncode == 0
    assert "submission_id=sid1" in completed.stdout
    assert "status=200" in completed.stdout


def test_ray_submission_fails_on_failed_terminal_status(tmp_path: Path) -> None:
    completed = _run_generated_submission(
        tmp_path,
        """
class Response:
    def __init__(self, status_code, text, body):
        self.status_code = status_code
        self.text = text
        self._body = body
    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError("http error")
    def json(self):
        return self._body

def post(*args, **kwargs):
    return Response(200, '{"submission_id":"sid1"}', {"submission_id": "sid1"})

def get(*args, **kwargs):
    return Response(200, '{"status":"FAILED"}', {"status": "FAILED"})
""",
    )

    assert completed.returncode != 0
    assert "FAILED" in completed.stdout


def test_ray_submission_allows_declared_surrogate_without_polling(tmp_path: Path) -> None:
    completed = _run_generated_submission(
        tmp_path,
        """
class Response:
    def __init__(self, status_code, text, body):
        self.status_code = status_code
        self.text = text
        self._body = body
    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError("http error")
    def json(self):
        return self._body

def post(*args, **kwargs):
    return Response(200, '{"submission_id":"sid_surrogate"}', {"submission_id": "sid_surrogate"})

def get(*args, **kwargs):
    return Response(404, "not found", {})
""",
    )

    assert completed.returncode == 0
    assert "poll_unavailable=surrogate_or_legacy_endpoint" in completed.stdout


def test_ray_preflight_command_compiles() -> None:
    command = _ray_jobs_preflight_command()
    script = shlex.split(command)[2]
    compile(script, "<ray-preflight>", "exec")
    assert "/api/jobs/" in script
    assert "ray_job_preflight=ok" in script
