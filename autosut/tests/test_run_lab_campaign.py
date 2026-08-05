from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = PROJECT_ROOT / "scripts" / "run_lab_campaign.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("run_lab_campaign", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_success_path_runs_up_execute_collect_and_teardown(monkeypatch: pytest.MonkeyPatch) -> None:
    module = _load_module()
    calls: list[list[str]] = []
    restored = {"value": False}
    cleaned = {"value": False}

    def fake_run(command, cwd=None, check=None, env=None):
        calls.append(list(command))
        return None

    class DummySnapshot:
        def restore(self) -> None:
            restored["value"] = True

    monkeypatch.setattr(module.subprocess, "run", fake_run)
    monkeypatch.setattr(module, "_capture_derived_state", lambda: DummySnapshot())
    monkeypatch.setattr(
        module, "_cleanup_runtime_outputs", lambda: cleaned.__setitem__("value", True)
    )

    exit_code = module.main(["--campaign", "0.c0011", "--provider", "qemu"])

    assert exit_code == 0
    assert restored["value"] is True
    assert cleaned["value"] is True
    assert calls == [
        ["bash", str(module.UP_LAB_SCRIPT), "--campaign", "0.c0011", "--provider", "qemu"],
        [sys.executable, str(module.RUN_CAMPAIGN_SCRIPT), "--campaign", "0.c0011"],
        ["bash", str(module.COLLECT_EVIDENCE_SCRIPT)],
        [sys.executable, str(module.GENERATE_CORPUS_STATE_SCRIPT)],
        ["bash", str(module.DESTROY_LAB_SCRIPT), "--campaign", "0.c0011"],
    ]


def test_keep_lab_skips_teardown(monkeypatch: pytest.MonkeyPatch) -> None:
    module = _load_module()
    calls: list[list[str]] = []

    def fake_run(command, cwd=None, check=None, env=None):
        calls.append(list(command))
        return None

    monkeypatch.setattr(module.subprocess, "run", fake_run)
    monkeypatch.setattr(module, "_capture_derived_state", lambda: type("S", (), {"restore": lambda self: None})())
    monkeypatch.setattr(module, "_cleanup_runtime_outputs", lambda: None)

    exit_code = module.main(["--campaign", "0.c0011", "--keep-lab"])

    assert exit_code == 0
    assert calls[-1] != ["bash", str(module.DESTROY_LAB_SCRIPT), "--campaign", "0.c0011"]
    assert calls[0] == ["bash", str(module.UP_LAB_SCRIPT), "--campaign", "0.c0011"]


def test_teardown_runs_when_campaign_execution_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    module = _load_module()
    calls: list[list[str]] = []

    def fake_run(command, cwd=None, check=None, env=None):
        calls.append(list(command))
        if list(command)[1:] == [str(module.RUN_CAMPAIGN_SCRIPT), "--campaign", "0.c0015"]:
            raise module.subprocess.CalledProcessError(returncode=1, cmd=command)
        return None

    monkeypatch.setattr(module.subprocess, "run", fake_run)
    monkeypatch.setattr(module, "_capture_derived_state", lambda: type("S", (), {"restore": lambda self: None})())
    monkeypatch.setattr(module, "_cleanup_runtime_outputs", lambda: None)
    monkeypatch.setattr(module, "_evidence_available", lambda: True)

    with pytest.raises(module.subprocess.CalledProcessError):
        module.main(["--campaign", "0.c0015"])

    assert calls[0] == ["bash", str(module.UP_LAB_SCRIPT), "--campaign", "0.c0015"]
    assert calls[-1] == ["bash", str(module.DESTROY_LAB_SCRIPT), "--campaign", "0.c0015"]


def test_failure_still_refreshes_evidence_and_corpus_state(monkeypatch: pytest.MonkeyPatch) -> None:
    module = _load_module()
    calls: list[list[str]] = []

    def fake_run(command, cwd=None, check=None, env=None):
        calls.append(list(command))
        if list(command)[1:] == [str(module.RUN_CAMPAIGN_SCRIPT), "--campaign", "0.c0015"]:
            raise module.subprocess.CalledProcessError(returncode=1, cmd=command)
        return None

    monkeypatch.setattr(module.subprocess, "run", fake_run)
    monkeypatch.setattr(module, "_capture_derived_state", lambda: type("S", (), {"restore": lambda self: None})())
    monkeypatch.setattr(module, "_cleanup_runtime_outputs", lambda: None)
    monkeypatch.setattr(module, "_evidence_available", lambda: True)

    with pytest.raises(module.subprocess.CalledProcessError):
        module.main(["--campaign", "0.c0015"])

    assert calls == [
        ["bash", str(module.UP_LAB_SCRIPT), "--campaign", "0.c0015"],
        [sys.executable, str(module.RUN_CAMPAIGN_SCRIPT), "--campaign", "0.c0015"],
        ["bash", str(module.COLLECT_EVIDENCE_SCRIPT)],
        [sys.executable, str(module.GENERATE_CORPUS_STATE_SCRIPT)],
        ["bash", str(module.DESTROY_LAB_SCRIPT), "--campaign", "0.c0015"],
    ]


def test_teardown_runs_when_up_lab_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    module = _load_module()
    calls: list[list[str]] = []

    def fake_run(command, cwd=None, check=None, env=None):
        calls.append(list(command))
        if list(command) == ["bash", str(module.UP_LAB_SCRIPT), "--campaign", "0.c0011"]:
            raise module.subprocess.CalledProcessError(returncode=1, cmd=command)
        return None

    monkeypatch.setattr(module.subprocess, "run", fake_run)
    monkeypatch.setattr(module, "_capture_derived_state", lambda: type("S", (), {"restore": lambda self: None})())
    monkeypatch.setattr(module, "_cleanup_runtime_outputs", lambda: None)

    with pytest.raises(module.subprocess.CalledProcessError):
        module.main(["--campaign", "0.c0011"])

    assert calls == [
        ["bash", str(module.UP_LAB_SCRIPT), "--campaign", "0.c0011"],
        ["bash", str(module.DESTROY_LAB_SCRIPT), "--campaign", "0.c0011"],
    ]


def test_skip_collect_evidence_avoids_post_run_refresh(monkeypatch: pytest.MonkeyPatch) -> None:
    module = _load_module()
    calls: list[list[str]] = []

    def fake_run(command, cwd=None, check=None, env=None):
        calls.append(list(command))
        return None

    monkeypatch.setattr(module.subprocess, "run", fake_run)
    monkeypatch.setattr(module, "_capture_derived_state", lambda: type("S", (), {"restore": lambda self: None})())
    monkeypatch.setattr(module, "_cleanup_runtime_outputs", lambda: None)

    exit_code = module.main(["--campaign", "0.c0011", "--skip-collect-evidence"])

    assert exit_code == 0
    assert calls == [
        ["bash", str(module.UP_LAB_SCRIPT), "--campaign", "0.c0011"],
        [sys.executable, str(module.RUN_CAMPAIGN_SCRIPT), "--campaign", "0.c0011"],
        ["bash", str(module.DESTROY_LAB_SCRIPT), "--campaign", "0.c0011"],
    ]


def test_assume_lab_running_skips_up_lab(monkeypatch: pytest.MonkeyPatch) -> None:
    module = _load_module()
    calls: list[list[str]] = []

    def fake_run(command, cwd=None, check=None, env=None):
        calls.append(list(command))
        return None

    monkeypatch.setattr(module.subprocess, "run", fake_run)
    monkeypatch.setattr(module, "_capture_derived_state", lambda: type("S", (), {"restore": lambda self: None})())
    monkeypatch.setattr(module, "_cleanup_runtime_outputs", lambda: None)

    exit_code = module.main(["--campaign", "0.c0011", "--assume-lab-running"])

    assert exit_code == 0
    assert calls == [
        [sys.executable, str(module.RUN_CAMPAIGN_SCRIPT), "--campaign", "0.c0011"],
        ["bash", str(module.COLLECT_EVIDENCE_SCRIPT)],
        [sys.executable, str(module.GENERATE_CORPUS_STATE_SCRIPT)],
        ["bash", str(module.DESTROY_LAB_SCRIPT), "--campaign", "0.c0011"],
    ]


def test_persist_derived_state_skips_restore_and_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_module()
    calls: list[list[str]] = []
    capture_called = {"value": False}
    cleaned = {"value": False}

    def fake_run(command, cwd=None, check=None, env=None):
        calls.append(list(command))
        return None

    monkeypatch.setattr(module.subprocess, "run", fake_run)
    monkeypatch.setattr(
        module, "_capture_derived_state", lambda: capture_called.__setitem__("value", True)
    )
    monkeypatch.setattr(
        module, "_cleanup_runtime_outputs", lambda: cleaned.__setitem__("value", True)
    )

    exit_code = module.main(["--campaign", "0.c0011", "--persist-derived-state"])

    assert exit_code == 0
    assert capture_called["value"] is False
    assert cleaned["value"] is False
    assert calls == [
        ["bash", str(module.UP_LAB_SCRIPT), "--campaign", "0.c0011"],
        [sys.executable, str(module.RUN_CAMPAIGN_SCRIPT), "--campaign", "0.c0011"],
        ["bash", str(module.COLLECT_EVIDENCE_SCRIPT)],
        [sys.executable, str(module.GENERATE_CORPUS_STATE_SCRIPT)],
        ["bash", str(module.DESTROY_LAB_SCRIPT), "--campaign", "0.c0011"],
    ]
