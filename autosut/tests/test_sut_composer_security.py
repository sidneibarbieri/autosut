from __future__ import annotations

import json
import getpass
import subprocess
import sys
from pathlib import Path
import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from orchestrator.models import Credential, StagedArtifact, SUTComposition  # noqa: E402
from orchestrator.environment_base import CommandResult  # noqa: E402
from orchestrator.sut_composer import _apply_artifact, apply_composition  # noqa: E402


class ShellHost:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str | None]] = []

    def run_shell(self, command: str, log_name=None, timeout=600):
        self.calls.append((command, log_name))
        result = subprocess.run(["sh", "-c", command], capture_output=True, text=True)
        return CommandResult(command, result.returncode, result.stdout, result.stderr)


class RecordingHost:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str | None]] = []

    def run_shell(self, command: str, log_name=None, timeout=600):
        self.calls.append((command, log_name))
        return CommandResult(command, 0, "", "")


def test_artifact_content_cannot_close_a_heredoc_or_run_shell(tmp_path):
    output = tmp_path / "artifact.txt"
    marker = tmp_path / "injected"
    payload = f"AUTOSUT_ART_EOF\ntouch {marker}\nAUTOSUT_ART_EOF"
    host = ShellHost()
    artifact = StagedArtifact(
        path=str(output), content_text=payload,
        owner=getpass.getuser(), mode="0644",
    )
    _apply_artifact(host, artifact, tmp_path, 0)
    assert output.read_text() == payload
    assert not marker.exists()
    assert host.calls[0][1] is None
    assert payload not in (tmp_path / "sut/artifact_00.log").read_text()


def test_composition_manifest_excludes_secret_and_artifact_content(tmp_path):
    host = RecordingHost()
    composition = SUTComposition(
        credentials=[Credential(kind="password", user="labuser", secret="sensitive-value")],
        artifacts=[StagedArtifact(path="/tmp/artifact", content_text="private-content")],
    )
    apply_composition(host, "lab", composition, tmp_path)
    manifest = (tmp_path / "sut/composition_lab.json").read_text()
    assert "sensitive-value" not in manifest
    assert "private-content" not in manifest
    assert "sensitive-value" not in json.dumps(
        [path.read_text() for path in (tmp_path / "sut").glob("*.log")]
    )
    assert all(log_name is None for _, log_name in host.calls)


def test_rejects_multiline_password_before_any_host_mutation(tmp_path):
    host = RecordingHost()
    composition = SUTComposition(
        artifacts=[StagedArtifact(path="/tmp/safe", content_text="data")],
        credentials=[Credential(kind="password", user="labuser", secret="pass\nother:pass")],
    )
    with pytest.raises(ValueError, match="multiline"):
        apply_composition(host, "lab", composition, tmp_path)
    assert not host.calls
