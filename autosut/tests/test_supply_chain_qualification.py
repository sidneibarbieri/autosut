"""Qualification failures must remain visible and precede provisioning."""

import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from planning import supply_chain_qualification as qualification


def test_command_failure_preserves_exit_and_diagnostic(tmp_path: Path) -> None:
    log = tmp_path / "operation.log"
    with pytest.raises(subprocess.CalledProcessError) as failure:
        qualification._command(
            [sys.executable, "-c", "import sys; print('operation rejected'); sys.exit(7)"], log
        )
    assert failure.value.returncode == 7
    assert "operation rejected" in log.read_text()


def test_unknown_sequence_is_rejected_before_evidence_or_provisioning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        qualification,
        "load_procedural_plan",
        lambda path: SimpleNamespace(steps=[SimpleNamespace(technique_id="T1105")]),
    )
    evidence = tmp_path / "evidence"
    with pytest.raises(ValueError, match="complete source sequence"):
        qualification.qualify_supply_chain(tmp_path / "source.json", evidence, "unused-image")
    assert not evidence.exists()


def test_existing_evidence_is_never_overwritten(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        qualification,
        "load_procedural_plan",
        lambda path: SimpleNamespace(
            steps=[
                SimpleNamespace(technique_id=identifier)
                for identifier in qualification.TECHNIQUE_SEQUENCE
            ]
        ),
    )
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    marker = evidence / "preserved.txt"
    marker.write_text("preserved failure")
    with pytest.raises(ValueError, match="must be new"):
        qualification.qualify_supply_chain(tmp_path / "source.json", evidence, "unused-image")
    assert marker.read_text() == "preserved failure"
