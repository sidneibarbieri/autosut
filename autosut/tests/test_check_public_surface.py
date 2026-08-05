from __future__ import annotations

from pathlib import Path

from scripts.check_public_surface import is_runtime_state


def test_runtime_state_detection_is_recursive() -> None:
    assert is_runtime_state(Path(".venv/bin/activate"))
    assert is_runtime_state(Path("lab/target/.vagrant/machines/default/id"))
    assert is_runtime_state(Path("src/__pycache__/module.cpython-312.pyc"))
    assert is_runtime_state(Path("results/.coverage"))


def test_release_evidence_is_not_runtime_state() -> None:
    assert not is_runtime_state(
        Path("release/evidence/run/sut/containment.log")
    )
