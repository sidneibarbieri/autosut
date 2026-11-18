"""The execution command must fail when its witness is not executable."""

import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import prove_subdetermination as proof_cli


@pytest.mark.parametrize(
    "execute,executable,expected_exit",
    [(False, False, 0), (True, False, 1), (True, True, 0)],
)
def test_exit_reflects_requested_execution(
    monkeypatch, capsys, execute, executable, expected_exit
):
    proof = SimpleNamespace(
        executable=executable,
        model_dump=lambda **kwargs: {"executable": executable},
    )
    monkeypatch.setattr(
        proof_cli.subdetermination, "prove_subdetermination",
        lambda *args, **kwargs: proof,
    )
    arguments = ["prove_subdetermination.py", "0.cve_2021_41773"]
    if execute:
        arguments.append("--execute")
    monkeypatch.setattr(sys, "argv", arguments)

    assert proof_cli.main() == expected_exit
    assert json.loads(capsys.readouterr().out) == {"executable": executable}
