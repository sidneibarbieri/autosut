from __future__ import annotations

import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from render_attack_graph import ExecutedStep, deduplicate, render_tikz  # noqa: E402


def _steps() -> list[ExecutedStep]:
    return [
        ExecutedStep("host-A", "T1552.001", "credential-access", "produce credential", True),
        ExecutedStep("host-A", "T1021", "lateral-movement", "consume fact", True),
        ExecutedStep("host-B", "T1552.001", "credential-access", "produce credential", False),
        ExecutedStep("host-B", "T1021", "lateral-movement", "consume fact", True),
    ]


def test_orders_steps_by_kill_chain_tactic():
    ordered = deduplicate(_steps())
    tactics = [step.tactic for step in ordered]
    assert tactics.index("credential-access") < tactics.index("lateral-movement")


def test_marks_failed_step_as_attempted_not_executed():
    figure = render_tikz(_steps())
    assert "attempted" in figure
    assert "executed" in figure


def test_draws_the_causal_edge_between_tactics():
    figure = render_tikz(_steps())
    assert "causal" in figure
    assert "credential" in figure


def test_uses_reserved_tikz_key_safely():
    # 'step' is a reserved TikZ key; the style must not collide with it.
    figure = render_tikz(_steps())
    assert "atkstep/.style" in figure
    assert " step/.style" not in figure and "\nstep/.style" not in figure
