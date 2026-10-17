"""A persisted uncleared cell blocks subsequent collection and resume."""

import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest


def collector():
    path = Path(__file__).resolve().parents[1] / "scripts" / "collect_operational_ledger.py"
    spec = importlib.util.spec_from_file_location("cleanup_gate_collector", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("status", ["completed", "failed", "timed_out", "interrupted"])
def test_unclean_terminal_cell_blocks_resume(status):
    module = collector()
    cell = SimpleNamespace(
        status=module.CellStatus(status), clean_teardown=False, environment_id="fixture", seed=1
    )
    with pytest.raises(RuntimeError, match="verified cleanup"):
        module.require_clean_previous_cells(SimpleNamespace(cells=(cell,)))


def test_clean_cell_allows_next_planned_cell():
    module = collector()
    cells = (
        SimpleNamespace(status=module.CellStatus.COMPLETED, clean_teardown=True),
        SimpleNamespace(status=module.CellStatus.PLANNED, clean_teardown=False),
    )
    module.require_clean_previous_cells(SimpleNamespace(cells=cells))
