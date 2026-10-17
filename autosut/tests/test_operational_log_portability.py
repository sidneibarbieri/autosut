from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))


def _module():
    spec = importlib.util.spec_from_file_location(
        "operational_collector_for_log_test",
        PROJECT_ROOT / "scripts/collect_operational_ledger.py",
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_operational_log_replaces_checkout_prefix_only() -> None:
    module = _module()
    original = f"{PROJECT_ROOT}/.venv/bin/python {PROJECT_ROOT}/scripts/runner.py\nresult"

    portable = module.portable_log_text(original)

    assert str(PROJECT_ROOT) not in portable
    assert portable == "./.venv/bin/python ./scripts/runner.py\nresult"
