from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODULE_PATH = PROJECT_ROOT / "scripts" / "generate_corpus_state.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("sticks_generate_corpus_state", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_missing_release_evidence_directory_returns_no_summary(tmp_path: Path) -> None:
    module = _load_module()
    module.EVIDENCE_DIR = tmp_path / "release" / "evidence"
    module.DASHBOARD_EVIDENCE_DIR = tmp_path / "release" / "dashboard" / "data" / "evidence"

    assert module.EVIDENCE_DIR.exists() is False
    assert module.DASHBOARD_EVIDENCE_DIR.exists() is False
    assert module.evidence_dirs_for_campaign("0.shadowray") == []
    assert module.latest_summary("0.shadowray") is None
