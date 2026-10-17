from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


ARTIFACT_ROOT = Path(__file__).resolve().parents[1]


def _snapshot_registry_bindings() -> dict:
    script = """
import json
import sys
from pathlib import Path

artifact_root = Path.cwd()
sys.path.insert(0, str(artifact_root / "src"))

from executors.registry_initializer import initialize_registry
from executors.executor_registry import registry

initialize_registry(force=True)

snapshot = {}
for technique_id in ("T1016", "T1190", "T1068"):
    executor = registry.get_executor(technique_id)
    metadata = registry.get_metadata(technique_id)
    snapshot[technique_id] = {
        "executor_module": executor.__module__ if executor else None,
        "executor_name": executor.__name__ if executor else None,
        "produces": list(metadata.produces) if metadata else [],
        "requires": list(metadata.requires) if metadata else [],
    }

print(json.dumps(snapshot))
"""
    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=ARTIFACT_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(completed.stdout)


def test_t1016_binding_prefers_shadowray_fixed_executor() -> None:
    snapshot = _snapshot_registry_bindings()
    t1016 = snapshot["T1016"]
    assert t1016["executor_module"] == "executors.shadowray_fixed_executors"
    assert t1016["executor_name"] == "execute_t1016_shadowray_fixed"


def test_t1190_metadata_exposes_initial_access_capability() -> None:
    snapshot = _snapshot_registry_bindings()
    assert "access:initial" in snapshot["T1190"]["produces"]


def test_t1068_metadata_requires_initial_access_capability() -> None:
    snapshot = _snapshot_registry_bindings()
    assert "access:initial" in snapshot["T1068"]["requires"]
