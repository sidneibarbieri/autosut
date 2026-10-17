from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


ARTIFACT_ROOT = Path(__file__).resolve().parents[1]


def _salesforce_snapshot() -> dict:
    script = """
import json
import sys
from pathlib import Path

artifact_root = Path.cwd()
sys.path.insert(0, str(artifact_root / "src"))

from executors.registry_initializer import initialize_registry
from executors.executor_registry import registry
from loaders.campaign_loader import validate_campaign_sut_pair

initialize_registry(force=True)

techniques = [
    "T1078.003",
    "T1033",
    "T1056.001",
    "T1113",
    "T1119",
    "T1020",
    "T1567.002",
    "T1486",
]

snapshot = {
    "pair_validation": validate_campaign_sut_pair("0.salesforce_data_exfiltration"),
    "techniques": {},
}

for technique_id in techniques:
    executor = registry.get_executor(technique_id)
    metadata = registry.get_metadata(technique_id)
    snapshot["techniques"][technique_id] = {
        "executor_module": executor.__module__ if executor else None,
        "executor_name": executor.__name__ if executor else None,
        "requires": list(metadata.requires) if metadata else [],
        "produces": list(metadata.produces) if metadata else [],
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


def test_salesforce_profile_is_pair_valid() -> None:
    snapshot = _salesforce_snapshot()
    assert snapshot["pair_validation"] is None


def test_salesforce_cluster_binds_to_campaign_expansion_module() -> None:
    snapshot = _salesforce_snapshot()
    for technique_id, binding in snapshot["techniques"].items():
        assert binding["executor_module"] == "executors.campaign_expansion_executors"
        assert binding["executor_name"] is not None


def test_salesforce_access_chain_is_explicit() -> None:
    snapshot = _salesforce_snapshot()
    assert "access:initial" in snapshot["techniques"]["T1078.003"]["produces"]


def test_salesforce_collection_chain_is_explicit() -> None:
    snapshot = _salesforce_snapshot()
    assert "collection:archive" in snapshot["techniques"]["T1119"]["produces"]
    assert "collection:archive" in snapshot["techniques"]["T1020"]["requires"]
    assert "collection:archive" in snapshot["techniques"]["T1567.002"]["requires"]
    assert "collection:archive" in snapshot["techniques"]["T1486"]["requires"]


def _midnighteclipse_snapshot() -> dict:
    script = """
import json
import sys
from pathlib import Path

artifact_root = Path.cwd()
sys.path.insert(0, str(artifact_root / "src"))

from executors.registry_initializer import initialize_registry
from executors.executor_registry import registry
from loaders.campaign_loader import validate_campaign_sut_pair

initialize_registry(force=True)

techniques = [
    "T1007",
    "T1055",
    "T1564.001",
    "T1027",
    "T1491",
]

snapshot = {
    "pair_validation": validate_campaign_sut_pair("0.operation_midnighteclipse"),
    "techniques": {},
}

for technique_id in techniques:
    executor = registry.get_executor(technique_id)
    metadata = registry.get_metadata(technique_id)
    snapshot["techniques"][technique_id] = {
        "executor_module": executor.__module__ if executor else None,
        "executor_name": executor.__name__ if executor else None,
        "execution_mode": metadata.execution_mode.value if metadata else None,
        "execution_fidelity": metadata.execution_fidelity.value if metadata else None,
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


def test_midnighteclipse_profile_is_pair_valid() -> None:
    snapshot = _midnighteclipse_snapshot()
    assert snapshot["pair_validation"] is None


def test_midnighteclipse_cluster_binds_to_campaign_expansion_module() -> None:
    snapshot = _midnighteclipse_snapshot()
    for technique_id, binding in snapshot["techniques"].items():
        assert binding["executor_module"] == "executors.campaign_expansion_executors"
        assert binding["executor_name"] is not None


def test_midnighteclipse_process_injection_is_marked_inspired() -> None:
    snapshot = _midnighteclipse_snapshot()
    assert snapshot["techniques"]["T1055"]["execution_mode"] == "naive_simulated"
    assert snapshot["techniques"]["T1055"]["execution_fidelity"] == "inspired"
