"""The reviewer runner selects the probe from declared resource requirements."""

import importlib.util
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/run_corpus_resource_qualification.py"
SPEC = importlib.util.spec_from_file_location("run_corpus_resource_qualification", SCRIPT)
runner = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = runner
SPEC.loader.exec_module(runner)


def test_plain_host_uses_base_probe() -> None:
    assert runner.probe_script([{"kind": "platform"}]).name == "probe_corpus_base_host.py"


def test_resource_host_uses_network_probe() -> None:
    assert (
        runner.probe_script(
            [
                {"kind": "platform"},
                {"kind": "network", "acceptable_values": ["controlled-ingress-channel"]},
            ]
        ).name
        == "probe_corpus_network_resources.py"
    )
