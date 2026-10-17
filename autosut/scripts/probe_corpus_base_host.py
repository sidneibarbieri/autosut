#!/usr/bin/env python3
"""Boot and tear down a corpus Linux base host without campaign execution."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import uuid
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from planning.corpus_probe_admission import load_corpus_blueprint  # noqa: E402
from planning.sut_blueprint import BACKEND_RECIPES, SUTBlueprint  # noqa: E402


def _checked_host(corpus: Path, campaign_id: str) -> tuple[SUTBlueprint, str]:
    blueprint, constraints, file_sha256 = load_corpus_blueprint(corpus, campaign_id)
    if len(blueprint.hosts) != 1 or blueprint.hosts[0].platform != "Linux":
        raise ValueError("base-host probe requires one Linux host")
    if blueprint.hosts[0].recipe != BACKEND_RECIPES["Linux"]:
        raise ValueError("base-host probe requires the reviewed Linux recipe")
    if any(item.kind != "platform" for item in constraints.requirements):
        raise ValueError("base-host probe cannot satisfy nonplatform resources")
    return blueprint, file_sha256


def probe(corpus: Path, campaign_id: str, output: Path) -> dict:
    if output.exists():
        raise ValueError("receipt already exists")
    if not campaign_id.startswith("C") or not campaign_id[1:].isdigit():
        raise ValueError("invalid campaign ID")
    blueprint, blueprint_file_sha256 = _checked_host(corpus, campaign_id)
    recipe = blueprint.hosts[0].recipe
    image = subprocess.run(
        ["docker", "image", "inspect", recipe.base_image, "--format", "{{.Id}}"],
        capture_output=True, text=True, check=True, timeout=30,
    ).stdout.strip()
    name = f"autosut-baseprobe-{uuid.uuid4().hex[:12]}"
    command = [
        "docker", "run", "--rm", "--name", name, "--network", "none",
        "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--pids-limit", "128", "--memory", f"{recipe.memory_mb}m",
        "--cpus", str(recipe.cpu_count), recipe.base_image,
        "python3", "-c",
        "import json,platform; routes=open('/proc/net/route').read().splitlines()[1:]; "
        "print(json.dumps({'platform':platform.system(),'python':platform.python_version(),"
        "'default_route':any(line.split()[1]=='00000000' for line in routes)}))",
    ]
    try:
        execution = subprocess.run(command, capture_output=True, text=True, check=False, timeout=90)
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, text=True, check=False, timeout=30)
    residual = subprocess.run(
        ["docker", "ps", "-a", "--filter", f"name=^{name}$", "--format", "{{.Names}}"],
        capture_output=True, text=True, check=True, timeout=30,
    ).stdout.strip()
    observed = json.loads(execution.stdout) if execution.returncode == 0 else None
    passed = (execution.returncode == 0 and observed is not None
              and observed["platform"] == "Linux" and observed["default_route"] is False
              and not residual)
    receipt = {
        "schema_version": "autosut-base-host-probe/v1",
        "campaign_id": campaign_id,
        "blueprint_file_sha256": blueprint_file_sha256,
        "blueprint_content_sha256": blueprint.content_sha256,
        "image_id": image,
        "network_mode": "none",
        "read_only": True,
        "capabilities_dropped": "ALL",
        "probe_exit_code": execution.returncode,
        "observed": observed,
        "teardown_clean": not residual,
        "base_host_materialized": passed,
        "campaign_executed": False,
        "scope": "Base Linux host boot and teardown only; no resources or campaign effects verified.",
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(receipt, indent=2) + "\n")
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", required=True, type=Path)
    parser.add_argument("--campaign", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    receipt = probe(args.corpus.resolve(), args.campaign, args.output.resolve())
    print(json.dumps({key: receipt[key] for key in ("campaign_id", "base_host_materialized", "teardown_clean")}))
    return 0 if receipt["base_host_materialized"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
