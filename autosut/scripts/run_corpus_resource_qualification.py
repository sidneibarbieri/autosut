#!/usr/bin/env python3
"""Reproduce and audit every supported corpus base host and resource witness."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = Path(__file__).resolve().parent
DEFAULT_CORPUS = PROJECT_ROOT / "release/corpus-suts-20261001-enterprise-r3"


def probe_script(requirements: list[dict]) -> Path:
    if any(item["kind"] != "platform" for item in requirements):
        return SCRIPTS / "probe_corpus_network_resources.py"
    return SCRIPTS / "probe_corpus_base_host.py"


def _run(script: Path, arguments: list[str], *, timeout: int) -> None:
    subprocess.run(
        [sys.executable, str(script), *arguments],
        cwd=PROJECT_ROOT,
        check=True,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        timeout=timeout,
    )


def qualify(corpus: Path, output: Path) -> dict:
    if output.exists():
        raise ValueError("qualification output already exists")
    manifest = json.loads((corpus / "manifest.json").read_text())
    records = [item for item in manifest["records"] if item["status"] == "blueprint_generated"]
    if len(records) != manifest["blueprints_generated"]:
        raise ValueError("corpus blueprint count differs from its manifest")
    base_output = output / "base"
    network_output = output / "network"
    base_output.mkdir(parents=True)
    network_output.mkdir()
    for entry in records:
        campaign_id = entry["campaign_id"]
        constraints = json.loads((corpus / campaign_id / "constraints.json").read_text())
        script = probe_script(constraints["requirements"])
        receipt_dir = base_output if script.name == "probe_corpus_base_host.py" else network_output
        _run(
            script,
            [
                "--corpus",
                str(corpus),
                "--campaign",
                campaign_id,
                "--output",
                str(receipt_dir / f"{campaign_id}.json"),
            ],
            timeout=180,
        )
    audit_path = output / "audit.json"
    _run(
        SCRIPTS / "audit_corpus_resource_witnesses.py",
        [
            "--corpus",
            str(corpus),
            "--base-receipts",
            str(base_output),
            "--network-receipts",
            str(network_output),
            "--output",
            str(audit_path),
        ],
        timeout=30,
    )
    return json.loads(audit_path.read_text())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = qualify(args.corpus.resolve(), args.output.resolve())
    return (
        0
        if report["base_hosts_materialized"] + report["resource_witnesses"]
        == report["blueprints_generated"]
        else 1
    )


if __name__ == "__main__":
    raise SystemExit(main())
