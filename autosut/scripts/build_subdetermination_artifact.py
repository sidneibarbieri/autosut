#!/usr/bin/env python3
"""Generate the curated subdetermination proof artifact.

Writes release/subdetermination_proof.json with four proofs:
  - 0.cve_2021_41773 : executable witness (runs the real CVE when Docker is
    available, so `executable` reflects a live run).
  - 0.pivot_demo     : coincident witness (the informative free-region
    substitution OpenSSH<->Dropbear is itself executed: both realizations run
    the same real, contained SSH pivot end to end when Docker is available).
  - 0.web_demo       : coincident witness in a second service class (edge HTTP:
    Apache<->Nginx both run the same contained HTTP Basic Auth brute-force and
    exfiltration chain end to end when Docker is available).
  - 0.apt41_dust     : structural witness (large free region, material service
    substitution; never claimed to execute).

The reviewer dashboard and the release gate read this file; neither recomputes
the proof. The script is intentionally deterministic and self-contained.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from orchestrator import subdetermination  # noqa: E402

OUTPUT = PROJECT_ROOT / "release" / "subdetermination_proof.json"


def docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    return subprocess.run(["docker", "info"],
                          capture_output=True).returncode == 0


def build_artifact(execute: bool) -> dict:
    """Assemble the three-campaign proof artifact. The executable and coincident
    witnesses run only when `execute` (Docker available); the structural witness
    never executes."""
    cve = subdetermination.prove_subdetermination(
        "0.cve_2021_41773", n_variants=2, execute=execute)
    pivot = subdetermination.prove_subdetermination(
        "0.pivot_demo", n_variants=1, execute=execute)
    web = subdetermination.prove_subdetermination(
        "0.web_demo", n_variants=1, execute=execute)
    apt41 = subdetermination.prove_subdetermination(
        "0.apt41_dust", n_variants=3, execute=False)
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "proofs": {
            cve.campaign_id: cve.model_dump(mode="json"),
            pivot.campaign_id: pivot.model_dump(mode="json"),
            web.campaign_id: web.model_dump(mode="json"),
            apt41.campaign_id: apt41.model_dump(mode="json"),
        },
    }


def main() -> int:
    execute = docker_available()
    if not execute:
        print("[subdet] docker unavailable — executable + coincident witnesses "
              "will be structural only", file=sys.stderr)
    artifact = build_artifact(execute=execute)
    OUTPUT.write_text(json.dumps(artifact, indent=2), encoding="utf-8")
    print(f"[subdet] wrote {OUTPUT}")
    for cid in ("0.cve_2021_41773", "0.pivot_demo", "0.web_demo", "0.apt41_dust"):
        p = artifact["proofs"][cid]
        print(f"[subdet] {cid} executable={p['executable']} "
              f"(invariant {p['invariant_count']}, free {p['free_count']}, "
              f"variants {len(p['variants'])})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
