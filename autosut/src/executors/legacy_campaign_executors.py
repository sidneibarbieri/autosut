#!/usr/bin/env python3
"""Executors for legacy campaign techniques being restored into STICKS."""

from __future__ import annotations

import json
import socket
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import List, Tuple

from .executor_registry import (
    ExecutionFidelity,
    ExecutionMode,
    ExecutorMetadata,
    register_executor,
)

ARTIFACTS_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "artifacts"


def _reserve_local_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@register_executor(
    technique_id="T1584.001",
    metadata=ExecutorMetadata(
        technique_id="T1584.001",
        technique_name="Compromise Infrastructure: Domains",
        execution_mode=ExecutionMode.NAIVE_SIMULATED,
        produces=["infrastructure:compromised_domain"],
        requires=[],
        safe_simulation=True,
        cleanup_supported=True,
        description="Create a compromised-domain manifest for a watering-hole scenario",
        platform="any",
        execution_fidelity=ExecutionFidelity.INSPIRED,
        fidelity_justification=(
            "T1584.001 involves compromising an existing domain. In this execution: "
            "(1) domain takeover is represented through a structured manifest; "
            "(2) no external registrar or DNS provider is modified; "
            "(3) the compromised-infrastructure planning step is preserved."
        ),
        original_platform="any",
        requires_privilege="user",
    ),
)
def execute_t1584_001_simulated(
    campaign_id: str,
    sut_profile_id: str,
    **kwargs,
) -> Tuple[bool, str, str, List[str]]:
    """Create a compromised-domain manifest."""
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    manifest = ARTIFACTS_DIR / f"{campaign_id}_compromised_domain.json"
    payload = {
        "campaign_id": campaign_id,
        "domain": "oldsub.legitshipping.co.il",
        "compromise_mode": "controlled_subdomain_takeover",
        "timestamp": datetime.now().isoformat(),
        "notes": "Lab-safe representation of a compromised legitimate shipping domain.",
    }
    manifest.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return True, f"Compromised-domain manifest created at {manifest}", "", [str(manifest)]


@register_executor(
    technique_id="T1608.002",
    metadata=ExecutorMetadata(
        technique_id="T1608.002",
        technique_name="Stage Capabilities: Upload Tool",
        execution_mode=ExecutionMode.REAL_CONTROLLED,
        produces=["resources:tool_uploaded"],
        requires=["resources:staging_directory"],
        safe_simulation=True,
        cleanup_supported=True,
        description="Stage a benign tool artifact for later transfer",
        platform="linux",
        execution_fidelity=ExecutionFidelity.ADAPTED,
        fidelity_justification=(
            "T1608.002 involves staging tools on attacker-controlled infrastructure. "
            "In this execution: (1) a benign tool artifact is created; "
            "(2) no harmful capability is packaged; "
            "(3) the staging behavior is preserved."
        ),
        original_platform="any",
        requires_privilege="user",
    ),
)
def execute_t1608_002_real(
    campaign_id: str,
    sut_profile_id: str,
    **kwargs,
) -> Tuple[bool, str, str, List[str]]:
    """Stage a benign tool artifact."""
    staging_dir = ARTIFACTS_DIR / "staging"
    staging_dir.mkdir(parents=True, exist_ok=True)
    tool_path = staging_dir / f"{campaign_id}_tool.sh"
    tool_path.write_text(
        "#!/bin/sh\n"
        "echo 'STICKS benign staged tool'\n",
        encoding="utf-8",
    )
    tool_path.chmod(0o755)
    return True, f"Benign tool staged at {tool_path}", "", [str(tool_path)]


@register_executor(
    technique_id="T1608.004",
    metadata=ExecutorMetadata(
        technique_id="T1608.004",
        technique_name="Stage Capabilities: Drive-by Target",
        execution_mode=ExecutionMode.REAL_CONTROLLED,
        produces=["watering_hole:staged"],
        requires=["resources:staging_directory"],
        safe_simulation=True,
        cleanup_supported=True,
        description="Stage a benign watering-hole page and script",
        platform="linux",
        execution_fidelity=ExecutionFidelity.ADAPTED,
        fidelity_justification=(
            "T1608.004 involves staging drive-by content. In this execution: "
            "(1) a benign landing page and client-side script are created; "
            "(2) no browser exploit is delivered; "
            "(3) the watering-hole staging behavior is preserved."
        ),
        original_platform="any",
        requires_privilege="user",
    ),
)
def execute_t1608_004_real(
    campaign_id: str,
    sut_profile_id: str,
    **kwargs,
) -> Tuple[bool, str, str, List[str]]:
    """Stage a benign watering-hole page and client-side script."""
    watering_hole_dir = ARTIFACTS_DIR / f"{campaign_id}_watering_hole"
    watering_hole_dir.mkdir(parents=True, exist_ok=True)
    index_path = watering_hole_dir / "index.html"
    script_path = watering_hole_dir / "exploit.js"
    index_path.write_text(
        "<html><body><h1>Israeli Shipping Login</h1><script src=\"/exploit.js\"></script></body></html>\n",
        encoding="utf-8",
    )
    script_path.write_text(
        "console.log('STICKS benign drive-by profile script');\n",
        encoding="utf-8",
    )
    return (
        True,
        f"Watering-hole content staged at {watering_hole_dir}",
        "",
        [str(index_path), str(script_path)],
    )


@register_executor(
    technique_id="T1189",
    metadata=ExecutorMetadata(
        technique_id="T1189",
        technique_name="Drive-by Compromise",
        execution_mode=ExecutionMode.REAL_CONTROLLED,
        produces=["access:initial", "watering_hole:visited"],
        requires=["network:http_available"],
        safe_simulation=True,
        cleanup_supported=True,
        description="Fetch a staged watering-hole page and client-side script",
        platform="linux",
        execution_fidelity=ExecutionFidelity.ADAPTED,
        fidelity_justification=(
            "T1189 involves user exposure to a malicious website. In this execution: "
            "(1) a live HTTP server hosts a benign watering-hole page; "
            "(2) the page and staged script are fetched over HTTP; "
            "(3) no exploit or malicious payload is delivered."
        ),
        original_platform="any",
        requires_privilege="user",
    ),
)
def execute_t1189_real(
    campaign_id: str,
    sut_profile_id: str,
    **kwargs,
) -> Tuple[bool, str, str, List[str]]:
    """Fetch a staged watering-hole page and script over HTTP."""
    watering_hole_dir = ARTIFACTS_DIR / f"{campaign_id}_watering_hole"
    if not watering_hole_dir.exists():
        execute_t1608_004_real(campaign_id, sut_profile_id, **kwargs)

    port = _reserve_local_port()
    visit_log = ARTIFACTS_DIR / f"{campaign_id}_drive_by_visit.log"
    server = subprocess.Popen(
        ["python3", "-m", "http.server", str(port), "--bind", "127.0.0.1"],
        cwd=watering_hole_dir,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        last_error = None
        for _ in range(10):
            try:
                index_result = subprocess.run(
                    ["curl", "-fsS", f"http://127.0.0.1:{port}/index.html"],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=True,
                )
                script_result = subprocess.run(
                    ["curl", "-fsS", f"http://127.0.0.1:{port}/exploit.js"],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=True,
                )
                last_error = None
                break
            except subprocess.CalledProcessError as exc:
                last_error = exc
                time.sleep(0.2)
        if last_error is not None:
            raise last_error
    finally:
        server.terminate()
        server.wait(timeout=10)

    visit_log.write_text(
        "=== INDEX ===\n"
        f"{index_result.stdout}\n"
        "=== SCRIPT ===\n"
        f"{script_result.stdout}\n",
        encoding="utf-8",
    )
    return (
        True,
        f"Visited staged watering-hole content via http://127.0.0.1:{port}/index.html",
        "",
        [str(visit_log)],
    )
