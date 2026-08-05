"""Dispatch a single Caldera ability against a per-campaign sandcat agent.

This module is the integration point between the orchestrator and the running
MITRE Caldera C2. For each technique whose campaign declares
``expected_mode: caldera_driven``, the executor calls
:func:`dispatch_via_caldera`, which:

1. Ensures a sandcat agent is registered for this SUT container (installing
   and starting it on first call).
2. Creates a one-off Caldera adversary containing just the matching ART
   ability.
3. Starts an operation with the atomic planner against the agent's group.
4. Waits for the operation to finish, fetches the per-link report, and
   captures stdout/stderr/exit_code under ``run_dir/caldera/``.

The returned :class:`CalderaLinkResult` is consumed by the executor to build
a :class:`TechniqueOutcome` with ``executed_mode=caldera_driven`` and the
operation/link/ability IDs threaded into the manifest for auditability.
"""

from __future__ import annotations

import subprocess
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from . import caldera_client


SANDCAT_PATH_IN_CONTAINER = "/usr/local/bin/sandcat"
SANDCAT_LOG_IN_CONTAINER = "/tmp/sandcat.log"
DEFAULT_GROUP = "red"

# The dispatch path uses one fresh paw per Caldera operation. Reusing a sandcat
# across one-off operations is faster, but Caldera can leave stale operation
# state attached to an otherwise registered agent. Fresh paws make campaign
# replay slower and much more stable for external reviewers.
_paw_by_container: dict[str, str] = {}


@dataclass
class CalderaLinkResult:
    """Outcome of dispatching one ability via Caldera."""

    ok: bool
    technique_id: str
    ability_id: str
    ability_name: str
    operation_id: Optional[str] = None
    link_id: Optional[str] = None
    status: Optional[int] = None  # Caldera status: 0 = success
    stdout: str = ""
    stderr: str = ""
    exit_code: Optional[str] = None
    paw: Optional[str] = None
    evidence_files: list[str] = field(default_factory=list)
    error: Optional[str] = None


def reset_agent_cache() -> None:
    """Forget per-container sandcat paws after campaign teardown or C2 reset."""
    _paw_by_container.clear()


def _reset_container_agent(container: str) -> None:
    """Stop any sandcat in ``container`` and allocate a fresh paw next time."""
    _paw_by_container.pop(container, None)
    subprocess.run(
        [
            "docker", "exec", container, "bash", "-lc",
            f"pkill -f {SANDCAT_PATH_IN_CONTAINER} 2>/dev/null || true; "
            f"rm -f {SANDCAT_LOG_IN_CONTAINER}",
        ],
        capture_output=True, text=True, check=False,
    )


def _find_report_link(report: dict, ability_id: str,
                      paw: str) -> Optional[dict]:
    """Return the report link for ``ability_id``, preferring the run's paw."""
    fallback: Optional[dict] = None
    for paw_in_report, info in report.get("steps", {}).items():
        for cand in info.get("steps", []):
            if cand.get("ability_id") != ability_id:
                continue
            if paw_in_report == paw:
                return cand
            if fallback is None:
                fallback = cand
    return fallback


def _wait_report_link_or_finished(op_id: str, ability_id: str, paw: str,
                                  max_seconds: int,
                                  poll_seconds: float = 3.0
                                  ) -> tuple[Optional[dict], dict, Optional[dict]]:
    """Poll Caldera until the target link is observable or the budget expires.

    Caldera 5.x can expose completed per-link evidence in the operation report
    while the operation endpoint still says ``state=running``. Reviewer
    auditability depends on the per-link stdout/stderr, not on that stale state
    bit, so the dispatch path accepts a completed report link as the terminal
    condition.
    """
    deadline = time.monotonic() + max_seconds
    last_op: Optional[dict] = None
    last_report: dict = {}
    last_link: Optional[dict] = None
    while time.monotonic() < deadline:
        last_op = caldera_client.get_operation(op_id)
        report = caldera_client.get_operation_report(op_id) or {}
        if report:
            last_report = report
            last_link = _find_report_link(report, ability_id, paw)
            # Caldera uses -3 for a link that has been delegated but has not
            # yet returned agent output. Treating it as terminal races the
            # sandcat and can kill the agent before it submits stdout/stderr.
            if (last_link is not None
                    and last_link.get("status") is not None
                    and last_link.get("status") != -3):
                return last_op, last_report, last_link
            if report.get("finish"):
                return last_op, last_report, last_link
        if last_op is None or last_op.get("state") == "finished":
            return last_op, last_report, last_link
        time.sleep(poll_seconds)
    last_op = caldera_client.get_operation(op_id)
    last_report = caldera_client.get_operation_report(op_id) or last_report
    last_link = _find_report_link(last_report, ability_id, paw)
    return last_op, last_report, last_link


def _container_arch_for_sandcat(container: str) -> str:
    """Return the Sandcat architecture that matches the target container.

    Docker Desktop on Apple Silicon often runs linux/amd64 images through
    emulation. Choosing the host architecture in that case asks Caldera for a
    linux/arm64 sandcat even though the SUT is x86_64, which forces a fragile
    just-in-time build inside Caldera. Inspecting the SUT keeps the C2 path
    aligned with the executable target.
    """
    proc = subprocess.run(
        ["docker", "exec", container, "uname", "-m"],
        capture_output=True, text=True, check=False, timeout=5,
    )
    machine = (proc.stdout.strip() if proc.returncode == 0 else "").lower()
    if machine in ("aarch64", "arm64"):
        return "arm64"
    return "amd64"


def _agent_paw(container: str) -> str:
    paw = _paw_by_container.get(container)
    if paw is None:
        paw = f"autosut{uuid.uuid4().hex[:8]}"
        _paw_by_container[container] = paw
    return paw


def _container_has_sandcat(container: str) -> bool:
    proc = subprocess.run(
        ["docker", "exec", container, "test", "-x", SANDCAT_PATH_IN_CONTAINER],
        capture_output=True, text=True, check=False,
    )
    return proc.returncode == 0


def _copy_cached_sandcat(container: str, arch: str) -> bool:
    """Install Caldera's prebuilt sandcat payload without triggering Go builds."""
    if arch != "amd64":
        return False
    proc = subprocess.run(
        [
            "docker", "cp",
            f"{caldera_client.CALDERA_CONTAINER}:"
            "/usr/src/app/plugins/sandcat/payloads/sandcat.go-linux",
            f"{container}:{SANDCAT_PATH_IN_CONTAINER}",
        ],
        capture_output=True, text=True, check=False,
    )
    if proc.returncode != 0:
        return False
    chmod = subprocess.run(
        ["docker", "exec", container, "chmod", "+x", SANDCAT_PATH_IN_CONTAINER],
        capture_output=True, text=True, check=False,
    )
    return chmod.returncode == 0


def _install_sandcat(container: str) -> bool:
    arch = _container_arch_for_sandcat(container)
    if _copy_cached_sandcat(container, arch):
        return True
    binary = caldera_client.download_sandcat(platform="linux", architecture=arch)
    if not binary:
        return False
    tmp = Path(f"/tmp/sandcat_{container}.bin")
    tmp.write_bytes(binary)
    cp = subprocess.run(
        ["docker", "cp", str(tmp), f"{container}:{SANDCAT_PATH_IN_CONTAINER}"],
        capture_output=True, text=True, check=False,
    )
    tmp.unlink(missing_ok=True)
    if cp.returncode != 0:
        return False
    chmod = subprocess.run(
        ["docker", "exec", container, "chmod", "+x", SANDCAT_PATH_IN_CONTAINER],
        capture_output=True, text=True, check=False,
    )
    return chmod.returncode == 0


def _start_sandcat(container: str, caldera_url: str, paw: str,
                   group: str = DEFAULT_GROUP) -> None:
    cmd = (
        f"nohup {SANDCAT_PATH_IN_CONTAINER} "
        f"-server {caldera_url} "
        f"-group {group} "
        f"-paw {paw} "
        f"-v >{SANDCAT_LOG_IN_CONTAINER} 2>&1 &"
    )
    subprocess.run(
        ["docker", "exec", "-d", container, "bash", "-c", cmd],
        capture_output=True, text=True, check=False,
    )


def ensure_agent(container: str, run_dir: Path,
                 group: str = DEFAULT_GROUP) -> Optional[dict]:
    """Idempotently bring a sandcat agent up inside ``container`` and wait
    until Caldera registers it. Returns the agent dict on success.

    Idempotency strategy: first ask Caldera whether the paw associated with
    this container is already registered. If yes, return that agent without
    touching the container. Only fall through to install+start+wait when no
    agent is present, which guarantees we never spawn duplicate sandcats.
    """
    paw = _agent_paw(container)

    # Already registered? Cheap REST query, no container exec needed.
    existing = caldera_client.wait_agent_registered(
        paw_substring=paw, group=group, max_seconds=2, poll_seconds=0.5,
    )
    if existing:
        return existing

    if not _container_has_sandcat(container):
        if not _install_sandcat(container):
            return None
    caldera_ip = caldera_client.container_ip()
    if not caldera_ip:
        return None
    caldera_url = f"http://{caldera_ip}:8888"
    _start_sandcat(container, caldera_url, paw, group=group)
    agent = caldera_client.wait_agent_registered(paw_substring=paw,
                                                  group=group,
                                                  max_seconds=45)
    # Persist a small breadcrumb so a reviewer reading run_dir/ can confirm
    # the C2 channel was real.
    crumb = run_dir / "caldera" / f"agent_{paw}.txt"
    crumb.parent.mkdir(parents=True, exist_ok=True)
    crumb.write_text(
        f"caldera_url={caldera_url}\npaw={paw}\nregistered={bool(agent)}\n"
        f"agent={agent}\n",
        encoding="utf-8",
    )
    return agent


def dispatch_via_caldera(container: str, technique_id: str,
                         run_dir: Path,
                         preferred_platform: str = "linux",
                         operation_timeout_s: int = 180
                         ) -> CalderaLinkResult:
    """Run a single ART ability for ``technique_id`` against the agent in
    ``container``. Returns a CalderaLinkResult; if anything along the chain
    fails, ``ok=False`` and ``error`` carries the failure point."""
    ability = caldera_client.best_ability_for(technique_id, preferred_platform)
    if not ability:
        return CalderaLinkResult(
            ok=False, technique_id=technique_id, ability_id="", ability_name="",
            error=f"no Caldera ability for {technique_id}",
        )
    ability_id = ability.get("ability_id") or ""
    ability_name = ability.get("name") or ""

    _reset_container_agent(container)
    paw = _agent_paw(container)
    group = paw
    agent = ensure_agent(container, run_dir, group=group)
    if not agent:
        return CalderaLinkResult(
            ok=False, technique_id=technique_id,
            ability_id=ability_id, ability_name=ability_name,
            error="sandcat agent did not register with Caldera",
        )

    adv_id = caldera_client.create_adversary(
        name=f"autosut-{technique_id}-{uuid.uuid4().hex[:6]}",
        ability_ids=[ability_id],
        description=f"AutoSUT one-off adversary for {technique_id}",
    )
    if not adv_id:
        return CalderaLinkResult(
            ok=False, technique_id=technique_id,
            ability_id=ability_id, ability_name=ability_name,
            error="create_adversary failed",
        )

    op_name = f"autosut-{technique_id}-{int(time.time())}"
    op_id = caldera_client.start_operation(
        name=op_name, adversary_id=adv_id, group=group,
    )
    if not op_id:
        return CalderaLinkResult(
            ok=False, technique_id=technique_id,
            ability_id=ability_id, ability_name=ability_name,
            error="start_operation failed",
        )

    op, report, link = _wait_report_link_or_finished(
        op_id, ability_id, paw, max_seconds=operation_timeout_s,
    )

    # Persist the full report for reviewer auditability.
    evidence: list[str] = []
    report_path = run_dir / "caldera" / f"{technique_id}_{op_id}_report.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    import json as _json
    report_path.write_text(_json.dumps(report, indent=2), encoding="utf-8")
    evidence.append(str(report_path.relative_to(run_dir)))

    if link is None:
        # Operation finished but no link for our ability — usually means the
        # planner skipped it (platform mismatch, unsatisfied facts, etc.).
        skipped = report.get("skipped_abilities", [])
        return CalderaLinkResult(
            ok=False, technique_id=technique_id,
            ability_id=ability_id, ability_name=ability_name,
            operation_id=op_id, paw=paw,
            evidence_files=evidence,
            error=f"no link in report; skipped={skipped[:1]} state={op.get('state') if op else 'unknown'}",
        )

    output = link.get("output", {}) or {}
    if isinstance(output, str):
        stdout, stderr, exit_code = output, "", None
    else:
        stdout = output.get("stdout") or ""
        stderr = output.get("stderr") or ""
        exit_code = output.get("exit_code")

    # Persist the per-link stdout/stderr for grep-friendly inspection.
    log_path = run_dir / "caldera" / f"{technique_id}_{link.get('link_id')}.log"
    log_path.write_text(
        f"# Caldera link\n"
        f"operation_id: {op_id}\nlink_id: {link.get('link_id')}\n"
        f"ability_id: {ability_id}\nability_name: {ability_name}\n"
        f"command: {link.get('plaintext_command')}\n"
        f"status: {link.get('status')}\nexit_code: {exit_code}\n"
        f"--- stdout ---\n{stdout}\n"
        f"--- stderr ---\n{stderr}\n",
        encoding="utf-8",
    )
    evidence.append(str(log_path.relative_to(run_dir)))

    return CalderaLinkResult(
        ok=(link.get("status") == 0),
        technique_id=technique_id,
        ability_id=ability_id, ability_name=ability_name,
        operation_id=op_id, link_id=link.get("link_id"),
        status=link.get("status"),
        stdout=stdout, stderr=stderr, exit_code=str(exit_code) if exit_code is not None else None,
        paw=paw, evidence_files=evidence,
    )
