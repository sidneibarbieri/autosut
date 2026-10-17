#!/usr/bin/env python3
"""Execute one explicitly scoped R4 interruption-matrix cell through the canonical supervisor.

This is an evidence producer, not a result generator.  A cell names one real lifecycle stage and
one external interruption mechanism.  It starts the canonical Caldera experiment only through
``run_supervised.py``, waits until that stage writes its atomic marker, injects SIGINT/SIGTERM into
the child process group (or arms the supervisor's deadline), and seals the resulting observation.

The bundle records the exact command, stage marker, child PID/PGID, supervisor outcome, child
output, and a post-run namespace inventory.  It deliberately does not promote a passing cell to a
paper claim: qualification requires a predeclared matrix, independent reruns, and a review of every
cell including failures.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from infrastructure.docker_namespace import DockerInventoryError, autosut_resources  # noqa: E402
from infrastructure.revision import current_revision  # noqa: E402
from infrastructure.run_context import seal_directory  # noqa: E402


_SUPPORTED_STAGES = {
    "materialize_caldera",
    "verify_caldera_readiness",
    "materialize_sut",
    "enroll_agent",
    "register_and_execute",
    "verify_effect",
    "persist_execution_evidence",
    "destroy_attacker",
    "destroy_sut",
    "destroy_caldera",
}
_SUPPORTED_INJECTIONS = {"sigint", "sigterm", "deadline"}
_EVIDENCE_ROOT = PROJECT_ROOT / "release" / "evidence" / "raw" / "r4-interruption-matrix"
_COMMIT_SHA256 = re.compile(r"^[0-9a-f]{40}$")


def _read_json(path: Path) -> dict | None:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def _await_stage(path: Path, stage: str, timeout_seconds: float) -> dict:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        record = _read_json(path)
        if record and record.get("stage") == stage:
            return record
        time.sleep(0.1)
    raise TimeoutError(f"stage {stage!r} did not begin within {timeout_seconds}s")


def _boundary_path(directory: Path, stage: str, condition: str) -> Path:
    """Return the canonical semantic-boundary filename emitted by the Caldera lifecycle."""
    safe_stage = "".join(character if character.isalnum() or character in "-_" else "-"
                         for character in stage)
    safe_condition = "".join(character if character.isalnum() or character in "-_" else "-"
                             for character in condition)
    return directory / f"{safe_stage}--{safe_condition}.json"


def _await_semantic_boundary(
    directory: Path,
    stage: str,
    condition: str,
    timeout_seconds: float,
) -> dict:
    """Wait for an actual observed condition, not merely entry into a lifecycle function."""
    path = _boundary_path(directory, stage, condition)
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        record = _read_json(path)
        if (
            record
            and record.get("stage") == stage
            and record.get("condition") == condition
            and isinstance(record.get("evidence"), dict)
        ):
            return record
        time.sleep(0.1)
    raise TimeoutError(f"semantic boundary {stage!r}/{condition!r} was not observed")


def _await_supervisor(path: Path, timeout_seconds: float) -> dict:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        record = _read_json(path)
        if record and isinstance(record.get("pgid"), int):
            return record
        time.sleep(0.05)
    raise TimeoutError("supervisor did not publish the child PID/PGID")


def _unique_bundle(stage: str, injection: str, label: str) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe_label = "".join(character if character.isalnum() or character in "-_" else "-" for character in label)
    return _EVIDENCE_ROOT / f"{stamp}_{stage}_{injection}_{safe_label}"


def _write_json(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def _terminate_child_then_wrapper(process: subprocess.Popen, child: dict | None) -> None:
    """Stop the actual child group before stopping the wrapper on a driver-side failure.

    ``run_supervised.py`` intentionally starts its experiment in another process session.  Killing
    only the wrapper would leave that child outside the driver's group, so the driver uses the
    supervisor-published PGID and gives the wrapper time to run its sweep and emit a receipt.
    """
    if child is not None and isinstance(child.get("pgid"), int):
        pgid = child["pgid"]
        try:
            os.killpg(pgid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=45)
            return
        except subprocess.TimeoutExpired:
            try:
                os.killpg(pgid, signal.SIGKILL)
            except ProcessLookupError:
                pass
    if process.poll() is None:
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(os.getpgid(process.pid), signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=30)


def _protocol_cell(path: Path, cell_id: str, stage: str, injection: str) -> tuple[dict, dict, str]:
    """Return one protocol and predeclared cell after binding identifiers to the CLI request."""
    raw = path.read_bytes()
    protocol = json.loads(raw)
    matches = [cell for cell in protocol.get("cells", []) if cell.get("id") == cell_id]
    if len(matches) != 1:
        raise ValueError(f"protocol must contain exactly one cell id {cell_id!r}")
    cell = matches[0]
    if cell.get("stage") != stage or cell.get("injection") != injection:
        raise ValueError(
            f"cell {cell_id} declares {cell.get('stage')}/{cell.get('injection')}, "
            f"not {stage}/{injection}"
        )
    return protocol, cell, hashlib.sha256(raw).hexdigest()


def _v2_qualification_requirements(
    protocol: dict,
    observed_revision: str,
) -> dict[str, str] | None:
    """Return a revision-bound qualification declaration, or reject a draft v2 protocol.

    The human-readable v2 protocol template is intentionally not executable.  A separate freeze
    step must bind it to one clean source commit before a driver can create a qualifying attempt.
    This prevents a field trial from silently deciding which code revision it evaluated.
    """

    if protocol.get("schema_version") != "r4-interruption-protocol/v2":
        return None
    if protocol.get("status") != "frozen_for_execution":
        raise ValueError("R4 v2 execution requires a protocol frozen for one immutable revision")
    frozen_revision = protocol.get("frozen_revision")
    if not isinstance(frozen_revision, str) or not _COMMIT_SHA256.fullmatch(frozen_revision):
        raise ValueError("R4 v2 protocol is missing an immutable frozen_revision")
    if observed_revision != frozen_revision:
        raise ValueError("R4 v2 protocol revision does not match the clean source revision")
    requirements = protocol.get("execution_requirements")
    if not isinstance(requirements, dict):
        raise ValueError("R4 v2 protocol is missing execution_requirements")
    if requirements.get("execution_mode") != "supervised":
        raise ValueError("R4 v2 requires supervised execution")
    if requirements.get("evidence_role") != "qualification":
        raise ValueError("R4 v2 requires qualification evidence role")
    if requirements.get("implementation_revision") != "immutable_clean_commit":
        raise ValueError("R4 v2 must require an immutable clean commit")
    topology = requirements.get("topology")
    if not isinstance(topology, str) or not topology.strip():
        raise ValueError("R4 v2 protocol is missing a qualification topology")
    metadata_protocol = requirements.get(
        "qualification_metadata_protocol_version", "autosut-qualification/v1"
    )
    if not isinstance(metadata_protocol, str) or not metadata_protocol.strip():
        raise ValueError("R4 v2 protocol has an invalid qualification metadata protocol version")
    return {
        "revision": frozen_revision,
        "topology": topology,
        "metadata_protocol": metadata_protocol,
    }


def _qualification_metadata_observed(
    supervision: dict | None,
    requirement: dict[str, str] | None,
) -> bool:
    """Check the child-side declaration before marking a v2 observation clean.

    The aggregator independently revalidates the full parent/child/manifest chain.  This local
    check prevents the driver from emitting a misleading green `outcome` if the required metadata
    was absent before the child sealed its bundle.
    """

    if requirement is None:
        return True
    if not isinstance(supervision, dict):
        return False
    handoff = supervision.get("handoff")
    if not isinstance(handoff, dict):
        return False
    relative = handoff.get("bundle_relative_path")
    if not isinstance(relative, str):
        return False
    candidate = Path(relative)
    if candidate.is_absolute() or ".." in candidate.parts:
        return False
    child_bundle = (PROJECT_ROOT / candidate).resolve()
    try:
        child_bundle.relative_to(PROJECT_ROOT.resolve())
    except ValueError:
        return False
    metadata_path = child_bundle / "qualification-metadata.json"
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    return (
        metadata.get("schema_version") == "autosut-evidence-metadata/v1"
        and metadata.get("protocol_version") == requirement["metadata_protocol"]
        and metadata.get("evidence_role") == "qualification"
        and metadata.get("execution_mode") == "supervised"
        and metadata.get("implementation_revision") == requirement["revision"]
        and metadata.get("topology") == requirement["topology"]
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", choices=sorted(_SUPPORTED_STAGES), required=True)
    parser.add_argument("--injection", choices=sorted(_SUPPORTED_INJECTIONS), required=True)
    parser.add_argument("--label", default="r4")
    parser.add_argument(
        "--condition",
        help="semantic condition for an ad-hoc development cell; protocol cells declare this field",
    )
    parser.add_argument(
        "--protocol",
        type=Path,
        help="predeclared protocol JSON; required with --cell-id",
    )
    parser.add_argument(
        "--cell-id",
        help="predeclared protocol cell identifier; required with --protocol",
    )
    parser.add_argument("--stage-wait-seconds", type=float, default=480.0)
    parser.add_argument("--deadline-seconds", type=float, default=2.0)
    parser.add_argument("--grace-seconds", type=float, default=30.0)
    parser.add_argument("--setup-deadline-seconds", type=float, default=600.0)
    args = parser.parse_args()
    if (args.protocol is None) != (args.cell_id is None):
        parser.error("--protocol and --cell-id must be supplied together")
    protocol_binding: dict[str, object] = {}
    qualification_requirement: dict[str, str] | None = None
    target_condition = args.condition
    observed_revision = current_revision(PROJECT_ROOT)
    if args.protocol is not None:
        try:
            protocol, cell, protocol_hash = _protocol_cell(
                args.protocol, args.cell_id, args.stage, args.injection
            )
            qualification_requirement = _v2_qualification_requirements(
                protocol, observed_revision
            )
        except (OSError, ValueError, json.JSONDecodeError) as error:
            parser.error(str(error))
        declared_condition = cell.get("condition")
        if args.condition is not None and args.condition != declared_condition:
            parser.error("--condition does not match the predeclared protocol cell")
        target_condition = declared_condition
        protocol_binding = {
            "protocol_id": protocol["protocol_id"],
            "protocol_version": protocol["schema_version"],
            "protocol_sha256": protocol_hash,
            "cell_id": cell["id"],
            "cell_property": cell["property"],
        }
        if qualification_requirement is not None:
            protocol_binding["frozen_revision"] = qualification_requirement["revision"]

    bundle = _unique_bundle(args.stage, args.injection, args.label)
    bundle.mkdir(parents=True, exist_ok=False)
    stage_status = bundle / "stage-status.json"
    semantic_boundary_dir = bundle / "semantic-boundaries"
    supervisor_status = bundle / "supervisor-status.json"
    supervision_receipt = bundle / "supervision-receipt.json"
    started = time.monotonic()

    command = [
        sys.executable,
        str(PROJECT_ROOT / "scripts" / "run_supervised.py"),
        "--experiment", "caldera",
        "--label", f"r4-{args.stage}-{args.injection}-{args.label}",
        "--deadline-seconds", str(args.deadline_seconds),
        "--grace-seconds", str(args.grace_seconds),
        "--setup-deadline-seconds", str(args.setup_deadline_seconds),
        "--stage-status-file", str(stage_status),
        "--semantic-boundary-dir", str(semantic_boundary_dir),
        "--supervisor-status-file", str(supervisor_status),
        "--supervision-receipt-file", str(supervision_receipt),
    ]
    if qualification_requirement is not None:
        command.extend([
            "--qualification-protocol-version", qualification_requirement["metadata_protocol"],
            "--qualification-revision", qualification_requirement["revision"],
            "--qualification-topology", qualification_requirement["topology"],
        ])
    if args.injection == "deadline":
        if target_condition is None:
            command.extend(["--arm-deadline-after-stage", args.stage])
        else:
            command.extend([
                "--arm-deadline-after-boundary-file",
                str(_boundary_path(semantic_boundary_dir, args.stage, target_condition)),
            ])
    else:
        # A large ordinary deadline makes the requested external signal, not elapsed setup time,
        # the only intended interruption mechanism for this cell.
        command[command.index("--deadline-seconds") + 1] = "3600"

    stdout_path = bundle / "wrapper.stdout.log"
    stderr_path = bundle / "wrapper.stderr.log"
    stdout_handle = stdout_path.open("w", encoding="utf-8")
    stderr_handle = stderr_path.open("w", encoding="utf-8")
    process = subprocess.Popen(
        command, stdout=stdout_handle, stderr=stderr_handle, text=True, start_new_session=True
    )
    observation: dict[str, object] = {
        "schema_version": (
            "r4-interruption-cell/v2"
            if qualification_requirement is not None
            else "r4-interruption-cell/v1"
        ),
        "classification": (
            "predeclared_qualification_attempt"
            if qualification_requirement is not None
            else "historical_development_evidence"
        ),
        "stage": args.stage,
        "target_condition": target_condition,
        "injection": args.injection,
        "command": command,
        "implementation_revision": observed_revision,
        "started_at": datetime.now(timezone.utc).isoformat(),
        **protocol_binding,
    }

    child: dict | None = None
    try:
        child = _await_supervisor(supervisor_status, timeout_seconds=30)
        observation["child"] = child
        if target_condition is None:
            boundary_record = _await_stage(stage_status, args.stage, args.stage_wait_seconds)
        else:
            boundary_record = _await_semantic_boundary(
                semantic_boundary_dir, args.stage, target_condition, args.stage_wait_seconds
            )
        observation["observed_stage"] = boundary_record
        observation["target_stage"] = args.stage
        observation["stage_boundary_observed"] = boundary_record.get("stage") == args.stage
        observation["boundary_observed_at"] = boundary_record.get(
            "observed_at", boundary_record.get("recorded_at")
        )
        observation["injection_at"] = datetime.now(timezone.utc).isoformat()
        if args.injection == "sigint":
            os.killpg(child["pgid"], signal.SIGINT)
            observation["signal_sent"] = "SIGINT"
        elif args.injection == "sigterm":
            os.killpg(child["pgid"], signal.SIGTERM)
            observation["signal_sent"] = "SIGTERM"
        else:
            observation["signal_sent"] = "supervisor deadline armed after observed stage"
        process.wait(timeout=args.grace_seconds + 180)
    except BaseException as failure:
        _terminate_child_then_wrapper(process, child)
        observation["driver_error"] = f"{type(failure).__name__}: {failure}"
    finally:
        stdout_handle.close()
        stderr_handle.close()

    observation["wrapper_exit_code"] = process.returncode
    observation["duration_seconds"] = round(time.monotonic() - started, 3)
    try:
        observation["resources_after_wrapper"] = sorted(autosut_resources())
    except DockerInventoryError as error:
        observation["resources_after_wrapper"] = None
        observation["inventory_error"] = error.diagnostic.model_dump(mode="json")
    supervision = _read_json(supervision_receipt)
    if supervision is None:
        observation["supervision_record_missing"] = True

    qualification_metadata_valid = _qualification_metadata_observed(
        supervision, qualification_requirement
    )
    if qualification_requirement is not None:
        observation["qualification_metadata_observed"] = qualification_metadata_valid
    valid_observation = (
        "driver_error" not in observation
        and "observed_stage" in observation
        and supervision is not None
        and observation["resources_after_wrapper"] == []
        and supervision.get("receipt_status") == "bound"
        and supervision.get("cleanup_completed") is True
        and not supervision.get("residual_after_termination")
        and qualification_metadata_valid
    )
    observation["outcome"] = "observed_clean" if valid_observation else "incomplete_or_dirty"
    observation["supervision_result"] = {
        "record_present": supervision is not None,
        "completed_naturally": supervision.get("completed_naturally") if supervision else None,
        "exit_code": supervision.get("exit_code") if supervision else None,
        "signals_sent": supervision.get("escalation") if supervision else [],
        "grace_expired": supervision.get("grace_deadline_exceeded") if supervision else None,
        "residual_inventory": supervision.get("residual_after_termination") if supervision else None,
        "cleanup_completed": supervision.get("cleanup_completed") if supervision else None,
        "receipt_status": supervision.get("receipt_status") if supervision else None,
    }
    # A direct SIGINT/SIGTERM is intentionally handled by the lifecycle, which reports its own
    # interrupted run as non-zero. The matrix cell therefore judges evidence completeness and
    # verified cleanup, not a normal-success exit code from an intentionally interrupted child.
    observation["expected_interruption_exit"] = args.injection in {"sigint", "sigterm"}
    if qualification_requirement is not None:
        observation["attempt_accounting"] = {"disposition": "included", "reason_codes": []}
    _write_json(bundle / "matrix-cell.json", observation)

    manifest = seal_directory(bundle, bundle.name, observation["started_at"])
    print(f"[r4-matrix] bundle: {bundle.relative_to(PROJECT_ROOT)}")
    print(f"[r4-matrix] wrapper exit: {process.returncode}; outcome: {observation['outcome']}; "
          f"residual: {observation['resources_after_wrapper'] or 'none'}")
    print(f"[r4-matrix] sealed files: {manifest.file_count}")
    return 0 if valid_observation else 2


if __name__ == "__main__":
    raise SystemExit(main())
