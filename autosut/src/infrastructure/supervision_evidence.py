"""Bind a supervised process to the sealed experiment bundle it produced.

The operating-system supervisor and the experiment child are different processes.  A qualifying
bundle therefore needs an explicit, bidirectional link rather than an inferred match by timestamp
or label.  The child seals a binding in its bundle before it runs.  The supervisor records a
receipt after the child exits, including the sealed manifest hash.  Qualification code verifies
both directions and fails closed when either side is absent or inconsistent.

This is provenance for reproducible evaluation, not a cryptographic attestation against a hostile
author.  It prevents accidental promotion of direct, unsupervised runs and makes the reviewer
path auditable without relying on global-directory races.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict


class SupervisionEvidenceError(RuntimeError):
    """A run lacks the supervision evidence required for qualification."""


class SupervisionBinding(BaseModel):
    """The child-side record sealed into an experiment bundle before execution."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["autosut-supervision-binding/v1"] = "autosut-supervision-binding/v1"
    supervision_id: str
    experiment: str
    entrypoint: str
    run_id: str
    receipt_relative_path: str
    created_at: str


class SupervisionHandoff(BaseModel):
    """A child-to-supervisor handoff written before the child can be interrupted."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["autosut-supervision-handoff/v1"] = "autosut-supervision-handoff/v1"
    supervision_id: str
    experiment: str
    entrypoint: str
    run_id: str
    bundle_relative_path: str
    binding_sha256: str
    created_at: str


class SupervisionReceipt(BaseModel):
    """The supervisor-side result, emitted only after the child has ended."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["autosut-supervision-receipt/v1"] = "autosut-supervision-receipt/v1"
    supervision_id: str
    experiment: str
    entrypoint: str
    label: str
    command_sha256: str
    supervisor_pid: int
    child_pid: int | None
    child_pgid: int | None
    started_at: str
    completed_at: str
    completed_naturally: bool | None
    exit_code: int | None
    escalation: list[str]
    grace_deadline_exceeded: bool | None
    residual_after_termination: list[str] | None
    cleanup_completed: bool | None
    cleanup_error: dict | None
    supervisor_interruption: str | None
    handoff: SupervisionHandoff | None
    bundle_manifest_sha256: str | None
    receipt_status: Literal["bound", "handoff_missing", "bundle_unsealed", "supervisor_error"]
    supervisor_error: str | None = None


def utc_now() -> str:
    """Return the canonical timestamp used in supervisor provenance records."""
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path: Path) -> str:
    """Return a content hash without relying on filesystem metadata."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_command(command: list[str]) -> str:
    """Hash the exact argument vector with unambiguous separators."""
    digest = hashlib.sha256()
    for argument in command:
        digest.update(argument.encode("utf-8"))
        digest.update(b"\0")
    return digest.hexdigest()


def write_json_atomic(path: Path, payload: BaseModel | dict) -> None:
    """Write a structured evidence record atomically so readers never see a partial JSON file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = (
        payload.model_dump_json(indent=2)
        if isinstance(payload, BaseModel)
        else json.dumps(payload, indent=2, sort_keys=True)
    )
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(encoded + "\n", encoding="utf-8")
    temporary.replace(path)


def _safe_relative_path(project_root: Path, value: Path | str) -> str:
    """Return a project-relative path, refusing paths that escape the artifact root."""
    candidate = Path(value)
    if candidate.is_absolute():
        try:
            candidate = candidate.resolve().relative_to(project_root.resolve())
        except ValueError as failure:
            raise SupervisionEvidenceError("supervision evidence path escapes project root") from failure
    if ".." in candidate.parts:
        raise SupervisionEvidenceError("supervision evidence path must not contain '..'")
    return candidate.as_posix()


def bind_child_run(
    *,
    project_root: Path,
    run_dir: Path,
    run_id: str,
    experiment: str,
    entrypoint: str,
    supervision_id: str,
    receipt_path: Path,
    handoff_path: Path,
) -> SupervisionBinding:
    """Seal a child binding and publish a handoff before the first lifecycle action runs."""
    binding = SupervisionBinding(
        supervision_id=supervision_id,
        experiment=experiment,
        entrypoint=entrypoint,
        run_id=run_id,
        receipt_relative_path=_safe_relative_path(project_root, receipt_path),
        created_at=utc_now(),
    )
    binding_path = run_dir / "supervision-binding.json"
    write_json_atomic(binding_path, binding)
    handoff = SupervisionHandoff(
        supervision_id=supervision_id,
        experiment=experiment,
        entrypoint=entrypoint,
        run_id=run_id,
        bundle_relative_path=_safe_relative_path(project_root, run_dir),
        binding_sha256=sha256_file(binding_path),
        created_at=utc_now(),
    )
    write_json_atomic(handoff_path, handoff)
    return binding


def read_handoff(path: Path) -> SupervisionHandoff | None:
    """Read a completed handoff, returning ``None`` when the child never reached allocation."""
    if not path.is_file():
        return None
    try:
        return SupervisionHandoff.model_validate_json(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, ValueError) as failure:
        raise SupervisionEvidenceError(f"invalid supervision handoff: {path.name}") from failure


def _relative_child_bundle(project_root: Path, handoff: SupervisionHandoff) -> Path:
    relative = Path(handoff.bundle_relative_path)
    if relative.is_absolute() or ".." in relative.parts:
        raise SupervisionEvidenceError("handoff bundle path is not project-relative")
    bundle = (project_root / relative).resolve()
    try:
        bundle.relative_to(project_root.resolve())
    except ValueError as failure:
        raise SupervisionEvidenceError("handoff bundle path escapes project root") from failure
    return bundle


def _verified_manifest_hash(bundle: Path) -> str:
    """Verify every entry in a sealed bundle and return the manifest's own hash.

    A receipt naming only ``manifest.json`` would not detect a later modification to another
    bundle file.  Qualification therefore checks the manifest entries as well as the manifest
    file's hash recorded in the supervisor receipt.
    """
    manifest_path = bundle / "manifest.json"
    if not manifest_path.is_file():
        raise SupervisionEvidenceError("bundle manifest is missing")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        entries = manifest["files"]
    except (json.JSONDecodeError, KeyError, TypeError) as failure:
        raise SupervisionEvidenceError("bundle manifest is invalid") from failure
    seen: set[str] = set()
    for entry in entries:
        try:
            relative = Path(entry["path"])
            expected_hash = entry["sha256"]
        except (KeyError, TypeError) as failure:
            raise SupervisionEvidenceError("bundle manifest contains an invalid entry") from failure
        if relative.is_absolute() or ".." in relative.parts or relative.as_posix() in seen:
            raise SupervisionEvidenceError("bundle manifest contains an unsafe or duplicate path")
        seen.add(relative.as_posix())
        candidate = bundle / relative
        if not candidate.is_file() or sha256_file(candidate) != expected_hash:
            raise SupervisionEvidenceError("bundle content does not match its sealed manifest")
    return sha256_file(manifest_path)


def build_receipt(
    *,
    project_root: Path,
    supervision_id: str,
    experiment: str,
    entrypoint: str,
    label: str,
    command: list[str],
    supervisor_pid: int,
    started_at: str,
    outcome: dict | None,
    handoff_path: Path,
    supervisor_error: str | None = None,
) -> SupervisionReceipt:
    """Construct a receipt after a child ends; an incomplete child remains explicit evidence."""
    try:
        handoff = read_handoff(handoff_path)
    except SupervisionEvidenceError as failure:
        handoff = None
        supervisor_error = supervisor_error or str(failure)
    manifest_hash: str | None = None
    status: Literal["bound", "handoff_missing", "bundle_unsealed", "supervisor_error"]
    if supervisor_error is not None:
        status = "supervisor_error"
    elif handoff is None:
        status = "handoff_missing"
    else:
        bundle = _relative_child_bundle(project_root, handoff)
        binding_path = bundle / "supervision-binding.json"
        manifest_path = bundle / "manifest.json"
        if not binding_path.is_file() or not manifest_path.is_file():
            status = "bundle_unsealed"
        elif sha256_file(binding_path) != handoff.binding_sha256:
            status = "bundle_unsealed"
        else:
            try:
                manifest_hash = _verified_manifest_hash(bundle)
                status = "bound"
            except SupervisionEvidenceError:
                status = "bundle_unsealed"

    return SupervisionReceipt(
        supervision_id=supervision_id,
        experiment=experiment,
        entrypoint=entrypoint,
        label=label,
        command_sha256=sha256_command(command),
        supervisor_pid=supervisor_pid,
        child_pid=outcome.get("pid") if outcome else None,
        child_pgid=outcome.get("pgid") if outcome else None,
        started_at=started_at,
        completed_at=utc_now(),
        completed_naturally=outcome.get("completed_naturally") if outcome else None,
        exit_code=outcome.get("exit_code") if outcome else None,
        escalation=outcome.get("escalation", []) if outcome else [],
        grace_deadline_exceeded=outcome.get("grace_deadline_exceeded") if outcome else None,
        residual_after_termination=outcome.get("residual_after_termination") if outcome else None,
        cleanup_completed=outcome.get("cleanup_completed") if outcome else None,
        cleanup_error=outcome.get("cleanup_error") if outcome else None,
        supervisor_interruption=outcome.get("supervisor_interruption") if outcome else None,
        handoff=handoff,
        bundle_manifest_sha256=manifest_hash,
        receipt_status=status,
        supervisor_error=supervisor_error,
    )


def verify_qualified_bundle(
    *,
    project_root: Path,
    bundle: Path,
    expected_experiment: str,
    require_natural_completion: bool = True,
) -> SupervisionReceipt:
    """Verify the child binding, parent receipt, and sealed-manifest link for qualification.

    Direct entrypoint invocations do not write a parent receipt and therefore fail here.  A receipt
    is also not sufficient on its own: it must name this exact sealed manifest and child binding.
    """
    binding_path = bundle / "supervision-binding.json"
    manifest_path = bundle / "manifest.json"
    if not binding_path.is_file() or not manifest_path.is_file():
        raise SupervisionEvidenceError("bundle lacks a sealed supervision binding or manifest")
    try:
        binding = SupervisionBinding.model_validate_json(binding_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, ValueError) as failure:
        raise SupervisionEvidenceError("invalid child supervision binding") from failure
    if binding.experiment != expected_experiment:
        raise SupervisionEvidenceError("binding experiment does not match qualification target")
    try:
        expected_bundle = bundle.resolve().relative_to(project_root.resolve()).as_posix()
    except ValueError as failure:
        raise SupervisionEvidenceError("bundle is outside project root") from failure
    receipt_relative = Path(binding.receipt_relative_path)
    if receipt_relative.is_absolute() or ".." in receipt_relative.parts:
        raise SupervisionEvidenceError("binding receipt path is not project-relative")
    receipt_path = (project_root / receipt_relative).resolve()
    try:
        receipt_path.relative_to(project_root.resolve())
    except ValueError as failure:
        raise SupervisionEvidenceError("binding receipt path escapes project root") from failure
    if not receipt_path.is_file():
        raise SupervisionEvidenceError("supervisor receipt is missing")
    try:
        receipt = SupervisionReceipt.model_validate_json(receipt_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, ValueError) as failure:
        raise SupervisionEvidenceError("invalid supervisor receipt") from failure

    if receipt.receipt_status != "bound":
        raise SupervisionEvidenceError(f"receipt is not bound: {receipt.receipt_status}")
    if receipt.supervision_id != binding.supervision_id or receipt.experiment != expected_experiment:
        raise SupervisionEvidenceError("receipt identity does not match child binding")
    if receipt.handoff is None:
        raise SupervisionEvidenceError("bound receipt lacks child handoff")
    if receipt.handoff.run_id != binding.run_id or receipt.handoff.bundle_relative_path != expected_bundle:
        raise SupervisionEvidenceError("receipt handoff does not name this bundle")
    if receipt.handoff.binding_sha256 != sha256_file(binding_path):
        raise SupervisionEvidenceError("receipt handoff does not match sealed child binding")
    verified_manifest_hash = _verified_manifest_hash(bundle)
    if receipt.bundle_manifest_sha256 != verified_manifest_hash:
        raise SupervisionEvidenceError("receipt does not name this sealed manifest")
    if receipt.cleanup_completed is not True:
        raise SupervisionEvidenceError("supervisor could not complete a cleanup inventory")
    if receipt.residual_after_termination:
        raise SupervisionEvidenceError("supervisor recorded residual resources")
    if require_natural_completion and (
        receipt.completed_naturally is not True or receipt.exit_code != 0 or receipt.escalation
    ):
        raise SupervisionEvidenceError("qualification requires a natural, successful supervised run")
    return receipt
