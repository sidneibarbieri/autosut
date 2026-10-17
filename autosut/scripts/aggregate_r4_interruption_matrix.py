#!/usr/bin/env python3
"""Derive a version-aware, fail-closed R4 interruption-matrix qualification record.

The matrix contains two distinct evidence generations.  Version 1 records remain useful
development history, but they predate semantic boundaries and the explicit parent-supervisor to
child-bundle binding.  They are therefore retained and reported as historical development evidence,
not relabelled as invalid evidence and not allowed to promote the current qualification claim.

Version 2 is deliberately stricter.  It qualifies a cell only when its sealed driver bundle, its
sealed child bundle, and the independent supervisor receipt form one complete evidence chain.  A
green ``outcome`` field is never sufficient.  Every raw attempt is emitted with a structured
accounting disposition so later retries, exclusions, and malformed records cannot disappear behind
a latest-attempt summary.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from infrastructure.supervision_evidence import (  # noqa: E402
    SupervisionEvidenceError,
    SupervisionReceipt,
    verify_qualified_bundle,
)
from infrastructure.qualification import (  # noqa: E402
    EvidenceRole,
    ExecutionMode,
    QualificationEvidenceMetadata,
)

DEFAULT_PROTOCOL = (
    PROJECT_ROOT / "release" / "experiments" / "r4_interruption_matrix_protocol_v2.json"
)
RAW_ROOT = PROJECT_ROOT / "release" / "evidence" / "raw" / "r4-interruption-matrix"
OUTPUT_ROOT = PROJECT_ROOT / "release" / "experiments"

_COMMIT_SHA256 = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PROTOCOL_SCHEMA = re.compile(r"^r4-interruption-protocol/v(?P<version>[1-9][0-9]*)$")
_CELL_SCHEMA = re.compile(r"^r4-interruption-cell/v(?P<version>[1-9][0-9]*)$")
_ACCOUNTING_DISPOSITIONS = {"included", "retry", "excluded"}
_HOST_PATH = re.compile(r"(?:/(?:Users|home|private|var|tmp)/|[A-Za-z]:[\\/])")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_bundle_identifier(bundle: Path) -> str:
    """Return a stable identifier without leaking an absolute host path."""
    try:
        return bundle.resolve().relative_to(PROJECT_ROOT.resolve()).as_posix()
    except ValueError:
        # Test fixtures and an explicitly supplied external raw root are still accounted for, but
        # their local filesystem location is not a reviewer-facing datum.
        return f"external-raw/{hashlib.sha256(str(bundle).encode('utf-8')).hexdigest()[:16]}"


def _safe_timestamp(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc).isoformat()


def _parse_timestamp(value: object) -> datetime | None:
    normalized = _safe_timestamp(value)
    return datetime.fromisoformat(normalized) if normalized is not None else None


def _safe_revision(value: object) -> str | None:
    return value if isinstance(value, str) and _COMMIT_SHA256.fullmatch(value) else None


def _safe_text(value: object) -> str | None:
    """Keep declared prose only when it cannot expose a local host path."""
    if not isinstance(value, str) or _HOST_PATH.search(value):
        return None
    return value


def _protocol_version(protocol: dict[str, Any]) -> int | None:
    schema = protocol.get("schema_version")
    if not isinstance(schema, str):
        return None
    match = _PROTOCOL_SCHEMA.fullmatch(schema)
    return int(match.group("version")) if match else None


def _cell_record_version(record: dict[str, Any]) -> int | None:
    for key, pattern in (("protocol_version", _PROTOCOL_SCHEMA), ("schema_version", _CELL_SCHEMA)):
        value = record.get(key)
        if isinstance(value, str):
            match = pattern.fullmatch(value)
            if match:
                return int(match.group("version"))
    return None


def _is_safe_relative_path(value: object) -> bool:
    if not isinstance(value, str) or not value:
        return False
    path = Path(value)
    return not path.is_absolute() and ".." not in path.parts and path != Path(".")


def _verify_full_manifest(bundle: Path) -> tuple[bool, list[str], str | None]:
    """Verify a complete directory seal, including no unlisted files after sealing.

    ``verify_qualified_bundle`` verifies the parent/child chain.  This local check additionally
    rejects a directory with files added after its manifest was written, because an R4 driver bundle
    is the object whose matrix observation must itself be immutable.
    """
    manifest_path = bundle / "manifest.json"
    if not manifest_path.is_file() or manifest_path.is_symlink():
        return False, ["manifest_missing"], None
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False, ["manifest_unparseable"], None
    if not isinstance(manifest, dict):
        return False, ["manifest_not_object"], None

    reasons: list[str] = []
    required = {"run_id", "created_at", "sealed_at", "file_count", "total_bytes", "files"}
    if not required <= set(manifest):
        reasons.append("manifest_required_fields_missing")
    if manifest.get("run_id") != bundle.name:
        reasons.append("manifest_run_id_mismatch")
    entries = manifest.get("files")
    if not isinstance(entries, list):
        return False, [*reasons, "manifest_entries_invalid"], None
    if not isinstance(manifest.get("file_count"), int) or isinstance(
        manifest.get("file_count"), bool
    ):
        reasons.append("manifest_file_count_invalid")
    if not isinstance(manifest.get("total_bytes"), int) or isinstance(
        manifest.get("total_bytes"), bool
    ):
        reasons.append("manifest_total_bytes_invalid")

    expected: set[str] = set()
    total_bytes = 0
    for entry in entries:
        if not isinstance(entry, dict):
            reasons.append("manifest_entry_invalid")
            continue
        relative = entry.get("path")
        expected_hash = entry.get("sha256")
        expected_bytes = entry.get("bytes")
        if not _is_safe_relative_path(relative):
            reasons.append("manifest_entry_path_unsafe")
            continue
        if not isinstance(expected_hash, str) or not _SHA256.fullmatch(expected_hash):
            reasons.append("manifest_entry_hash_invalid")
            continue
        if (
            not isinstance(expected_bytes, int)
            or isinstance(expected_bytes, bool)
            or expected_bytes < 0
        ):
            reasons.append("manifest_entry_size_invalid")
            continue
        assert isinstance(relative, str)
        if relative in expected:
            reasons.append("manifest_entry_duplicate")
            continue
        expected.add(relative)
        candidate = bundle / relative
        if candidate.is_symlink() or not candidate.is_file():
            reasons.append("manifest_entry_file_missing")
            continue
        try:
            actual_bytes = candidate.stat().st_size
            actual_hash = _sha256(candidate)
        except OSError:
            reasons.append("manifest_entry_unreadable")
            continue
        if actual_bytes != expected_bytes:
            reasons.append("manifest_entry_size_mismatch")
        if actual_hash != expected_hash:
            reasons.append("manifest_entry_hash_mismatch")
        total_bytes += actual_bytes

    actual: set[str] = set()
    try:
        for candidate in bundle.rglob("*"):
            if candidate.is_symlink():
                reasons.append("bundle_symlink_present")
                continue
            if candidate.is_file() and candidate != manifest_path:
                actual.add(candidate.relative_to(bundle).as_posix())
    except OSError:
        reasons.append("bundle_walk_failed")
    if actual != expected:
        reasons.append("manifest_not_full_directory_seal")
    if manifest.get("file_count") != len(entries):
        reasons.append("manifest_file_count_mismatch")
    if manifest.get("total_bytes") != total_bytes:
        reasons.append("manifest_total_bytes_mismatch")
    reasons = sorted(set(reasons))
    return not reasons, reasons, _sha256(manifest_path) if not reasons else None


def _read_attempts(raw_root: Path) -> list[dict[str, Any]]:
    """Read every raw directory into internal records; never silently skip a malformed one."""
    attempts: list[dict[str, Any]] = []
    for bundle in sorted(raw_root.iterdir()) if raw_root.exists() else []:
        if not bundle.is_dir():
            attempts.append(
                {
                    "bundle_path": bundle,
                    "bundle": _safe_bundle_identifier(bundle),
                    "record": None,
                    "read_reason": "raw_entry_not_directory",
                }
            )
            continue
        record_path = bundle / "matrix-cell.json"
        if not record_path.is_file():
            attempts.append(
                {
                    "bundle_path": bundle,
                    "bundle": _safe_bundle_identifier(bundle),
                    "record": None,
                    "read_reason": "matrix_cell_missing",
                }
            )
            continue
        try:
            record = json.loads(record_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            attempts.append(
                {
                    "bundle_path": bundle,
                    "bundle": _safe_bundle_identifier(bundle),
                    "record": None,
                    "read_reason": "matrix_cell_unparseable",
                }
            )
            continue
        if not isinstance(record, dict):
            attempts.append(
                {
                    "bundle_path": bundle,
                    "bundle": _safe_bundle_identifier(bundle),
                    "record": None,
                    "read_reason": "matrix_cell_not_object",
                }
            )
            continue
        attempts.append(
            {
                "bundle_path": bundle,
                "bundle": _safe_bundle_identifier(bundle),
                "record": record,
                "read_reason": None,
            }
        )
    return attempts


def _declared_accounting(record: dict[str, Any]) -> tuple[str, list[str]]:
    """Read optional retry/exclusion metadata without letting it erase a bad attempt."""
    accounting = record.get("attempt_accounting")
    if accounting is None:
        return "included", []
    if not isinstance(accounting, dict):
        return "included", ["attempt_accounting_invalid"]
    disposition = accounting.get("disposition")
    reasons = accounting.get("reason_codes", [])
    if disposition not in _ACCOUNTING_DISPOSITIONS:
        return "included", ["attempt_accounting_disposition_invalid"]
    if not isinstance(reasons, list) or not all(
        isinstance(reason, str) and re.fullmatch(r"[a-z0-9_:-]+", reason) for reason in reasons
    ):
        return disposition, ["attempt_accounting_reason_codes_invalid"]
    if disposition in {"retry", "excluded"} and not reasons:
        return disposition, ["attempt_accounting_reason_codes_missing"]
    return disposition, sorted(set(reasons))


def _classify_attempt(
    attempt: dict[str, Any],
    protocol: dict[str, Any],
    protocol_hash: str,
    version: int,
) -> tuple[str, list[str]]:
    """Classify an attempt without treating historical v1 material as defective v2 evidence."""
    record = attempt["record"]
    if record is None:
        return "unclassifiable", [attempt["read_reason"]]

    record_version = _cell_record_version(record)
    if record_version == 1:
        return "historical_development", ["protocol_v1_historical_development"]
    if version == 1:
        return "historical_development", ["selected_protocol_v1_historical_development"]
    if record_version is None:
        return "unclassifiable", ["record_protocol_version_missing"]
    if record_version != version:
        return "other_protocol_version", ["record_protocol_version_not_selected"]

    matching_identity = (
        record.get("protocol_id") == protocol.get("protocol_id")
        and record.get("protocol_sha256") == protocol_hash
        and record.get("protocol_version") == protocol.get("schema_version")
    )
    if matching_identity:
        return "selected_protocol", []
    if record.get("protocol_id") == protocol.get("protocol_id"):
        return "selected_protocol_mismatch", ["protocol_hash_or_version_mismatch"]
    return "other_protocol", ["record_protocol_not_selected"]


def _read_receipt(bundle: Path) -> tuple[SupervisionReceipt | None, list[str]]:
    receipt_path = bundle / "supervision-receipt.json"
    if not receipt_path.is_file() or receipt_path.is_symlink():
        return None, ["supervision_receipt_missing"]
    try:
        receipt = SupervisionReceipt.model_validate_json(receipt_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None, ["supervision_receipt_invalid"]
    return receipt, []


def _child_bundle_from_receipt(receipt: SupervisionReceipt) -> tuple[Path | None, list[str]]:
    if receipt.handoff is None:
        return None, ["supervision_handoff_missing"]
    relative = Path(receipt.handoff.bundle_relative_path)
    if relative.is_absolute() or ".." in relative.parts:
        return None, ["supervision_handoff_path_unsafe"]
    bundle = (PROJECT_ROOT / relative).resolve()
    try:
        bundle.relative_to(PROJECT_ROOT.resolve())
    except ValueError:
        return None, ["supervision_handoff_path_outside_project"]
    return bundle, []


def _validate_qualification_metadata(
    bundle: Path,
    revision: str | None,
    required_topology: str | None,
    required_protocol_version: str,
) -> tuple[bool, str | None, list[str]]:
    """Require the policy-layer declaration sealed with the supervised child bundle."""
    path = bundle / "qualification-metadata.json"
    if not path.is_file() or path.is_symlink():
        return False, None, ["qualification_metadata_missing"]
    try:
        metadata = QualificationEvidenceMetadata.model_validate_json(
            path.read_text(encoding="utf-8")
        )
    except (OSError, ValueError):
        return False, None, ["qualification_metadata_invalid"]
    reasons: list[str] = []
    if metadata.evidence_role is not EvidenceRole.QUALIFICATION:
        reasons.append("qualification_metadata_role_not_qualification")
    if metadata.execution_mode is not ExecutionMode.SUPERVISED:
        reasons.append("qualification_metadata_execution_mode_not_supervised")
    if metadata.implementation_revision != revision:
        reasons.append("qualification_metadata_revision_mismatch")
    if required_topology is not None and metadata.topology != required_topology:
        reasons.append("qualification_metadata_topology_mismatch")
    if metadata.protocol_version != required_protocol_version:
        reasons.append("qualification_metadata_protocol_version_mismatch")
    return not reasons, _safe_text(metadata.protocol_version), reasons


def _validate_receipt_summary(record: dict[str, Any], receipt: SupervisionReceipt) -> list[str]:
    summary = record.get("supervision_result")
    if not isinstance(summary, dict):
        return ["supervision_result_missing"]
    reasons: list[str] = []
    expected = {
        "record_present": True,
        "completed_naturally": receipt.completed_naturally,
        "exit_code": receipt.exit_code,
        "signals_sent": receipt.escalation,
        "grace_expired": receipt.grace_deadline_exceeded,
        "residual_inventory": receipt.residual_after_termination,
        "cleanup_completed": receipt.cleanup_completed,
        "receipt_status": receipt.receipt_status,
    }
    for field, value in expected.items():
        if summary.get(field) != value:
            reasons.append(f"supervision_result_{field}_mismatch")
    return reasons


def _validate_injection_semantics(
    record: dict[str, Any], cell: dict[str, Any], receipt: SupervisionReceipt
) -> list[str]:
    """Require evidence for the specific interruption mechanism, not merely a cleaned namespace."""
    injection = cell["injection"]
    reasons: list[str] = []
    if record.get("injection") != injection:
        reasons.append("injection_does_not_match_protocol")
        return reasons
    if injection == "sigint":
        if record.get("signal_sent") != "SIGINT":
            reasons.append("sigint_not_recorded")
        if record.get("expected_interruption_exit") is not True:
            reasons.append("sigint_expected_interruption_not_recorded")
        if receipt.completed_naturally is not True or receipt.escalation:
            reasons.append("sigint_child_not_cleanly_signal_terminated")
        if not isinstance(record.get("wrapper_exit_code"), int) or record["wrapper_exit_code"] == 0:
            reasons.append("sigint_wrapper_exit_not_interrupted")
    elif injection == "sigterm":
        if record.get("signal_sent") != "SIGTERM":
            reasons.append("sigterm_not_recorded")
        if record.get("expected_interruption_exit") is not True:
            reasons.append("sigterm_expected_interruption_not_recorded")
        if receipt.completed_naturally is not True or receipt.escalation:
            reasons.append("sigterm_child_not_cleanly_signal_terminated")
        if not isinstance(record.get("wrapper_exit_code"), int) or record["wrapper_exit_code"] == 0:
            reasons.append("sigterm_wrapper_exit_not_interrupted")
    elif injection == "deadline":
        signal_record = record.get("signal_sent")
        if not isinstance(signal_record, str) or "deadline" not in signal_record.lower():
            reasons.append("deadline_not_armed_after_boundary")
        if record.get("expected_interruption_exit") is not False:
            reasons.append("deadline_expected_interruption_semantics_missing")
        if receipt.completed_naturally is not False:
            reasons.append("deadline_did_not_require_supervisor_termination")
        if not receipt.escalation or receipt.escalation[0] != "SIGTERM":
            reasons.append("deadline_supervisor_sigterm_missing")
        if receipt.grace_deadline_exceeded != ("SIGKILL" in receipt.escalation):
            reasons.append("deadline_grace_escalation_inconsistent")
    else:  # Protocol parsing rejects this before any row can be promoted.
        reasons.append("protocol_injection_unsupported")
    return reasons


def _validate_v2_attempt(
    attempt: dict[str, Any],
    cell: dict[str, Any],
    requested_revision: str | None,
    required_topology: str | None,
    required_metadata_protocol_version: str,
    protocol_status: str | None,
    frozen_revision: str | None,
) -> dict[str, Any]:
    """Return structured, fail-closed validation for one v2 attempt."""
    record = attempt["record"]
    assert isinstance(record, dict)
    bundle = attempt["bundle_path"]
    reasons: list[str] = []
    required_fields = {
        "protocol_id",
        "protocol_sha256",
        "cell_id",
        "implementation_revision",
        "target_stage",
        "target_condition",
        "observed_stage",
        "stage_boundary_observed",
        "boundary_observed_at",
        "injection_at",
        "child",
        "supervision_result",
        "resources_after_wrapper",
        "outcome",
    }
    for field in sorted(required_fields):
        if field not in record:
            reasons.append(f"required_field_missing:{field}")
    if record.get("schema_version") != "r4-interruption-cell/v2":
        reasons.append("record_schema_not_v2")
    if protocol_status != "frozen_for_execution":
        reasons.append("protocol_not_frozen_for_execution")
    if frozen_revision is None:
        reasons.append("protocol_frozen_revision_not_immutable_clean_commit")

    if record.get("cell_id") != cell["id"]:
        reasons.append("cell_id_does_not_match_protocol")
    if record.get("target_stage") != cell["stage"]:
        reasons.append("target_stage_does_not_match_protocol")
    if record.get("target_condition") != cell["condition"]:
        reasons.append("target_condition_does_not_match_protocol")
    observed = record.get("observed_stage")
    if not isinstance(observed, dict):
        reasons.append("observed_stage_missing")
    else:
        if observed.get("stage") != cell["stage"]:
            reasons.append("observed_stage_does_not_match_target")
        if observed.get("condition") != cell["condition"]:
            reasons.append("observed_condition_does_not_match_target")
        if not isinstance(observed.get("evidence"), dict) or not observed["evidence"]:
            reasons.append("semantic_boundary_evidence_missing")
    if record.get("stage_boundary_observed") is not True:
        reasons.append("semantic_boundary_not_observed")
    boundary_time = _parse_timestamp(record.get("boundary_observed_at"))
    injection_time = _parse_timestamp(record.get("injection_at"))
    if boundary_time is None:
        reasons.append("boundary_timestamp_invalid")
    if injection_time is None:
        reasons.append("injection_timestamp_invalid")
    elif boundary_time is not None and injection_time <= boundary_time:
        reasons.append("injection_not_after_semantic_boundary")

    revision = _safe_revision(record.get("implementation_revision"))
    if revision is None:
        reasons.append("implementation_revision_not_immutable_clean_commit")
    elif requested_revision is None:
        reasons.append("requested_frozen_revision_not_supplied")
    elif revision != requested_revision:
        reasons.append("implementation_revision_does_not_match_requested_revision")
    if frozen_revision is not None and revision != frozen_revision:
        reasons.append("implementation_revision_does_not_match_frozen_protocol_revision")

    manifest_valid, manifest_reasons, manifest_hash = _verify_full_manifest(bundle)
    if not manifest_valid:
        reasons.extend(manifest_reasons)
    if record.get("resources_after_wrapper") != []:
        reasons.append("wrapper_cleanup_inventory_not_empty")
    if record.get("outcome") != "observed_clean":
        reasons.append("driver_outcome_not_observed_clean")
    if "driver_error" in record:
        reasons.append("driver_reported_error")

    receipt, receipt_reasons = _read_receipt(bundle)
    reasons.extend(receipt_reasons)
    child_manifest_valid = False
    child_manifest_hash: str | None = None
    receipt_status: str | None = None
    qualification_metadata_valid = False
    qualification_metadata_protocol: str | None = None
    if receipt is not None:
        receipt_status = receipt.receipt_status
        reasons.extend(_validate_receipt_summary(record, receipt))
        child_bundle, child_reasons = _child_bundle_from_receipt(receipt)
        reasons.extend(child_reasons)
        if child_bundle is not None:
            child_manifest_valid, child_manifest_reasons, child_manifest_hash = (
                _verify_full_manifest(child_bundle)
            )
            if not child_manifest_valid:
                reasons.extend(f"child_{reason}" for reason in child_manifest_reasons)
            try:
                verified = verify_qualified_bundle(
                    project_root=PROJECT_ROOT,
                    bundle=child_bundle,
                    expected_experiment="caldera",
                    require_natural_completion=False,
                )
            except SupervisionEvidenceError:
                reasons.append("supervision_binding_or_receipt_link_invalid")
            else:
                if verified.supervision_id != receipt.supervision_id:
                    reasons.append("supervision_receipt_identity_mismatch")
            (
                qualification_metadata_valid,
                qualification_metadata_protocol,
                metadata_reasons,
            ) = _validate_qualification_metadata(
                child_bundle,
                revision,
                required_topology,
                required_metadata_protocol_version,
            )
            reasons.extend(metadata_reasons)
        if receipt.receipt_status != "bound":
            reasons.append("supervision_receipt_not_bound")
        if receipt.cleanup_completed is not True:
            reasons.append("supervisor_cleanup_inventory_incomplete")
        if receipt.residual_after_termination != []:
            reasons.append("supervisor_residual_inventory_not_empty")
        if receipt.cleanup_error is not None:
            reasons.append("supervisor_cleanup_error_recorded")
        reasons.extend(_validate_injection_semantics(record, cell, receipt))

    disposition, accounting_reasons = _declared_accounting(record)
    reasons.extend(accounting_reasons)
    if disposition != "included":
        # The protocol explicitly says a retry or exclusion remains in accounting and prevents
        # promotion until a later protocol revision defines how it is scientifically handled.
        reasons.append(f"attempt_disposition_not_included:{disposition}")
    reasons = sorted(set(reasons))
    return {
        "bundle": attempt["bundle"],
        "disposition": disposition,
        "reason_codes": reasons,
        "promotion_eligible": not reasons,
        "manifest_valid": manifest_valid,
        "manifest_sha256": manifest_hash,
        "child_manifest_valid": child_manifest_valid,
        "child_manifest_sha256": child_manifest_hash,
        "receipt_status": receipt_status,
        "qualification_metadata_valid": qualification_metadata_valid,
        "qualification_metadata_protocol": qualification_metadata_protocol,
        "implementation_revision": revision,
        "started_at": _safe_timestamp(record.get("started_at")),
    }


def _public_attempt_summary(attempt: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
    """Project accounting to portable fields only; raw commands and host paths stay raw."""
    record = attempt["record"]
    if record is None:
        return {
            "bundle": attempt["bundle"],
            "accounting_disposition": result["classification"],
            "reason_codes": result["reason_codes"],
            "promotion_eligible": False,
        }
    observed = (
        record.get("observed_stage") if isinstance(record.get("observed_stage"), dict) else {}
    )
    revision = _safe_revision(record.get("implementation_revision"))
    return {
        "bundle": attempt["bundle"],
        "accounting_disposition": result["classification"],
        "attempt_disposition": result.get("disposition", "included"),
        "cell_id": (
            _safe_text(record.get("cell_id"))
            if isinstance(record.get("cell_id"), str) and record.get("cell_id", "").startswith("R4")
            else None
        ),
        "protocol_version": _cell_record_version(record),
        "target_stage": _safe_text(record.get("target_stage")),
        "target_condition": _safe_text(record.get("target_condition")),
        "observed_stage": _safe_text(observed.get("stage")),
        "observed_condition": _safe_text(observed.get("condition")),
        "stage_boundary_observed": record.get("stage_boundary_observed") is True,
        "injection": (
            record.get("injection")
            if record.get("injection") in {"sigint", "sigterm", "deadline"}
            else None
        ),
        "outcome": (
            record.get("outcome")
            if record.get("outcome") in {"observed_clean", "incomplete_or_dirty"}
            else None
        ),
        "implementation_revision": revision,
        "started_at": _safe_timestamp(record.get("started_at")),
        "manifest_valid": result.get("manifest_valid", False),
        "child_manifest_valid": result.get("child_manifest_valid", False),
        "receipt_status": result.get("receipt_status"),
        "qualification_metadata_valid": result.get("qualification_metadata_valid", False),
        "qualification_metadata_protocol": result.get("qualification_metadata_protocol"),
        "promotion_eligible": result.get("promotion_eligible", False),
        "reason_codes": result["reason_codes"],
    }


def _public_protocol(protocol: dict[str, Any], protocol_hash: str) -> dict[str, Any]:
    """Emit only the declared protocol contract, never arbitrary raw protocol fields."""
    cells = []
    for cell in protocol.get("cells", []):
        if not isinstance(cell, dict):
            continue
        cells.append(
            {
                "id": _safe_text(cell.get("id")),
                "stage": _safe_text(cell.get("stage")),
                "condition": _safe_text(cell.get("condition")),
                "injection": (
                    cell.get("injection")
                    if cell.get("injection") in {"sigint", "sigterm", "deadline"}
                    else None
                ),
                "property": _safe_text(cell.get("property")),
            }
        )
    return {
        "schema_version": _safe_text(protocol.get("schema_version")),
        "protocol_id": _safe_text(protocol.get("protocol_id")),
        "protocol_sha256": protocol_hash,
        "status": _safe_text(protocol.get("status")),
        "cells": cells,
    }


def _protocol_is_well_formed(
    protocol: dict[str, Any], version: int | None
) -> tuple[bool, list[str]]:
    reasons: list[str] = []
    if version not in {1, 2}:
        reasons.append("protocol_schema_unsupported")
    if not isinstance(protocol.get("protocol_id"), str) or not protocol["protocol_id"]:
        reasons.append("protocol_id_missing")
    cells = protocol.get("cells")
    if not isinstance(cells, list) or not cells:
        reasons.append("protocol_cells_missing")
        return False, reasons
    identifiers: set[str] = set()
    for cell in cells:
        if not isinstance(cell, dict):
            reasons.append("protocol_cell_invalid")
            continue
        identifier = cell.get("id")
        if not isinstance(identifier, str) or not identifier or identifier in identifiers:
            reasons.append("protocol_cell_id_invalid_or_duplicate")
        elif isinstance(identifier, str):
            identifiers.add(identifier)
        if not isinstance(cell.get("stage"), str) or not cell["stage"]:
            reasons.append("protocol_cell_stage_missing")
        if cell.get("injection") not in {"sigint", "sigterm", "deadline"}:
            reasons.append("protocol_cell_injection_invalid")
        if version == 2 and (not isinstance(cell.get("condition"), str) or not cell["condition"]):
            reasons.append("protocol_v2_cell_condition_missing")
    if version == 2:
        status = protocol.get("status")
        if status not in {"predeclared_before_execution", "frozen_for_execution"}:
            reasons.append("protocol_v2_status_invalid")
        if status == "frozen_for_execution" and _safe_revision(protocol.get("frozen_revision")) is None:
            reasons.append("protocol_v2_frozen_revision_missing_or_invalid")
        requirements = protocol.get("execution_requirements")
        if not isinstance(requirements, dict):
            reasons.append("protocol_v2_execution_requirements_missing")
        else:
            if requirements.get("execution_mode") != "supervised":
                reasons.append("protocol_v2_execution_mode_not_supervised")
            if requirements.get("evidence_role") != "qualification":
                reasons.append("protocol_v2_evidence_role_not_qualification")
            if requirements.get("implementation_revision") != "immutable_clean_commit":
                reasons.append("protocol_v2_revision_requirement_missing")
            if requirements.get("manifest_validation") != "required":
                reasons.append("protocol_v2_manifest_requirement_missing")
            if not isinstance(requirements.get("topology"), str) or not requirements["topology"]:
                reasons.append("protocol_v2_topology_missing")
    return not reasons, sorted(set(reasons))


def aggregate(
    *,
    protocol_path: Path,
    raw_root: Path,
    output_root: Path,
    requested_revision: str | None,
) -> tuple[dict[str, Any], dict[str, Any], int]:
    """Aggregate all raw R4 evidence and return public matrix, qualification, and exit code."""
    raw_protocol = protocol_path.read_bytes()
    protocol_value = json.loads(raw_protocol)
    if not isinstance(protocol_value, dict):
        raise ValueError("R4 protocol must be a JSON object")
    protocol = protocol_value
    protocol_hash = hashlib.sha256(raw_protocol).hexdigest()
    version = _protocol_version(protocol)
    protocol_well_formed, protocol_reasons = _protocol_is_well_formed(protocol, version)
    requested_revision_clean = _safe_revision(requested_revision)
    frozen_revision = _safe_revision(protocol.get("frozen_revision")) if version == 2 else None
    protocol_status = protocol.get("status") if isinstance(protocol.get("status"), str) else None
    requested_revision_state = (
        "not_supplied"
        if requested_revision is None
        else (
            "immutable_clean_commit"
            if requested_revision_clean is not None
            else "not_immutable_clean_commit"
        )
    )

    attempts = _read_attempts(raw_root)
    cells = protocol.get("cells") if isinstance(protocol.get("cells"), list) else []
    cells_by_id = {
        cell.get("id"): cell
        for cell in cells
        if isinstance(cell, dict) and isinstance(cell.get("id"), str)
    }
    results: list[dict[str, Any]] = []
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    accounting_blockers: list[str] = []
    requirements = protocol.get("execution_requirements")
    required_topology = requirements.get("topology") if isinstance(requirements, dict) else None
    required_metadata_protocol_version = (
        requirements.get("qualification_metadata_protocol_version", "autosut-qualification/v1")
        if isinstance(requirements, dict)
        else "autosut-qualification/v1"
    )

    for attempt in attempts:
        classification, classification_reasons = _classify_attempt(
            attempt, protocol, protocol_hash, version or 0
        )
        record = attempt["record"]
        result: dict[str, Any] = {
            "classification": classification,
            "reason_codes": classification_reasons,
            "promotion_eligible": False,
            "manifest_valid": False,
            "child_manifest_valid": False,
            "receipt_status": None,
            "implementation_revision": None,
        }
        if isinstance(record, dict):
            disposition, disposition_reasons = _declared_accounting(record)
            result["disposition"] = disposition
            result["reason_codes"] = sorted(set([*result["reason_codes"], *disposition_reasons]))
        if classification == "selected_protocol" and isinstance(record, dict):
            cell_id = record.get("cell_id")
            cell = cells_by_id.get(cell_id) if isinstance(cell_id, str) else None
            if version != 2:
                result["classification"] = "historical_development"
                result["reason_codes"] = ["selected_protocol_v1_historical_development"]
            elif cell is None:
                result["classification"] = "selected_protocol_malformed"
                result["reason_codes"] = ["cell_id_not_declared_by_protocol"]
                accounting_blockers.append("selected_protocol_cell_id_not_declared")
            else:
                result.update(
                    _validate_v2_attempt(
                        attempt,
                        cell,
                        requested_revision_clean,
                        required_topology,
                        required_metadata_protocol_version,
                        protocol_status,
                        frozen_revision,
                    )
                )
                grouped[cell_id].append(result)
        elif classification == "selected_protocol_mismatch":
            accounting_blockers.append("selected_protocol_mismatch")
        elif classification == "unclassifiable":
            accounting_blockers.append("unclassifiable_raw_attempt")
        results.append(result)

    rows: list[dict[str, Any]] = []
    all_cells_eligible = version == 2 and protocol_well_formed
    for cell in cells:
        if not isinstance(cell, dict) or not isinstance(cell.get("id"), str):
            continue
        cell_id = cell["id"]
        cell_attempts = sorted(
            grouped.get(cell_id, []),
            key=lambda item: (item.get("started_at") or "", item["bundle"]),
        )
        if version == 1:
            row_status = "historical_development"
            row_reasons = ["protocol_v1_historical_development"]
        elif not cell_attempts:
            row_status = "missing"
            row_reasons = ["predeclared_cell_not_observed"]
            all_cells_eligible = False
        else:
            noneligible = [item for item in cell_attempts if not item["promotion_eligible"]]
            if noneligible:
                row_status = "observed_unqualified"
                row_reasons = sorted(
                    {reason for item in noneligible for reason in item["reason_codes"]}
                )
                all_cells_eligible = False
            else:
                row_status = "observed_qualified"
                row_reasons = []
        rows.append(
            {
                "id": _safe_text(cell_id) or "",
                "stage": _safe_text(cell.get("stage")) or "",
                "condition": _safe_text(cell.get("condition")) or "",
                "injection": (
                    cell.get("injection", "")
                    if cell.get("injection") in {"sigint", "sigterm", "deadline"}
                    else ""
                ),
                "property": _safe_text(cell.get("property")) or "",
                "status": row_status,
                "attempt_count": len(cell_attempts),
                "qualifying_attempt_count": sum(
                    item["promotion_eligible"] for item in cell_attempts
                ),
                "nonqualifying_attempt_count": sum(
                    not item["promotion_eligible"] for item in cell_attempts
                ),
                "retry_attempt_count": sum(
                    item.get("disposition") == "retry" for item in cell_attempts
                ),
                "excluded_attempt_count": sum(
                    item.get("disposition") == "excluded" for item in cell_attempts
                ),
                "bundles": [item["bundle"] for item in cell_attempts],
                "implementation_revisions": sorted(
                    {
                        item["implementation_revision"]
                        for item in cell_attempts
                        if item["implementation_revision"]
                    }
                ),
                "reason_codes": row_reasons,
            }
        )

    classifications = Counter(result["classification"] for result in results)
    selected_v2_attempt_count = sum(
        classifications[classification]
        for classification in (
            "selected_protocol",
            "selected_protocol_malformed",
            "selected_protocol_mismatch",
        )
    )
    invalid_v2_attempts = [
        result
        for result in results
        if result["classification"]
        in {"selected_protocol", "selected_protocol_malformed", "selected_protocol_mismatch"}
        and not result["promotion_eligible"]
    ]
    observed_revisions = sorted(
        {
            result["implementation_revision"]
            for result in results
            if result.get("implementation_revision")
        }
    )
    all_attempts_accounted = not accounting_blockers
    qualification_reasons = list(protocol_reasons)
    if version != 2:
        qualification_reasons.append("protocol_version_is_historical_not_qualifying")
    elif protocol_status != "frozen_for_execution":
        qualification_reasons.append("protocol_not_frozen_for_execution")
    elif frozen_revision is None:
        qualification_reasons.append("protocol_frozen_revision_not_immutable_clean_commit")
    elif requested_revision_clean is not None and requested_revision_clean != frozen_revision:
        qualification_reasons.append("requested_revision_does_not_match_frozen_protocol_revision")
    elif selected_v2_attempt_count == 0:
        qualification_reasons.append("predeclared_protocol_has_no_v2_attempts")
    if requested_revision is None:
        qualification_reasons.append("requested_frozen_revision_not_supplied")
    elif requested_revision_clean is None:
        qualification_reasons.append("requested_revision_not_immutable_clean_commit")
    if not all_attempts_accounted:
        qualification_reasons.extend(sorted(set(accounting_blockers)))
    if not all_cells_eligible:
        qualification_reasons.append("not_every_predeclared_cell_is_qualification_eligible")
    if invalid_v2_attempts:
        qualification_reasons.append("one_or_more_v2_attempts_failed_qualification")
    if requested_revision_clean is not None and observed_revisions != [requested_revision_clean]:
        qualification_reasons.append("observed_revisions_do_not_equal_requested_revision")
    qualified = not qualification_reasons

    if qualified:
        matrix_status = "matrix_complete_qualified"
    elif version == 1:
        matrix_status = "historical_development"
    elif selected_v2_attempt_count == 0 and protocol_status == "predeclared_before_execution":
        matrix_status = "predeclared_nonexecuted"
    elif selected_v2_attempt_count == 0:
        matrix_status = "qualification_in_progress"
    elif any(row["status"] == "missing" for row in rows):
        matrix_status = "qualification_in_progress"
    else:
        matrix_status = "matrix_complete_unqualified"

    public_attempts = [
        _public_attempt_summary(attempt, result) for attempt, result in zip(attempts, results)
    ]
    matrix = {
        "schema_version": "r4-interruption-matrix/v2",
        "protocol": _public_protocol(protocol, protocol_hash),
        "rows": rows,
        "attempts": public_attempts,
        "accounting": {
            "total_raw_entries": len(attempts),
            "classification_counts": dict(sorted(classifications.items())),
            "selected_v2_attempt_count": selected_v2_attempt_count,
            "all_attempts_accounted": all_attempts_accounted,
            "accounting_blockers": sorted(set(accounting_blockers)),
            "policy": (
                "Every v2 attempt is retained. A retry or exclusion remains visible and prevents "
                "promotion under this protocol; v1 material is historical development evidence."
            ),
        },
    }
    qualification = {
        "schema_version": "r4-qualification/v2",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "protocol_id": _safe_text(protocol.get("protocol_id")),
        "protocol_schema_version": _safe_text(protocol.get("schema_version")),
        "protocol_sha256": protocol_hash,
        "requested_revision": requested_revision_clean,
        "requested_revision_state": requested_revision_state,
        "observed_revisions": observed_revisions,
        "all_predeclared_cells_qualification_eligible": all_cells_eligible,
        "all_attempts_accounted": all_attempts_accounted,
        "all_cells_on_requested_frozen_revision": (
            requested_revision_clean is not None
            and observed_revisions == [requested_revision_clean]
        ),
        "qualified": qualified,
        "matrix_status": matrix_status,
        "qualification_result": "qualified" if qualified else "not_qualified",
        "historical_development_attempt_count": classifications.get("historical_development", 0),
        "protocol_execution_state": (
            "historical_development"
            if version == 1
            else (
                "predeclared_nonexecuted"
                if selected_v2_attempt_count == 0 and protocol_status == "predeclared_before_execution"
                else "frozen_nonexecuted" if selected_v2_attempt_count == 0 else "attempted"
            )
        ),
        "non_promotion_reason_codes": sorted(set(qualification_reasons)),
    }

    output_root.mkdir(parents=True, exist_ok=True)
    (output_root / "R4_interruption_matrix.json").write_text(
        json.dumps(matrix, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    fieldnames = [
        "id",
        "stage",
        "condition",
        "injection",
        "property",
        "status",
        "attempt_count",
        "qualifying_attempt_count",
        "nonqualifying_attempt_count",
        "retry_attempt_count",
        "excluded_attempt_count",
        "bundles",
        "implementation_revisions",
        "reason_codes",
    ]
    with (output_root / "R4_interruption_matrix.csv").open(
        "w", newline="", encoding="utf-8"
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            csv_row = dict(row)
            for field in ("bundles", "implementation_revisions", "reason_codes"):
                csv_row[field] = ";".join(csv_row[field])
            writer.writerow(csv_row)
    (output_root / "R4_qualification.json").write_text(
        json.dumps(qualification, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return matrix, qualification, 0 if qualified else 2


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--protocol", type=Path, default=DEFAULT_PROTOCOL)
    parser.add_argument("--raw-root", type=Path, default=RAW_ROOT)
    parser.add_argument("--output-root", type=Path, default=OUTPUT_ROOT)
    parser.add_argument(
        "--revision",
        help="immutable clean commit revision required for v2 qualification; omit for accounting only",
    )
    args = parser.parse_args()
    try:
        _matrix, qualification, exit_code = aggregate(
            protocol_path=args.protocol,
            raw_root=args.raw_root,
            output_root=args.output_root,
            requested_revision=args.revision,
        )
    except (OSError, ValueError, json.JSONDecodeError) as failure:
        # Do not write a partial aggregate with host-specific parser diagnostics.
        print(
            f"[r4-aggregate] unable to aggregate protocol: {type(failure).__name__}",
            file=sys.stderr,
        )
        return 2
    print(
        f"[r4-aggregate] matrix_status={qualification['matrix_status']} "
        f"qualification_result={qualification['qualification_result']} "
        f"historical_development={qualification['historical_development_attempt_count']}"
    )
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
