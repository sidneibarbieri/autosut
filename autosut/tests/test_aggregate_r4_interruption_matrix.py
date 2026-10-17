"""R4 aggregation must retain history while failing closed for v2 qualification."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = PROJECT_ROOT / "scripts"
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from infrastructure.run_context import seal_directory  # noqa: E402
from infrastructure.supervision_evidence import (  # noqa: E402
    bind_child_run,
    build_receipt,
    write_json_atomic,
)

REVISION = "a" * 40


def _module():
    spec = importlib.util.spec_from_file_location(
        "aggregate_r4_interruption_matrix", SCRIPTS / "aggregate_r4_interruption_matrix.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _protocol(project_root: Path) -> tuple[Path, dict, str]:
    protocol = {
        "schema_version": "r4-interruption-protocol/v2",
        "protocol_id": "R4-test-v2",
        "status": "frozen_for_execution",
        "frozen_revision": REVISION,
        "execution_requirements": {
            "execution_mode": "supervised",
            "evidence_role": "qualification",
            "implementation_revision": "immutable_clean_commit",
            "topology": "isolated_caldera_docker",
            "manifest_validation": "required",
        },
        "cells": [
            {
                "id": "R4V2-test",
                "stage": "enroll_agent",
                "condition": "enrollment_poll_active",
                "injection": "sigterm",
                "property": "A supervised signal arrives after the declared semantic boundary.",
            }
        ],
    }
    path = project_root / "release" / "experiments" / "protocol.json"
    _write_json(path, protocol)
    return path, protocol, hashlib.sha256(path.read_bytes()).hexdigest()


def _write_qualified_v2_attempt(
    project_root: Path,
    protocol: dict,
    protocol_hash: str,
    *,
    attempt_accounting: dict | None = None,
) -> Path:
    raw_root = project_root / "release" / "evidence" / "raw" / "r4-interruption-matrix"
    outer = raw_root / "r4v2-sigterm"
    outer.mkdir(parents=True)
    child = project_root / "release" / "evidence" / "caldera" / "child-run"
    child.mkdir(parents=True)
    receipt_path = outer / "supervision-receipt.json"
    binding = bind_child_run(
        project_root=project_root,
        run_dir=child,
        run_id="child-run",
        experiment="caldera",
        entrypoint="run_caldera_experiment.py",
        supervision_id="supervision-test",
        receipt_path=receipt_path,
        handoff_path=outer / "supervision-receipt.handoff.json",
    )
    _write_json(
        child / "qualification-metadata.json",
        {
            "schema_version": "autosut-evidence-metadata/v1",
            "protocol_version": "autosut-qualification/v1",
            "evidence_role": "qualification",
            "execution_mode": "supervised",
            "topology": "isolated_caldera_docker",
            "implementation_revision": REVISION,
        },
    )
    (child / "result.json").write_text('{"result":"interrupted-cleanly"}\n', encoding="utf-8")
    seal_directory(child, "child-run", binding.created_at)
    receipt = build_receipt(
        project_root=project_root,
        supervision_id="supervision-test",
        experiment="caldera",
        entrypoint="run_caldera_experiment.py",
        label="r4v2-sigterm",
        command=["python", "run_caldera_experiment.py"],
        supervisor_pid=101,
        started_at="2026-08-09T00:00:00+00:00",
        outcome={
            "pid": 102,
            "pgid": 102,
            "completed_naturally": True,
            "exit_code": 2,
            "escalation": [],
            "grace_deadline_exceeded": False,
            "residual_after_termination": [],
            "cleanup_completed": True,
            "cleanup_error": None,
        },
        handoff_path=outer / "supervision-receipt.handoff.json",
    )
    write_json_atomic(receipt_path, receipt)
    cell = protocol["cells"][0]
    record = {
        "schema_version": "r4-interruption-cell/v2",
        "protocol_id": protocol["protocol_id"],
        "protocol_version": protocol["schema_version"],
        "protocol_sha256": protocol_hash,
        "cell_id": cell["id"],
        "implementation_revision": REVISION,
        "target_stage": cell["stage"],
        "target_condition": cell["condition"],
        "observed_stage": {
            "stage": cell["stage"],
            "condition": cell["condition"],
            "evidence": {"caldera_poll": "started"},
        },
        "stage_boundary_observed": True,
        "boundary_observed_at": "2026-08-09T00:00:01+00:00",
        "injection_at": "2026-08-09T00:00:02+00:00",
        "child": {"pid": 102, "pgid": 102},
        "injection": "sigterm",
        "signal_sent": "SIGTERM",
        "expected_interruption_exit": True,
        "wrapper_exit_code": 2,
        "resources_after_wrapper": [],
        "outcome": "observed_clean",
        "started_at": "2026-08-09T00:00:00+00:00",
        "supervision_result": {
            "record_present": True,
            "completed_naturally": True,
            "exit_code": 2,
            "signals_sent": [],
            "grace_expired": False,
            "residual_inventory": [],
            "cleanup_completed": True,
            "receipt_status": "bound",
        },
    }
    if attempt_accounting is not None:
        record["attempt_accounting"] = attempt_accounting
    _write_json(outer / "matrix-cell.json", record)
    seal_directory(outer, outer.name, record["started_at"])
    return outer


def _run(tmp_path: Path, *, attempt_accounting: dict | None = None):
    project_root = tmp_path / "artifact"
    project_root.mkdir()
    protocol_path, protocol, protocol_hash = _protocol(project_root)
    raw_attempt = _write_qualified_v2_attempt(
        project_root, protocol, protocol_hash, attempt_accounting=attempt_accounting
    )
    module = _module()
    module.PROJECT_ROOT = project_root
    matrix, qualification, code = module.aggregate(
        protocol_path=protocol_path,
        raw_root=project_root / "release" / "evidence" / "raw" / "r4-interruption-matrix",
        output_root=project_root / "out",
        requested_revision=REVISION,
    )
    return project_root, raw_attempt, matrix, qualification, code


def test_v2_qualification_requires_full_bound_chain_but_keeps_v1_history(tmp_path):
    project_root, _attempt, matrix, qualification, code = _run(tmp_path)
    legacy = project_root / "release" / "evidence" / "raw" / "r4-interruption-matrix" / "legacy-v1"
    legacy.mkdir()
    _write_json(
        legacy / "matrix-cell.json",
        {
            "schema_version": "r4-interruption-cell/v1",
            "command": ["/Users/example/private-command"],
            "stage": "materialize_sut",
            "injection": "sigterm",
        },
    )

    module = _module()
    module.PROJECT_ROOT = project_root
    matrix, qualification, code = module.aggregate(
        protocol_path=project_root / "release" / "experiments" / "protocol.json",
        raw_root=project_root / "release" / "evidence" / "raw" / "r4-interruption-matrix",
        output_root=project_root / "out-with-history",
        requested_revision=REVISION,
    )

    assert code == 0
    assert qualification["qualified"] is True
    assert qualification["historical_development_attempt_count"] == 1
    assert matrix["rows"][0]["status"] == "observed_qualified"
    serialized = json.dumps(matrix)
    assert "/Users/example" not in serialized
    assert "protocol_v1_historical_development" in serialized


def test_extra_file_after_manifest_and_retry_metadata_both_prevent_promotion(tmp_path):
    _project_root, attempt, _matrix, _qualification, _code = _run(
        tmp_path,
        attempt_accounting={"disposition": "retry", "reason_codes": ["transport_timeout"]},
    )
    # This file is deliberately not resealed. A full-manifest validator must notice it instead of
    # trusting a previous manifest or a driver-provided green outcome.
    (attempt / "post-seal-extra.txt").write_text("unexpected\n", encoding="utf-8")

    module = _module()
    module.PROJECT_ROOT = _project_root
    matrix, qualification, code = module.aggregate(
        protocol_path=_project_root / "release" / "experiments" / "protocol.json",
        raw_root=_project_root / "release" / "evidence" / "raw" / "r4-interruption-matrix",
        output_root=_project_root / "out-failed",
        requested_revision=REVISION,
    )

    assert code == 2
    assert qualification["qualified"] is False
    reasons = matrix["rows"][0]["reason_codes"]
    assert "manifest_not_full_directory_seal" in reasons
    assert "attempt_disposition_not_included:retry" in reasons
    public_attempt = matrix["attempts"][0]
    assert public_attempt["attempt_disposition"] == "retry"
    assert public_attempt["promotion_eligible"] is False


def test_injection_before_boundary_is_not_qualification_evidence(tmp_path):
    project_root, attempt, _matrix, _qualification, _code = _run(tmp_path)
    record_path = attempt / "matrix-cell.json"
    record = json.loads(record_path.read_text(encoding="utf-8"))
    record["injection_at"] = "2026-08-09T00:00:01+00:00"
    _write_json(record_path, record)
    seal_directory(attempt, attempt.name, record["started_at"])

    module = _module()
    module.PROJECT_ROOT = project_root
    matrix, qualification, code = module.aggregate(
        protocol_path=project_root / "release" / "experiments" / "protocol.json",
        raw_root=project_root / "release" / "evidence" / "raw" / "r4-interruption-matrix",
        output_root=project_root / "out-boundary-failed",
        requested_revision=REVISION,
    )

    assert code == 2
    assert qualification["qualified"] is False
    assert "injection_not_after_semantic_boundary" in matrix["rows"][0]["reason_codes"]
