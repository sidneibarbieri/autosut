"""The supervisor-to-bundle linkage must be explicit, sealed, and fail closed."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from infrastructure.run_context import seal_directory  # noqa: E402
from infrastructure.supervision_evidence import (  # noqa: E402
    SupervisionEvidenceError,
    bind_child_run,
    build_receipt,
    verify_qualified_bundle,
    write_json_atomic,
)


def _bound_bundle(tmp_path: Path) -> tuple[Path, Path]:
    project_root = tmp_path / "artifact"
    bundle = project_root / "release" / "evidence" / "run-1"
    bundle.mkdir(parents=True)
    receipt_path = project_root / "release" / "evidence" / "raw" / "supervision" / "s1.json"
    handoff_path = receipt_path.with_name("s1.handoff.json")
    binding = bind_child_run(
        project_root=project_root,
        run_dir=bundle,
        run_id="run-1",
        experiment="caldera",
        entrypoint="run_caldera_experiment.py",
        supervision_id="s1",
        receipt_path=receipt_path,
        handoff_path=handoff_path,
    )
    (bundle / "result.json").write_text('{"state":"clean"}\n', encoding="utf-8")
    seal_directory(bundle, "run-1", binding.created_at)
    receipt = build_receipt(
        project_root=project_root,
        supervision_id="s1",
        experiment="caldera",
        entrypoint="run_caldera_experiment.py",
        label="qualified",
        command=["python", "run_caldera_experiment.py"],
        supervisor_pid=101,
        started_at=binding.created_at,
        outcome={
            "pid": 102,
            "pgid": 102,
            "completed_naturally": True,
            "exit_code": 0,
            "escalation": [],
            "grace_deadline_exceeded": False,
            "residual_after_termination": [],
            "cleanup_completed": True,
            "cleanup_error": None,
            "supervisor_interruption": None,
        },
        handoff_path=handoff_path,
    )
    write_json_atomic(receipt_path, receipt)
    return project_root, bundle


def test_bound_receipt_verifies_the_exact_child_manifest(tmp_path):
    project_root, bundle = _bound_bundle(tmp_path)

    receipt = verify_qualified_bundle(
        project_root=project_root, bundle=bundle, expected_experiment="caldera"
    )

    assert receipt.receipt_status == "bound"
    assert receipt.handoff is not None
    assert receipt.handoff.run_id == "run-1"


def test_direct_bundle_is_not_eligible_for_a_supervised_qualification(tmp_path):
    project_root = tmp_path / "artifact"
    bundle = project_root / "release" / "evidence" / "direct"
    bundle.mkdir(parents=True)
    (bundle / "result.json").write_text("direct\n", encoding="utf-8")
    seal_directory(bundle, "direct", "2026-08-09T00:00:00+00:00")

    with pytest.raises(SupervisionEvidenceError, match="supervision binding"):
        verify_qualified_bundle(
            project_root=project_root, bundle=bundle, expected_experiment="caldera"
        )


def test_receipt_rejects_a_bundle_changed_after_its_manifest_was_bound(tmp_path):
    project_root, bundle = _bound_bundle(tmp_path)
    (bundle / "result.json").write_text('{"state":"tampered"}\n', encoding="utf-8")

    with pytest.raises(SupervisionEvidenceError, match="manifest|bundle content"):
        verify_qualified_bundle(
            project_root=project_root, bundle=bundle, expected_experiment="caldera"
        )
