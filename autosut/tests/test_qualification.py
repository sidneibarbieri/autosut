"""A backend earns reproducible only from enough real clean bundles plus a recovered failure.

The summary is computed from bundle contents, so fewer clean runs, or a failure run that did not
reach clean, yields a lower level. The derived capability record carries the clean-run count the
level requires.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from infrastructure.capability import CapabilityLevel  # noqa: E402
from infrastructure.qualification import (  # noqa: E402
    EligibilityExclusionReason,
    EvidenceEligibilityPolicy,
    ExecutionMode,
    capability_record,
    prepare_supervised_qualification_metadata,
    summarize,
    supervised_final_policy,
    write_qualification_metadata,
)
from infrastructure.run_context import seal_directory  # noqa: E402
from infrastructure.supervision_evidence import (  # noqa: E402
    bind_child_run,
    build_receipt,
    write_json_atomic,
)

_REVISION = "rev-abc123"


def _direct_final_policy(revision: str = _REVISION) -> EvidenceEligibilityPolicy:
    """A valid final protocol need not be supervised when its property does not require it."""

    return EvidenceEligibilityPolicy(
        name="unit-direct-final/v1",
        final_qualification=True,
        required_execution_mode=ExecutionMode.DIRECT,
        required_revision=revision,
    )


def _bundle(tmp_path, label, final_state, seconds, revision=_REVISION):
    bundle = tmp_path / f"0.c0010_{label}"
    bundle.mkdir()
    (bundle / "lifecycle-result.json").write_text(
        json.dumps(
            {
                "label": label,
                "run_id": f"{label}-id",
                "final_state": final_state,
                "total_seconds": seconds,
                "implementation_revision": revision,
                "evidence_dir": f"release/evidence/0.c0010_{label}",
            }
        ),
        encoding="utf-8",
    )
    (bundle / "manifest.json").write_text(json.dumps({"run_id": f"{label}-id"}), encoding="utf-8")
    return bundle


def _supervised_bundle(tmp_path, revision: str):
    """Build a minimal sealed lifecycle bundle linked to a parent-owned receipt."""

    project_root = tmp_path / "artifact"
    bundle = project_root / "release" / "evidence" / "qualified-run"
    bundle.mkdir(parents=True)
    receipt_path = project_root / "release" / "evidence" / "raw" / "supervision" / "s1.json"
    handoff_path = receipt_path.with_name("s1.handoff.json")
    (bundle / "lifecycle-result.json").write_text(
        json.dumps(
            {
                "label": "qualified",
                "run_id": "qualified-run",
                "final_state": "clean",
                "total_seconds": 10.0,
                "implementation_revision": revision,
                "evidence_dir": "release/evidence/qualified-run",
            }
        ),
        encoding="utf-8",
    )
    (bundle / "qualification-metadata.json").write_text(
        json.dumps(
            {
                "schema_version": "autosut-evidence-metadata/v1",
                "protocol_version": "autosut-qualification/v1",
                "evidence_role": "qualification",
                "execution_mode": "supervised",
                "implementation_revision": revision,
            }
        ),
        encoding="utf-8",
    )
    binding = bind_child_run(
        project_root=project_root,
        run_dir=bundle,
        run_id="qualified-run",
        experiment="lifecycle",
        entrypoint="run_lifecycle.py",
        supervision_id="s1",
        receipt_path=receipt_path,
        handoff_path=handoff_path,
    )
    seal_directory(bundle, "qualified-run", binding.created_at)
    receipt = build_receipt(
        project_root=project_root,
        supervision_id="s1",
        experiment="lifecycle",
        entrypoint="run_lifecycle.py",
        label="qualified",
        command=["python", "run_lifecycle.py"],
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
        },
        handoff_path=handoff_path,
    )
    write_json_atomic(receipt_path, receipt)
    return project_root, bundle


def test_five_clean_runs_on_the_current_revision_reach_reproducible(tmp_path):
    bundles = [_bundle(tmp_path, f"run{i}", "clean", 30.0 + i) for i in range(1, 6)]
    bundles.append(_bundle(tmp_path, "failure_injection", "failed_clean", 2.0))
    summary = summarize("docker", "0.c0010", bundles, _REVISION, policy=_direct_final_policy())
    assert summary.clean_runs == 5
    assert summary.failure_recovery_reached_clean is True
    assert summary.capability_level is CapabilityLevel.REPRODUCIBLE
    assert not capability_record(summary, "lifecycle.docker_sut").may_support_a_claim


def test_a_set_on_a_different_revision_does_not_reach_reproducible(tmp_path):
    bundles = [_bundle(tmp_path, f"run{i}", "clean", 30.0 + i) for i in range(1, 6)]
    bundles.append(_bundle(tmp_path, "failure_injection", "failed_clean", 2.0))
    summary = summarize("docker", "0.c0010", bundles, "a-different-revision")
    assert summary.clean_runs == 5
    assert summary.capability_level is CapabilityLevel.END_TO_END_VALIDATED


def test_four_clean_runs_do_not_reach_reproducible(tmp_path):
    bundles = [_bundle(tmp_path, f"run{i}", "clean", 30.0) for i in range(1, 5)]
    bundles.append(_bundle(tmp_path, "failure_injection", "failed_clean", 2.0))
    summary = summarize("docker", "0.c0010", bundles, _REVISION)
    assert summary.clean_runs == 4
    assert summary.capability_level is CapabilityLevel.END_TO_END_VALIDATED


def test_a_failure_run_that_stayed_dirty_blocks_reproducible(tmp_path):
    bundles = [_bundle(tmp_path, f"run{i}", "clean", 30.0) for i in range(1, 6)]
    bundles.append(_bundle(tmp_path, "failure_injection", "failed_dirty", 2.0))
    summary = summarize("docker", "0.c0010", bundles, _REVISION)
    assert summary.clean_runs == 5
    assert summary.failure_recovery_reached_clean is False
    assert summary.capability_level is CapabilityLevel.END_TO_END_VALIDATED


def test_every_run_records_a_verifiable_manifest_hash(tmp_path):
    bundles = [_bundle(tmp_path, "run1", "clean", 30.0)]
    summary = summarize("docker", "0.c0010", bundles, _REVISION)
    assert len(summary.runs[0].bundle_manifest_sha256) == 64


def test_historical_direct_bundle_is_retained_but_excluded_from_supervised_final_policy(tmp_path):
    bundle = _bundle(tmp_path, "historical", "clean", 30.0, revision="a" * 40)
    policy = supervised_final_policy(
        name="supervised-lifecycle-final/v1",
        expected_experiment="lifecycle",
        required_revision="a" * 40,
    )

    summary = summarize(
        "docker",
        "0.c0010",
        [bundle],
        "a" * 40,
        policy=policy,
        project_root=tmp_path,
    )

    assert summary.total_runs == 1
    assert summary.observed_clean_runs == 1
    assert summary.eligible_runs == 0
    assert summary.excluded_runs == 1
    record = summary.runs[0]
    assert record.final_state == "clean"
    assert record.eligibility.eligible is False
    assert EligibilityExclusionReason.UNSUPERVISED_FOR_SUPERVISED_PROTOCOL in (
        record.eligibility.exclusion_reasons
    )
    assert EligibilityExclusionReason.MISSING_EVIDENCE_METADATA in (
        record.eligibility.exclusion_reasons
    )


def test_direct_final_policy_does_not_require_supervision_globally(tmp_path):
    bundle = _bundle(tmp_path, "direct", "clean", 30.0)
    policy = _direct_final_policy()

    summary = summarize("docker", "0.c0010", [bundle], _REVISION, policy=policy)

    assert summary.eligible_runs == 1
    assert summary.runs[0].eligibility.observed_execution_mode is ExecutionMode.DIRECT
    assert summary.runs[0].eligibility.exclusion_reasons == []


def test_supervised_final_policy_accepts_a_receipt_bound_bundle(tmp_path):
    revision = "c" * 40
    project_root, bundle = _supervised_bundle(tmp_path, revision)
    policy = supervised_final_policy(
        name="supervised-lifecycle-final/v1",
        expected_experiment="lifecycle",
        required_revision=revision,
    )

    summary = summarize(
        "docker",
        "0.c0010",
        [bundle],
        revision,
        policy=policy,
        project_root=project_root,
    )

    assert summary.eligible_runs == 1
    assert summary.clean_runs == 1
    assert summary.runs[0].eligibility.observed_execution_mode is ExecutionMode.SUPERVISED
    assert summary.runs[0].eligibility.supervision_id == "s1"
    assert summary.runs[0].eligibility.exclusion_reasons == []


def test_manifest_validation_is_an_independent_policy_axis(tmp_path):
    bundle = _bundle(tmp_path, "unsealed", "clean", 30.0)
    policy = EvidenceEligibilityPolicy(
        name="direct-final-with-seal/v1",
        final_qualification=True,
        required_execution_mode=ExecutionMode.DIRECT,
        required_revision=_REVISION,
        require_manifest_validation=True,
    )

    summary = summarize("docker", "0.c0010", [bundle], _REVISION, policy=policy)

    assert summary.eligible_runs == 0
    assert summary.runs[0].eligibility.manifest_valid is False
    assert EligibilityExclusionReason.MANIFEST_INVALID in (
        summary.runs[0].eligibility.exclusion_reasons
    )


def test_qualification_metadata_requires_explicit_supervised_clean_commit(tmp_path):
    revision = "f" * 40
    metadata = prepare_supervised_qualification_metadata(
        protocol_version="autosut-qualification/v1",
        required_revision=revision,
        topology="single_host",
        observed_revision=revision,
        supervised=True,
    )
    path = write_qualification_metadata(tmp_path, metadata)
    assert path is not None
    stored = json.loads(path.read_text(encoding="utf-8"))
    assert stored["evidence_role"] == "qualification"
    assert stored["execution_mode"] == "supervised"
    assert stored["implementation_revision"] == revision


def test_partial_or_dirty_qualification_declaration_is_rejected():
    try:
        prepare_supervised_qualification_metadata(
            protocol_version="autosut-qualification/v1",
            required_revision="f" * 40,
            topology=None,
            observed_revision="f" * 40,
            supervised=True,
        )
    except ValueError as error:
        assert "supplied together" in str(error)
    else:
        raise AssertionError("partial qualification declaration must fail")

    try:
        prepare_supervised_qualification_metadata(
            protocol_version="autosut-qualification/v1",
            required_revision="f" * 40,
            topology="single_host",
            observed_revision=("f" * 40) + "+tree-deadbeef",
            supervised=True,
        )
    except ValueError as error:
        assert "clean source revision" in str(error)
    else:
        raise AssertionError("dirty source revision must fail")
