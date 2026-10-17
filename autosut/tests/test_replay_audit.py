import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from evaluation.replay_audit import audit_replay_report  # noqa: E402


def _fixture(root: Path) -> Path:
    run = root / "release/evidence/test"
    run.mkdir(parents=True)
    (run / "effect.log").write_text("recorded effect\n", encoding="utf-8")
    (run / "marker.log").write_text("concept only\n", encoding="utf-8")
    manifest = {
        "campaign_id": "test",
        "teardown_clean": True,
        "techniques": [
            {
                "status": "success",
                "executed_mode": "real_controlled",
                "executed_fidelity": "inspired",
                "evidence_files": ["effect.log"],
            },
            {
                "status": "success",
                "executed_mode": "naive_simulated",
                "executed_fidelity": "inspired",
                "evidence_files": ["marker.log"],
            },
        ],
    }
    (run / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (run / "provenance.json").write_text('{"git_commit": "legacy"}', encoding="utf-8")
    report = root / "report.json"
    report.write_text(json.dumps([{
        "campaign_id": "test", "status": "PASS", "total": 2, "successful": 2,
        "evidence_backed_successful": 2, "marker_only_successful": 0,
        "caldera_driven_successful": 0, "final_namespace_clean": True,
        "elapsed_seconds": 1.5, "evidence_manifest": "release/evidence/test/manifest.json",
        "notes": "must not be copied into the public audit",
    }]), encoding="utf-8")
    return report


def test_audit_recomputes_counts_without_promoting_legacy_pass(tmp_path):
    audit = audit_replay_report(_fixture(tmp_path), tmp_path)
    record = audit.records[0]

    assert record.reported_status == "PASS"
    assert record.manifest_counts.evidence_backed_successful == 1
    assert record.manifest_counts.marker_only_successful == 1
    assert record.manifest_counts.inspired_execution_steps == 1
    assert record.manifest_counts.steps_with_all_references_present == 1
    assert "count_mismatch:evidence_backed_successful" in record.issues
    assert "implementation_revision_not_recorded" in record.issues
    assert record.recorded_revision is None
    assert "must not be copied" not in audit.model_dump_json()


def test_missing_files_do_not_disappear_from_the_denominator(tmp_path):
    report = _fixture(tmp_path)
    (tmp_path / "release/evidence/test/effect.log").unlink()

    record = audit_replay_report(report, tmp_path).records[0]

    assert record.reported_total == 2
    assert record.manifest_counts.evidence_backed_successful == 1
    assert record.manifest_counts.steps_with_all_references_present == 0
    assert "missing_execution_references" in record.issues
    assert any(item.sha256 is None for item in record.files)


def test_missing_manifest_keeps_reported_counts_and_unknown_observations(tmp_path):
    report = _fixture(tmp_path)
    (tmp_path / "release/evidence/test/manifest.json").unlink()

    record = audit_replay_report(report, tmp_path).records[0]

    assert record.manifest_counts is None
    assert record.reported_total == 2
    assert "missing_manifest" in record.issues


@pytest.mark.parametrize("reference", ["../outside.log", "/tmp/outside.log"])
def test_evidence_reference_cannot_escape_run_directory(tmp_path, reference):
    report = _fixture(tmp_path)
    manifest_path = tmp_path / "release/evidence/test/manifest.json"
    manifest = json.loads(manifest_path.read_text("utf-8"))
    manifest["techniques"][0]["evidence_files"] = [reference]
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ValueError, match="evidence path"):
        audit_replay_report(report, tmp_path)


def test_duplicate_rows_cannot_inflate_campaign_count(tmp_path):
    report = _fixture(tmp_path)
    rows = json.loads(report.read_text("utf-8"))
    report.write_text(json.dumps(rows + rows), encoding="utf-8")

    with pytest.raises(ValueError, match="duplicate campaign"):
        audit_replay_report(report, tmp_path)
