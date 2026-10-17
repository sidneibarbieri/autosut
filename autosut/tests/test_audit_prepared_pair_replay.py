"""A replay audit must reject a changed receipt or missing observation."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = PROJECT_ROOT / "scripts/audit_prepared_pair_replay.py"
PAIR = PROJECT_ROOT / "release/prepared-pairs/0.c0010"
EVIDENCE = PROJECT_ROOT / "release/evidence/2026-10-01-joint-e2e-r6/0.c0010"


def _module():
    specification = importlib.util.spec_from_file_location("prepared_pair_audit", MODULE_PATH)
    module = importlib.util.module_from_spec(specification)
    assert specification.loader is not None
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


@pytest.fixture
def evidence_copy(tmp_path: Path) -> Path:
    return Path(shutil.copytree(EVIDENCE, tmp_path / "evidence"))


@pytest.fixture
def bound_evidence(evidence_copy: Path) -> Path:
    state = json.loads((evidence_copy / "campaign_state.json").read_text())
    (evidence_copy / "replay-identity.json").write_text(json.dumps({
        "run_id": "0123456789abcdef0123456789abcdef", "run_label": state["run_id"],
        "campaign_id": "0.c0010"}))
    entries = []
    for path in sorted(evidence_copy.rglob("*")):
        if path.is_file() and path.name != "joint-replay-receipt.json":
            entries.append({"path": path.relative_to(evidence_copy).as_posix(),
                            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                            "bytes": path.stat().st_size})
    manifest = {"schema_version": "autosut-replay-evidence/v1",
                "run_id": "0123456789abcdef0123456789abcdef",
                "run_label": state["run_id"], "campaign_id": "0.c0010", "files": entries}
    manifest_path = evidence_copy / "replay-evidence-manifest.json"
    manifest_path.write_text(json.dumps(manifest))
    receipt_path = evidence_copy / "joint-replay-receipt.json"
    receipt = json.loads(receipt_path.read_text())
    receipt.update(schema_version="autosut-joint-replay/v2", run_id=manifest["run_id"],
                   evidence_manifest_sha256=hashlib.sha256(manifest_path.read_bytes()).hexdigest())
    receipt_path.write_text(json.dumps(receipt))
    return evidence_copy


def test_bound_replay_verifies_retained_file_integrity(bound_evidence: Path) -> None:
    audit = _module().audit_replay(PAIR, bound_evidence)
    assert audit.integrity_verified
    assert audit.run_id == "0123456789abcdef0123456789abcdef"


def test_bound_replay_rejects_changed_observation_bytes(bound_evidence: Path) -> None:
    manifest = json.loads((bound_evidence / "manifest.json").read_text())
    target = bound_evidence / manifest["techniques"][0]["evidence_files"][0]
    target.write_bytes(target.read_bytes() + b"changed")
    with pytest.raises(ValueError, match="evidence file integrity"):
        _module().audit_replay(PAIR, bound_evidence)


def test_bound_replay_rejects_receipt_run_identity_change(bound_evidence: Path) -> None:
    receipt_path = bound_evidence / "joint-replay-receipt.json"
    receipt = json.loads(receipt_path.read_text())
    receipt["run_id"] = "f" * 32
    receipt_path.write_text(json.dumps(receipt))
    with pytest.raises(ValueError, match="run identity"):
        _module().audit_replay(PAIR, bound_evidence)


def test_legacy_replay_reports_unverified_file_integrity(evidence_copy: Path) -> None:
    assert not _module().audit_replay(PAIR, evidence_copy).integrity_verified
    with pytest.raises(ValueError, match="integrity binding required"):
        _module().audit_replay(PAIR, evidence_copy, require_integrity=True)


def test_partial_identity_binding_cannot_pass_as_legacy(evidence_copy: Path) -> None:
    receipt_path = evidence_copy / "joint-replay-receipt.json"
    receipt = json.loads(receipt_path.read_text())
    receipt["run_id"] = "a" * 32
    receipt_path.write_text(json.dumps(receipt))
    with pytest.raises(ValueError, match="integrity binding required"):
        _module().audit_replay(PAIR, evidence_copy)


def test_bound_replay_rejects_unlisted_evidence(bound_evidence: Path) -> None:
    (bound_evidence / "unexpected.json").write_text("{}")
    with pytest.raises(ValueError, match="file inventory"):
        _module().audit_replay(PAIR, bound_evidence)


def test_bound_replay_cannot_remove_its_integrity_manifest(bound_evidence: Path) -> None:
    (bound_evidence / "replay-evidence-manifest.json").unlink()
    with pytest.raises(FileNotFoundError):
        _module().audit_replay(PAIR, bound_evidence)


def test_frozen_replay_has_auditable_identity_and_observations(evidence_copy: Path) -> None:
    audit = _module().audit_replay(PAIR, evidence_copy)

    assert audit.campaign_id == "0.c0010"
    assert audit.total_steps == 9
    assert audit.evidence_files_checked >= audit.total_steps
    assert audit.teardown_clean


def test_changed_pair_identity_is_rejected(evidence_copy: Path) -> None:
    receipt_path = evidence_copy / "joint-replay-receipt.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["pair_manifest_sha256"] = "0" * 64
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")

    with pytest.raises(ValueError, match="prepared-pair manifest hash"):
        _module().audit_replay(PAIR, evidence_copy)


def test_missing_effect_record_is_rejected(evidence_copy: Path) -> None:
    manifest = json.loads((evidence_copy / "manifest.json").read_text(encoding="utf-8"))
    (evidence_copy / manifest["techniques"][0]["evidence_files"][0]).unlink()

    with pytest.raises(ValueError, match="technique evidence is missing"):
        _module().audit_replay(PAIR, evidence_copy)


def test_gateway_denial_requires_counted_observation(evidence_copy: Path) -> None:
    gateway_path = evidence_copy / "gateway-isolation.json"
    gateway = json.loads(gateway_path.read_text(encoding="utf-8"))
    gateway["dropped_packets"] = 0
    gateway_path.write_text(json.dumps(gateway), encoding="utf-8")

    with pytest.raises(ValueError, match="gateway certificate lacks"):
        _module().audit_replay(PAIR, evidence_copy)


@pytest.mark.parametrize(
    ("field", "replacement", "message"),
    [
        ("technique_id", "T9999", "technique sequence"),
        ("executed_fidelity", "faithful", "fidelity ceiling"),
        ("executed_fidelity", "unknown", "unsupported executed fidelity"),
    ],
)
def test_manifest_cannot_change_executed_semantics(
    evidence_copy: Path, field: str, replacement: str, message: str
) -> None:
    manifest_path = evidence_copy / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["techniques"][0][field] = replacement
    manifest_path.write_text(json.dumps(manifest))

    with pytest.raises(ValueError, match=message):
        _module().audit_replay(PAIR, evidence_copy)


def test_receipt_cannot_relabel_inspired_steps_as_adapted(evidence_copy: Path) -> None:
    receipt_path = evidence_copy / "joint-replay-receipt.json"
    receipt = json.loads(receipt_path.read_text())
    receipt["adapted_steps"] += 1
    receipt["inspired_steps"] -= 1
    receipt_path.write_text(json.dumps(receipt))

    with pytest.raises(ValueError, match="fidelity counts differ"):
        _module().audit_replay(PAIR, evidence_copy)


def test_manifest_cannot_borrow_another_steps_evidence(evidence_copy: Path) -> None:
    manifest_path = evidence_copy / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["techniques"][0]["evidence_files"] = manifest["techniques"][1]["evidence_files"]
    manifest_path.write_text(json.dumps(manifest))

    with pytest.raises(ValueError, match="evidence paths differ"):
        _module().audit_replay(PAIR, evidence_copy)
