"""Regression and adversarial tests for bounded recovery."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from infrastructure.failure_recovery import (  # noqa: E402
    AdmissionDecision,
    EvidenceReference,
    ExecutionObservation,
    FailureKind,
    RecoveryAttempt,
    RecoveryDisposition,
    RecoveryJournal,
    RecoveryProtocol,
    RecoveryRun,
    RevisionProposal,
    load_journal,
    run_recovery,
    sha256_text,
)


def _protocol(maximum_revisions: int = 3) -> RecoveryProtocol:
    return RecoveryProtocol.freeze(
        protocol_id="recovery-test",
        maximum_revisions=maximum_revisions,
    )


def _evidence() -> tuple[EvidenceReference, ...]:
    return (EvidenceReference(path="attempt.log", sha256="b" * 64),)


def _observation(artifact: str, index: int, *, succeeded: bool, stderr: str = ""):
    return ExecutionObservation(
        attempt_index=index,
        artifact_sha256=sha256_text(artifact),
        succeeded=succeeded,
        exit_code=0 if succeeded else 1,
        stderr=stderr,
        diagnostics_redacted=True,
        evidence=_evidence(),
    )


def _proposal(artifact: str, revised: str, kind: FailureKind) -> RevisionProposal:
    return RevisionProposal(
        parent_sha256=sha256_text(artifact),
        artifact=revised,
        artifact_sha256=sha256_text(revised),
        failure_kind=kind,
        proposer_id="test-reviser",
        proposer_version="1",
        rationale="bounded test revision",
    )


def _admit(proposal: RevisionProposal) -> AdmissionDecision:
    return AdmissionDecision(
        proposal_sha256=proposal.proposal_sha256,
        policy_version="test-admission-v1",
        admitted=True,
    )


def test_success_after_admitted_revision_is_denominator_complete(tmp_path: Path) -> None:
    journal = RecoveryJournal(tmp_path / "journal")
    revision_history_lengths = []

    def revise(artifact: str, classification, history) -> RevisionProposal:
        revision_history_lengths.append(len(history))
        return _proposal(artifact, "valid syntax", classification.kind)

    run = run_recovery(
        initial_artifact="bad syntax",
        protocol=_protocol(),
        execute=lambda artifact, index: _observation(
            artifact,
            index,
            succeeded=index == 1,
            stderr="syntax error" if index == 0 else "",
        ),
        revise=revise,
        admit=_admit,
        journal=journal,
    )

    assert run.disposition is RecoveryDisposition.SUCCEEDED_AFTER_REVISION
    assert run.recovered
    assert len(run.attempts) == 2
    assert revision_history_lengths == [1]
    records = load_journal(tmp_path / "journal")
    assert [record.event_type for record in records] == ["attempt", "attempt", "terminal"]


def test_unclassified_failure_never_reaches_reviser() -> None:
    revised = []
    run = run_recovery(
        initial_artifact="opaque",
        protocol=_protocol(),
        execute=lambda artifact, index: _observation(
            artifact, index, succeeded=False, stderr="opaque remote failure"
        ),
        revise=lambda *_args: revised.append(True),
        admit=_admit,
    )
    assert run.disposition is RecoveryDisposition.UNRECOVERABLE
    assert revised == []


def test_rejected_revision_is_never_executed() -> None:
    executed = []

    def execute(artifact: str, index: int) -> ExecutionObservation:
        executed.append(artifact)
        return _observation(artifact, index, succeeded=False, stderr="permission denied")

    def reject(proposal: RevisionProposal) -> AdmissionDecision:
        return AdmissionDecision(
            proposal_sha256=proposal.proposal_sha256,
            policy_version="test-admission-v1",
            admitted=False,
            reasons=("requires undeclared privilege",),
        )

    run = run_recovery(
        initial_artifact="command",
        protocol=_protocol(),
        execute=execute,
        revise=lambda artifact, classification, _history: _proposal(
            artifact, "sudo command", classification.kind
        ),
        admit=reject,
    )
    assert run.disposition is RecoveryDisposition.REVISION_REJECTED
    assert executed == ["command"]


def test_repeated_revision_stops_before_reexecution() -> None:
    executed = []

    def execute(artifact: str, index: int) -> ExecutionObservation:
        executed.append(artifact)
        return _observation(artifact, index, succeeded=False, stderr="syntax error")

    run = run_recovery(
        initial_artifact="same",
        protocol=_protocol(),
        execute=execute,
        revise=lambda artifact, classification, _history: _proposal(
            artifact, artifact, classification.kind
        ),
        admit=_admit,
    )
    assert run.disposition is RecoveryDisposition.REPEATED_REVISION
    assert executed == ["same"]


def test_revision_budget_is_exact() -> None:
    run = run_recovery(
        initial_artifact="revision-0",
        protocol=_protocol(maximum_revisions=2),
        execute=lambda artifact, index: _observation(
            artifact, index, succeeded=False, stderr="connection refused"
        ),
        revise=lambda artifact, classification, history: _proposal(
            artifact, f"revision-{len(history) + 1}", classification.kind
        ),
        admit=_admit,
    )
    assert run.disposition is RecoveryDisposition.BUDGET_EXHAUSTED
    assert len(run.attempts) == 3


def test_adapter_cannot_substitute_an_unobserved_artifact() -> None:
    with pytest.raises(ValueError, match="different artifact"):
        run_recovery(
            initial_artifact="declared",
            protocol=_protocol(),
            execute=lambda _artifact, index: _observation(
                "substituted", index, succeeded=False, stderr="syntax error"
            ),
            revise=lambda artifact, classification, _history: _proposal(
                artifact, "revision", classification.kind
            ),
            admit=_admit,
        )


def test_journal_detects_tampering(tmp_path: Path) -> None:
    journal = RecoveryJournal(tmp_path)
    run_recovery(
        initial_artifact="ok",
        protocol=_protocol(),
        execute=lambda artifact, index: _observation(artifact, index, succeeded=True),
        revise=lambda artifact, classification, _history: _proposal(
            artifact, "unused", classification.kind
        ),
        admit=_admit,
        journal=journal,
    )
    attempt_path = tmp_path / "0000-attempt.json"
    payload = json.loads(attempt_path.read_text(encoding="utf-8"))
    payload["payload"]["observation"]["stdout"] = "tampered"
    attempt_path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="invalid hash"):
        load_journal(tmp_path)


def test_evidence_reference_verifies_content(tmp_path: Path) -> None:
    evidence = tmp_path / "attempt.log"
    evidence.write_text("observed", encoding="utf-8")
    reference = EvidenceReference(path="attempt.log", sha256=sha256_text("observed"))
    reference.verify(tmp_path)
    evidence.write_text("changed", encoding="utf-8")
    with pytest.raises(ValueError, match="hash mismatch"):
        reference.verify(tmp_path)


def test_protocol_rejects_a_forged_digest() -> None:
    payload = _protocol().model_dump(mode="json")
    payload["protocol_digest"] = "f" * 64
    with pytest.raises(ValueError, match="digest"):
        RecoveryProtocol.model_validate(payload)


def test_unredacted_diagnostics_are_rejected() -> None:
    with pytest.raises(ValueError, match="redacted"):
        ExecutionObservation(
            attempt_index=0,
            artifact_sha256="a" * 64,
            succeeded=False,
            exit_code=1,
            stderr="credential=secret",
            diagnostics_redacted=False,
            evidence=_evidence(),
        )


def test_terminal_disposition_cannot_be_forged() -> None:
    successful = _observation("ok", 0, succeeded=True)
    with pytest.raises(ValueError, match="failed disposition"):
        RecoveryRun(
            protocol=_protocol(),
            initial_artifact_sha256=sha256_text("ok"),
            attempts=(RecoveryAttempt(observation=successful),),
            disposition=RecoveryDisposition.UNRECOVERABLE,
            recovered=True,
        )
