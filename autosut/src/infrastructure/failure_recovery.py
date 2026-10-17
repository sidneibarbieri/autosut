"""Bounded, admission-gated recovery with a hash-chained decision trail.

The engine is deliberately independent of Caldera, Docker, and any model provider. Callers inject
execution, revision, and admission adapters. A proposed revision is never executed until an
independent admission adapter accepts it, and every transition can be persisted before the next
attempt starts.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Callable, Sequence
from enum import Enum
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

SHA256_PATTERN = r"^[0-9a-f]{64}$"
CLASSIFIER_VERSION = "autosut-failure-classifier/1"


class StrictModel(BaseModel):
    """Base DTO that rejects undeclared fields."""

    model_config = ConfigDict(extra="forbid")


class FailureKind(str, Enum):
    """Operational failure classes supported by the fixed classifier."""

    SYNTAX_ERROR = "syntax_error"
    DEPENDENCY_ERROR = "dependency_error"
    MISSING_ENVIRONMENT = "missing_environment"
    TIMEOUT = "timeout"
    UNCLASSIFIED = "unclassified"


class RecoveryDisposition(str, Enum):
    """Why the recovery state machine stopped."""

    SUCCEEDED_INITIAL = "succeeded_initial"
    SUCCEEDED_AFTER_REVISION = "succeeded_after_revision"
    UNRECOVERABLE = "unrecoverable"
    BUDGET_EXHAUSTED = "budget_exhausted"
    REPEATED_REVISION = "repeated_revision"
    REVISION_REJECTED = "revision_rejected"


class EvidenceReference(StrictModel):
    """Hash-bound reference to evidence retained outside the recovery DTO."""

    path: str = Field(min_length=1)
    sha256: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def _path_is_relative(self) -> "EvidenceReference":
        candidate = Path(self.path)
        if candidate.is_absolute() or ".." in candidate.parts:
            raise ValueError("evidence path must be relative and stay inside its evidence root")
        return self

    def verify(self, evidence_root: Path) -> None:
        """Fail if the referenced evidence is absent or no longer matches its digest."""
        candidate = evidence_root / self.path
        if not candidate.is_file():
            raise ValueError(f"recovery evidence is missing: {self.path}")
        if sha256_bytes(candidate.read_bytes()) != self.sha256:
            raise ValueError(f"recovery evidence hash mismatch: {self.path}")


class RecoveryProtocol(StrictModel):
    """Frozen recovery budget and classifier identity."""

    schema_version: Literal["autosut-recovery-protocol/v1"] = "autosut-recovery-protocol/v1"
    protocol_id: str = Field(min_length=1)
    protocol_digest: str = Field(pattern=SHA256_PATTERN)
    classifier_version: str = Field(min_length=1)
    maximum_revisions: int = Field(ge=0, le=20)
    recoverable_failure_kinds: frozenset[FailureKind] = Field(
        default_factory=lambda: frozenset(
            {
                FailureKind.SYNTAX_ERROR,
                FailureKind.DEPENDENCY_ERROR,
                FailureKind.MISSING_ENVIRONMENT,
                FailureKind.TIMEOUT,
            }
        )
    )

    @model_validator(mode="after")
    def _definition_is_frozen(self) -> "RecoveryProtocol":
        if FailureKind.UNCLASSIFIED in self.recoverable_failure_kinds:
            raise ValueError("unclassified failures cannot enter the recovery loop")
        if self.classifier_version != CLASSIFIER_VERSION:
            raise ValueError("recovery protocol names an unsupported classifier version")
        if self.protocol_digest != canonical_sha256(self.digest_payload()):
            raise ValueError("recovery protocol digest does not match its definition")
        return self

    def digest_payload(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "protocol_id": self.protocol_id,
            "classifier_version": self.classifier_version,
            "maximum_revisions": self.maximum_revisions,
            "recoverable_failure_kinds": sorted(
                kind.value for kind in self.recoverable_failure_kinds
            ),
        }

    @classmethod
    def freeze(cls, *, protocol_id: str, maximum_revisions: int) -> "RecoveryProtocol":
        recoverable = frozenset(
            {
                FailureKind.SYNTAX_ERROR,
                FailureKind.DEPENDENCY_ERROR,
                FailureKind.MISSING_ENVIRONMENT,
                FailureKind.TIMEOUT,
            }
        )
        payload = {
            "schema_version": "autosut-recovery-protocol/v1",
            "protocol_id": protocol_id,
            "classifier_version": CLASSIFIER_VERSION,
            "maximum_revisions": maximum_revisions,
            "recoverable_failure_kinds": sorted(kind.value for kind in recoverable),
        }
        return cls(
            protocol_id=protocol_id,
            protocol_digest=canonical_sha256(payload),
            classifier_version=CLASSIFIER_VERSION,
            maximum_revisions=maximum_revisions,
            recoverable_failure_kinds=recoverable,
        )


class ExecutionObservation(StrictModel):
    """One observed execution of one immutable artifact revision."""

    attempt_index: int = Field(ge=0)
    artifact_sha256: str = Field(pattern=SHA256_PATTERN)
    succeeded: bool
    exit_code: int | None = None
    stdout: str = Field(default="", max_length=8192)
    stderr: str = Field(default="", max_length=8192)
    diagnostics_redacted: bool
    timed_out: bool = False
    evidence: tuple[EvidenceReference, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def _outcome_is_coherent(self) -> "ExecutionObservation":
        if not self.diagnostics_redacted:
            raise ValueError("execution diagnostics must be redacted before recovery persistence")
        if self.succeeded and self.timed_out:
            raise ValueError("a timed-out execution cannot be successful")
        if self.succeeded and self.exit_code not in (None, 0):
            raise ValueError("a successful execution cannot carry a non-zero exit code")
        return self


class FailureClassification(StrictModel):
    """Deterministic classification derived from an execution observation."""

    kind: FailureKind
    classifier_version: str
    matched_pattern: str | None = None

    @model_validator(mode="after")
    def _match_is_coherent(self) -> "FailureClassification":
        if self.kind is FailureKind.UNCLASSIFIED and self.matched_pattern is not None:
            raise ValueError("an unclassified failure cannot name a matching pattern")
        if self.kind is not FailureKind.UNCLASSIFIED and self.matched_pattern is None:
            raise ValueError("a classified failure must name the matching pattern")
        return self


class RevisionProposal(StrictModel):
    """A candidate revision emitted by an untrusted or trusted revision adapter."""

    parent_sha256: str = Field(pattern=SHA256_PATTERN)
    artifact: str
    artifact_sha256: str = Field(pattern=SHA256_PATTERN)
    failure_kind: FailureKind
    proposer_id: str = Field(min_length=1)
    proposer_version: str = Field(min_length=1)
    rationale: str = Field(min_length=1)

    @model_validator(mode="after")
    def _artifact_hash_matches(self) -> "RevisionProposal":
        if sha256_text(self.artifact) != self.artifact_sha256:
            raise ValueError("revision artifact does not match artifact_sha256")
        if self.failure_kind is FailureKind.UNCLASSIFIED:
            raise ValueError("an unclassified failure cannot produce a revision")
        return self

    @property
    def proposal_sha256(self) -> str:
        return canonical_sha256(self.model_dump(mode="json"))


class AdmissionDecision(StrictModel):
    """Independent decision that controls whether a proposal may execute."""

    proposal_sha256: str = Field(pattern=SHA256_PATTERN)
    policy_version: str = Field(min_length=1)
    admitted: bool
    reasons: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _decision_is_explained(self) -> "AdmissionDecision":
        if self.admitted and self.reasons:
            raise ValueError("an admitted proposal cannot carry rejection reasons")
        if not self.admitted and not self.reasons:
            raise ValueError("a rejected proposal must carry at least one reason")
        return self


class RecoveryAttempt(StrictModel):
    """One execution observation and the optional decision about its successor."""

    observation: ExecutionObservation
    classification: FailureClassification | None = None
    proposal: RevisionProposal | None = None
    admission: AdmissionDecision | None = None

    @model_validator(mode="after")
    def _transition_is_coherent(self) -> "RecoveryAttempt":
        if self.observation.succeeded:
            if any((self.classification, self.proposal, self.admission)):
                raise ValueError("a successful attempt cannot have a recovery transition")
            return self
        if self.classification is None:
            raise ValueError("a failed attempt requires a classification")
        if self.admission is not None and self.proposal is None:
            raise ValueError("an admission decision requires a proposal")
        if self.proposal is not None:
            if self.proposal.parent_sha256 != self.observation.artifact_sha256:
                raise ValueError("proposal parent does not match the executed artifact")
            if self.proposal.failure_kind is not self.classification.kind:
                raise ValueError("proposal failure kind does not match the classification")
        if self.admission is not None and self.proposal is not None:
            if self.admission.proposal_sha256 != self.proposal.proposal_sha256:
                raise ValueError("admission decision does not identify the proposal")
        return self


class RecoveryRun(StrictModel):
    """Terminal, denominator-complete record of one bounded recovery run."""

    schema_version: Literal["autosut-recovery-run/v1"] = "autosut-recovery-run/v1"
    protocol: RecoveryProtocol
    initial_artifact_sha256: str = Field(pattern=SHA256_PATTERN)
    attempts: tuple[RecoveryAttempt, ...] = Field(min_length=1)
    disposition: RecoveryDisposition
    recovered: bool

    @model_validator(mode="after")
    def _run_is_coherent(self) -> "RecoveryRun":
        for expected_index, attempt in enumerate(self.attempts):
            if attempt.observation.attempt_index != expected_index:
                raise ValueError("recovery attempt indices must be contiguous from zero")
            if expected_index == len(self.attempts) - 1:
                continue
            if (
                attempt.proposal is None
                or attempt.admission is None
                or not attempt.admission.admitted
            ):
                raise ValueError("every non-terminal attempt requires an admitted successor")
            successor = self.attempts[expected_index + 1]
            if successor.observation.artifact_sha256 != attempt.proposal.artifact_sha256:
                raise ValueError("a successor did not execute the admitted proposal")
        if self.attempts[0].observation.artifact_sha256 != self.initial_artifact_sha256:
            raise ValueError("first attempt does not execute the declared initial artifact")
        revisions = len(self.attempts) - 1
        if revisions > self.protocol.maximum_revisions:
            raise ValueError("recovery run exceeds its frozen revision budget")
        successful = self.attempts[-1].observation.succeeded
        if successful != self.recovered:
            raise ValueError("recovered must match the terminal observation")
        if self.disposition is RecoveryDisposition.SUCCEEDED_INITIAL:
            if not successful or len(self.attempts) != 1:
                raise ValueError("succeeded_initial requires exactly one successful attempt")
        if self.disposition is RecoveryDisposition.SUCCEEDED_AFTER_REVISION:
            if not successful or len(self.attempts) < 2:
                raise ValueError("succeeded_after_revision requires a successful revision")
        if (
            self.disposition
            not in {
                RecoveryDisposition.SUCCEEDED_INITIAL,
                RecoveryDisposition.SUCCEEDED_AFTER_REVISION,
            }
            and successful
        ):
            raise ValueError("a failed disposition cannot end in success")
        terminal = self.attempts[-1]
        if self.disposition is RecoveryDisposition.UNRECOVERABLE:
            if (
                terminal.classification is None
                or terminal.classification.kind in self.protocol.recoverable_failure_kinds
                or terminal.proposal is not None
            ):
                raise ValueError("unrecoverable disposition does not match its terminal attempt")
        if self.disposition is RecoveryDisposition.BUDGET_EXHAUSTED:
            if len(self.attempts) != self.protocol.maximum_revisions + 1:
                raise ValueError("budget exhaustion must consume the exact revision budget")
            if terminal.proposal is not None:
                raise ValueError("budget exhaustion cannot retain an unexecuted proposal")
        if self.disposition is RecoveryDisposition.REPEATED_REVISION:
            prior_hashes = {attempt.observation.artifact_sha256 for attempt in self.attempts}
            if (
                terminal.proposal is None
                or terminal.proposal.artifact_sha256 not in prior_hashes
                or terminal.admission is not None
            ):
                raise ValueError("repeated-revision disposition lacks a repeated proposal")
        if self.disposition is RecoveryDisposition.REVISION_REJECTED:
            if (
                terminal.proposal is None
                or terminal.admission is None
                or terminal.admission.admitted
            ):
                raise ValueError("revision-rejected disposition lacks a rejected decision")
        return self


class JournalRecord(StrictModel):
    """One immutable entry in a hash chain persisted before the next transition."""

    schema_version: Literal["autosut-recovery-journal/v1"] = "autosut-recovery-journal/v1"
    sequence: int = Field(ge=0)
    previous_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    event_type: Literal["attempt", "terminal"]
    payload: dict[str, Any]
    content_sha256: str = Field(pattern=SHA256_PATTERN)

    @classmethod
    def create(
        cls,
        *,
        sequence: int,
        previous_sha256: str | None,
        event_type: Literal["attempt", "terminal"],
        payload: dict[str, Any],
    ) -> "JournalRecord":
        content: dict[str, Any] = {
            "schema_version": "autosut-recovery-journal/v1",
            "sequence": sequence,
            "previous_sha256": previous_sha256,
            "event_type": event_type,
            "payload": payload,
        }
        return cls(
            sequence=sequence,
            previous_sha256=previous_sha256,
            event_type=event_type,
            payload=payload,
            content_sha256=canonical_sha256(content),
        )

    def verify_content_hash(self) -> None:
        content = self.model_dump(mode="json", exclude={"content_sha256"})
        if canonical_sha256(content) != self.content_sha256:
            raise ValueError(f"recovery journal record {self.sequence} has an invalid hash")


class RecoveryJournal:
    """Append recovery records with exclusive file creation and a verified hash chain."""

    def __init__(self, directory: Path):
        self.directory = directory
        self.directory.mkdir(parents=True, exist_ok=True)
        self._records = load_journal(directory)

    def append_attempt(self, attempt: RecoveryAttempt) -> None:
        self._append("attempt", attempt.model_dump(mode="json"))

    def append_terminal(self, run: RecoveryRun) -> None:
        self._append("terminal", run.model_dump(mode="json"))

    def _append(self, event_type: Literal["attempt", "terminal"], payload: dict[str, Any]) -> None:
        if self._records and self._records[-1].event_type == "terminal":
            raise ValueError("cannot append after a terminal recovery record")
        record = JournalRecord.create(
            sequence=len(self._records),
            previous_sha256=self._records[-1].content_sha256 if self._records else None,
            event_type=event_type,
            payload=payload,
        )
        path = self.directory / f"{record.sequence:04d}-{event_type}.json"
        with path.open("x", encoding="utf-8") as handle:
            handle.write(record.model_dump_json(indent=2) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        self._records.append(record)


_PATTERNS: tuple[tuple[FailureKind, tuple[str, ...]], ...] = (
    (
        FailureKind.TIMEOUT,
        (r"timeout(?:\s+reached)?", r"timed out", r"exit code:\s*124", r"killed.*time"),
    ),
    (
        FailureKind.SYNTAX_ERROR,
        (
            r"syntax error",
            r"parsererror",
            r"unexpected token",
            r"invalid (?:parameter|argument|syntax)",
            r"not recognized as (?:a|the) (?:command|name|cmdlet)",
        ),
    ),
    (
        FailureKind.DEPENDENCY_ERROR,
        (
            r"access (?:is )?denied",
            r"permission denied",
            r"requires? elevation",
            r"unauthori[sz]ed",
            r"missing (?:dependency|prerequisite)",
            r"command not found",
        ),
    ),
    (
        FailureKind.MISSING_ENVIRONMENT,
        (
            r"no such file or directory",
            r"cannot find (?:path|drive)",
            r"does not exist",
            r"network (?:name )?cannot be found",
            r"unable to connect",
            r"connection refused",
        ),
    ),
)


def classify_failure(
    observation: ExecutionObservation, classifier_version: str
) -> FailureClassification:
    """Classify one failed observation with deterministic, ordered patterns."""
    if observation.succeeded:
        raise ValueError("a successful observation cannot be classified as a failure")
    if observation.timed_out:
        return FailureClassification(
            kind=FailureKind.TIMEOUT,
            classifier_version=classifier_version,
            matched_pattern="timed_out=true",
        )
    diagnostic = "\n".join((observation.stderr, observation.stdout)).lower()
    for kind, patterns in _PATTERNS:
        for pattern in patterns:
            if re.search(pattern, diagnostic, flags=re.IGNORECASE):
                return FailureClassification(
                    kind=kind,
                    classifier_version=classifier_version,
                    matched_pattern=pattern,
                )
    return FailureClassification(
        kind=FailureKind.UNCLASSIFIED,
        classifier_version=classifier_version,
    )


ExecuteAdapter = Callable[[str, int], ExecutionObservation]
RevisionAdapter = Callable[
    [str, FailureClassification, Sequence[RecoveryAttempt]], RevisionProposal
]
AdmissionAdapter = Callable[[RevisionProposal], AdmissionDecision]


def run_recovery(
    *,
    initial_artifact: str,
    protocol: RecoveryProtocol,
    execute: ExecuteAdapter,
    revise: RevisionAdapter,
    admit: AdmissionAdapter,
    journal: RecoveryJournal | None = None,
) -> RecoveryRun:
    """Execute and revise under a frozen budget, stopping closed on every invalid transition."""
    artifact = initial_artifact
    initial_hash = sha256_text(initial_artifact)
    seen_hashes = {initial_hash}
    attempts: list[RecoveryAttempt] = []

    for attempt_index in range(protocol.maximum_revisions + 1):
        observation = execute(artifact, attempt_index)
        expected_hash = sha256_text(artifact)
        if observation.attempt_index != attempt_index:
            raise ValueError("execution adapter returned the wrong attempt index")
        if observation.artifact_sha256 != expected_hash:
            raise ValueError("execution adapter observed a different artifact revision")
        if observation.succeeded:
            attempt = RecoveryAttempt(observation=observation)
            attempts.append(attempt)
            disposition = (
                RecoveryDisposition.SUCCEEDED_INITIAL
                if attempt_index == 0
                else RecoveryDisposition.SUCCEEDED_AFTER_REVISION
            )
            return _finish_run(protocol, initial_hash, attempts, disposition, journal)

        classification = classify_failure(observation, protocol.classifier_version)
        if classification.kind not in protocol.recoverable_failure_kinds:
            attempt = RecoveryAttempt(observation=observation, classification=classification)
            attempts.append(attempt)
            return _finish_run(
                protocol, initial_hash, attempts, RecoveryDisposition.UNRECOVERABLE, journal
            )
        if attempt_index == protocol.maximum_revisions:
            attempt = RecoveryAttempt(observation=observation, classification=classification)
            attempts.append(attempt)
            return _finish_run(
                protocol, initial_hash, attempts, RecoveryDisposition.BUDGET_EXHAUSTED, journal
            )

        failed_attempt = RecoveryAttempt(
            observation=observation,
            classification=classification,
        )
        proposal = revise(artifact, classification, (*attempts, failed_attempt))
        if proposal.parent_sha256 != expected_hash:
            raise ValueError("revision adapter targeted an artifact other than the failed revision")
        if proposal.failure_kind is not classification.kind:
            raise ValueError("revision adapter changed the classified failure kind")
        if proposal.artifact_sha256 in seen_hashes:
            attempt = RecoveryAttempt(
                observation=observation,
                classification=classification,
                proposal=proposal,
            )
            attempts.append(attempt)
            return _finish_run(
                protocol, initial_hash, attempts, RecoveryDisposition.REPEATED_REVISION, journal
            )

        decision = admit(proposal)
        if decision.proposal_sha256 != proposal.proposal_sha256:
            raise ValueError("admission adapter decided on a different proposal")
        attempt = RecoveryAttempt(
            observation=observation,
            classification=classification,
            proposal=proposal,
            admission=decision,
        )
        attempts.append(attempt)
        if journal is not None:
            journal.append_attempt(attempt)
        if not decision.admitted:
            return _finish_run(
                protocol,
                initial_hash,
                attempts,
                RecoveryDisposition.REVISION_REJECTED,
                journal,
                append_last_attempt=False,
            )
        artifact = proposal.artifact
        seen_hashes.add(proposal.artifact_sha256)

    raise AssertionError("bounded recovery loop exited without a terminal disposition")


def _finish_run(
    protocol: RecoveryProtocol,
    initial_hash: str,
    attempts: list[RecoveryAttempt],
    disposition: RecoveryDisposition,
    journal: RecoveryJournal | None,
    *,
    append_last_attempt: bool = True,
) -> RecoveryRun:
    if journal is not None and append_last_attempt:
        journal.append_attempt(attempts[-1])
    run = RecoveryRun(
        protocol=protocol,
        initial_artifact_sha256=initial_hash,
        attempts=tuple(attempts),
        disposition=disposition,
        recovered=attempts[-1].observation.succeeded,
    )
    if journal is not None:
        journal.append_terminal(run)
    return run


def load_journal(directory: Path) -> list[JournalRecord]:
    """Load and verify a complete or interrupted journal without hiding corruption."""
    paths = sorted(directory.glob("*.json")) if directory.exists() else []
    records = [
        JournalRecord.model_validate_json(path.read_text(encoding="utf-8")) for path in paths
    ]
    previous: str | None = None
    for expected_sequence, record in enumerate(records):
        record.verify_content_hash()
        if record.sequence != expected_sequence:
            raise ValueError("recovery journal sequence is not contiguous")
        if record.previous_sha256 != previous:
            raise ValueError("recovery journal hash chain is broken")
        if record.event_type == "terminal" and expected_sequence != len(records) - 1:
            raise ValueError("recovery journal contains records after its terminal event")
        previous = record.content_sha256
    return records


def canonical_sha256(payload: Any) -> str:
    """Hash structured content with deterministic JSON encoding."""
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return sha256_bytes(encoded)


def sha256_text(value: str) -> str:
    return sha256_bytes(value.encode("utf-8"))


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()
