"""Append-only provenance storage for a non-executing Step-2 attempt.

The store is intentionally transport-agnostic.  It never contacts a provider
and never turns a proposal into execution input.  Its job is narrower: bind
the protocol, closed input, prompt, response schema, validated model output,
and deterministic admission decision into a sealed directory that a later
evaluation can inspect.

Unsafe or malformed model text is not copied into a reviewer-facing evidence
bundle.  Its byte length and SHA-256 digest are recorded with the rejection
reason; a conforming JSON-only output is archived verbatim and then parsed.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from pydantic import ConfigDict, Field, model_validator

from .semantic_concretizer import (
    ConcretizationInput,
    ConcretizationResult,
    SemanticConcretizer,
    SemanticEnrichmentProtocol,
    SemanticProposal,
    StrictModel,
    build_prompt,
    parse_model_output,
    response_schema,
    verify_evidence_anchor_against_stix_object,
    verify_model_attestation,
)

EVIDENCE_SCHEMA_VERSION = "autosut.step2.semantic-enrichment.evidence/v1"
_RUN_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_ERROR_TYPE_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]{0,127}$")


class SemanticEvidenceError(RuntimeError):
    """Raised when an evidence directory would stop being append-only or sealed."""


class SemanticOutputRejected(ValueError):
    """A provider output failed closed-schema validation and was not archived verbatim."""


class ArtifactDigest(StrictModel):
    """Digest and project-relative location of one immutable run artifact."""

    path: str
    sha256: str
    bytes: int = Field(ge=0)

    @model_validator(mode="after")
    def _validate_path_and_digest(self) -> "ArtifactDigest":
        if not _safe_child_path(self.path):
            raise ValueError("artifact path must be a safe run-relative path")
        if not _SHA256_PATTERN.fullmatch(self.sha256):
            raise ValueError("artifact sha256 must be a SHA-256 hexadecimal digest")
        return self


class RejectedOutputRecord(StrictModel):
    """Safe audit record for output that cannot enter the closed semantic DTO."""

    raw_output_sha256: str
    raw_output_bytes: int = Field(ge=0)
    rejection_type: str

    @model_validator(mode="after")
    def _validate_digest(self) -> "RejectedOutputRecord":
        if not _SHA256_PATTERN.fullmatch(self.raw_output_sha256):
            raise ValueError("raw_output_sha256 must be a SHA-256 hexadecimal digest")
        return self


class TransportFailureRecord(StrictModel):
    """Safe record that a local request failed before any model output was received."""

    status: str = "transport_failed"
    error_type: str

    @model_validator(mode="after")
    def _validate_error_type(self) -> "TransportFailureRecord":
        if self.status != "transport_failed":
            raise ValueError("transport failure status must be transport_failed")
        if not _ERROR_TYPE_PATTERN.fullmatch(self.error_type):
            raise ValueError("transport failure error_type must be a compact class name")
        return self


class SealedSemanticRun(StrictModel):
    """The immutable manifest for one attempted local semantic proposal."""

    schema_version: str = EVIDENCE_SCHEMA_VERSION
    protocol_id: str
    run_id: str
    sealed_at_utc: str
    artifacts: list[ArtifactDigest] = Field(min_length=1)
    qualification_blockers: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _validate_manifest(self) -> "SealedSemanticRun":
        if self.schema_version != EVIDENCE_SCHEMA_VERSION:
            raise ValueError("unsupported semantic evidence schema version")
        if not _RUN_ID_PATTERN.fullmatch(self.run_id):
            raise ValueError("run_id must be a compact run identifier")
        paths = [item.path for item in self.artifacts]
        if len(paths) != len(set(paths)):
            raise ValueError("sealed semantic run contains duplicate artifact paths")
        return self

    @property
    def is_qualification_eligible(self) -> bool:
        """A sealed directory is not claim evidence while any blocker remains."""
        return not self.qualification_blockers


class VerifiedSemanticAdmission(StrictModel):
    """Typed result produced only after a store replay-verifies a sealed run.

    This object is evidence-provenance, not semantic support, environment
    qualification, execution evidence, or a claim-promotion token.  Consumers
    can use it to distinguish a replay-verified record from an in-memory
    admission DTO without accepting a caller-supplied manifest digest.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = EVIDENCE_SCHEMA_VERSION
    protocol_id: str
    run_id: str
    manifest_sha256: str
    semantic_input: ConcretizationInput
    admission: ConcretizationResult

    @model_validator(mode="after")
    def _validate_binding(self) -> "VerifiedSemanticAdmission":
        if self.schema_version != EVIDENCE_SCHEMA_VERSION:
            raise ValueError("unsupported verified semantic admission schema version")
        if not _RUN_ID_PATTERN.fullmatch(self.run_id):
            raise ValueError("verified semantic admission run_id is invalid")
        if not _SHA256_PATTERN.fullmatch(self.manifest_sha256):
            raise ValueError("verified semantic admission manifest digest is invalid")
        if self.admission.input_sha256 != self.semantic_input.input_sha256:
            raise ValueError("verified semantic admission input digest differs")
        return self


@dataclass(frozen=True)
class PreparedSemanticRun:
    """Opaque handle for a prepared run directory that is not sealed yet."""

    run_id: str
    directory: Path


class SemanticEvidenceStore:
    """Persist one protocol attempt in a new directory and seal it once."""

    def __init__(self, project_root: Path, protocol: SemanticEnrichmentProtocol) -> None:
        self._project_root = project_root.resolve()
        self._protocol = protocol
        self._root = _resolve_under_root(self._project_root, protocol.provenance.root)

    def prepare(
        self,
        run_id: str,
        request: ConcretizationInput,
        *,
        source_bundle_path: Path,
    ) -> PreparedSemanticRun:
        """Create a fresh run directory and archive protocol inputs exactly once."""
        if not _RUN_ID_PATTERN.fullmatch(run_id):
            raise SemanticEvidenceError("run_id must be a compact run identifier")
        self._verify_request_source_bundle(request, source_bundle_path)
        self._root.mkdir(parents=True, exist_ok=True)
        directory = self._root / run_id
        try:
            directory.mkdir(mode=0o700)
        except FileExistsError as exc:
            raise SemanticEvidenceError(f"semantic evidence run already exists: {run_id}") from exc

        run = PreparedSemanticRun(run_id=run_id, directory=directory)
        self._write_artifact(
            run, self._protocol.provenance.protocol_manifest, _canonical_json(self._protocol)
        )
        self._write_artifact(
            run, self._protocol.provenance.input_document, _canonical_json(request)
        )
        self._write_artifact(
            run,
            self._protocol.provenance.prompt_document,
            build_prompt(request).encode("utf-8"),
        )
        self._write_artifact(
            run,
            self._protocol.provenance.response_schema_document,
            _canonical_json(response_schema()),
        )
        return run

    def record_output(
        self,
        run: PreparedSemanticRun,
        request: ConcretizationInput,
        raw_output: str,
        *,
        reported_model_id: str | None = None,
    ) -> ConcretizationResult:
        """Validate and archive safe output, or archive only a safe rejection digest."""
        self._require_prepared(run)
        self._require_no_recorded_output(run)
        self._validate_prepared_snapshot(run, request)
        try:
            proposal = parse_model_output(
                raw_output,
                request,
                self._protocol,
                reported_model_id=reported_model_id,
            )
        except (ValueError, TypeError) as exc:
            raw_output_bytes = _raw_output_audit_bytes(raw_output)
            rejection = RejectedOutputRecord(
                raw_output_sha256=_sha256_bytes(raw_output_bytes),
                raw_output_bytes=len(raw_output_bytes),
                rejection_type="closed_schema_rejected",
            )
            self._write_artifact(
                run,
                self._protocol.provenance.rejection_document,
                _canonical_json(rejection),
            )
            raise SemanticOutputRejected(
                "semantic provider output failed closed-schema validation"
            ) from exc

        result = self._admit(request, proposal)
        self._write_artifact(
            run,
            self._protocol.provenance.raw_output_document,
            raw_output.encode("utf-8"),
        )
        self._write_artifact(
            run,
            self._protocol.provenance.parsed_proposal_document,
            _canonical_json(proposal),
        )
        self._write_artifact(
            run,
            self._protocol.provenance.admission_document,
            _canonical_json(result),
        )
        return result

    def record_transport_failure(
        self,
        run: PreparedSemanticRun,
        error: Exception,
    ) -> None:
        """Record a provider transport failure without serializing its message or payload."""
        self._require_prepared(run)
        self._require_no_recorded_output(run)
        error_type = f"{type(error).__module__}.{type(error).__qualname__}"
        self._write_artifact(
            run,
            self._protocol.provenance.transport_failure_document,
            _canonical_json(TransportFailureRecord(error_type=error_type)),
        )

    def seal(self, run: PreparedSemanticRun) -> SealedSemanticRun:
        """Seal an attempted run after exactly one accepted or rejected output record."""
        self._require_prepared(run)
        entries = list(run.directory.iterdir())
        if any(not path.is_file() or path.is_symlink() for path in entries):
            raise SemanticEvidenceError("semantic evidence run contains an unsafe non-file entry")
        output_paths = {
            self._protocol.provenance.raw_output_document,
            self._protocol.provenance.rejection_document,
            self._protocol.provenance.transport_failure_document,
        }
        present = {path.name for path in entries}
        required_inputs = {
            self._protocol.provenance.protocol_manifest,
            self._protocol.provenance.input_document,
            self._protocol.provenance.prompt_document,
            self._protocol.provenance.response_schema_document,
            _ledger_name(),
        }
        missing_inputs = required_inputs - present
        if missing_inputs:
            raise SemanticEvidenceError(
                "semantic evidence run is missing required provenance artifacts: "
                + ", ".join(sorted(missing_inputs))
            )
        if not present.intersection(output_paths):
            raise SemanticEvidenceError("cannot seal a run without an output or rejection record")
        self._validate_output_layout(present)
        allowed = self._allowed_artifact_names(present)
        unexpected = present - allowed
        if unexpected:
            raise SemanticEvidenceError(
                "semantic evidence run contains unexpected artifacts: "
                + ", ".join(sorted(unexpected))
            )
        artifacts = [
            ArtifactDigest(
                path=path.name,
                sha256=_sha256_bytes(path.read_bytes()),
                bytes=path.stat().st_size,
            )
            for path in sorted(run.directory.iterdir())
            if path.is_file()
            and path.name != self._protocol.provenance.manifest_document
            and path.name != _ledger_name()
        ]
        self._verify_ledger_entries(
            run.directory,
            {artifact.path: artifact for artifact in artifacts},
        )
        ledger_path = run.directory / _ledger_name()
        if ledger_path.exists():
            artifacts.append(
                ArtifactDigest(
                    path=ledger_path.name,
                    sha256=_sha256_bytes(ledger_path.read_bytes()),
                    bytes=ledger_path.stat().st_size,
                )
            )
        manifest = SealedSemanticRun(
            protocol_id=self._protocol.protocol_id,
            run_id=run.run_id,
            sealed_at_utc=datetime.now(timezone.utc).isoformat(),
            artifacts=sorted(artifacts, key=lambda item: item.path),
            qualification_blockers=self._run_qualification_blockers(run),
        )
        _write_once(
            run.directory / self._protocol.provenance.manifest_document,
            _canonical_json(manifest),
        )
        return manifest

    def verify(self, run_directory: Path, *, source_bundle_path: Path) -> SealedSemanticRun:
        """Verify the sealed manifest, all recorded digests, and no unlisted artifacts."""
        directory = run_directory.resolve()
        if not _is_relative_to(directory, self._root):
            raise SemanticEvidenceError(
                "semantic evidence directory is outside the configured root"
            )
        manifest_path = directory / self._protocol.provenance.manifest_document
        if not manifest_path.is_file():
            raise SemanticEvidenceError("sealed semantic evidence manifest is missing")
        manifest = SealedSemanticRun.model_validate_json(manifest_path.read_text(encoding="utf-8"))
        if manifest.protocol_id != self._protocol.protocol_id:
            raise SemanticEvidenceError("semantic evidence manifest protocol_id does not match")
        if manifest.run_id != directory.name:
            raise SemanticEvidenceError(
                "semantic evidence manifest run_id does not match its directory"
            )
        expected = {artifact.path: artifact for artifact in manifest.artifacts}
        entries = list(directory.iterdir())
        if any(not path.is_file() or path.is_symlink() for path in entries):
            raise SemanticEvidenceError("sealed semantic evidence directory has an unsafe entry")
        observed = {
            path.name
            for path in entries
            if path.name != self._protocol.provenance.manifest_document
        }
        if observed != set(expected):
            raise SemanticEvidenceError(
                "sealed semantic evidence directory has unlisted or missing files"
            )
        self._validate_output_layout(observed)
        allowed = self._allowed_artifact_names(observed)
        unexpected = observed - allowed
        if unexpected:
            raise SemanticEvidenceError(
                "sealed semantic evidence directory contains unexpected artifacts: "
                + ", ".join(sorted(unexpected))
            )
        for relative_path, artifact in expected.items():
            path = directory / relative_path
            if not path.is_file() or path.is_symlink():
                raise SemanticEvidenceError(
                    f"semantic evidence artifact is missing or unsafe: {relative_path}"
                )
            if path.stat().st_size != artifact.bytes:
                raise SemanticEvidenceError(
                    f"semantic evidence artifact size differs: {relative_path}"
                )
            if _sha256_bytes(path.read_bytes()) != artifact.sha256:
                raise SemanticEvidenceError(
                    f"semantic evidence artifact hash differs: {relative_path}"
                )
        self._verify_ledger_entries(
            directory,
            {path: artifact for path, artifact in expected.items() if path != _ledger_name()},
        )
        self._verify_replayable_snapshot(directory, source_bundle_path=source_bundle_path)
        return manifest

    def load_verified_admission(
        self,
        run_directory: Path,
        *,
        source_bundle_path: Path,
    ) -> tuple[ConcretizationInput, ConcretizationResult, SealedSemanticRun]:
        """Load one replay-verified accepted-or-rejected semantic admission.

        The method first verifies the complete sealed run, including the pinned
        STIX source bundle and deterministic replay.  Consumers receive only
        the typed bounded input and admission record; they never need to trust
        a raw provider output or use private store internals.
        """
        manifest = self.verify(run_directory, source_bundle_path=source_bundle_path)
        directory = run_directory.resolve()
        input_path = directory / self._protocol.provenance.input_document
        admission_path = directory / self._protocol.provenance.admission_document
        if not admission_path.is_file() or admission_path.is_symlink():
            raise SemanticEvidenceError("sealed semantic evidence has no admitted output")
        try:
            request = ConcretizationInput.model_validate_json(input_path.read_text(encoding="utf-8"))
        except ValueError as exc:
            raise SemanticEvidenceError("sealed semantic input has an invalid schema") from exc
        try:
            admission = ConcretizationResult.model_validate_json(
                admission_path.read_text(encoding="utf-8")
            )
        except ValueError as exc:
            raise SemanticEvidenceError("sealed semantic admission has an invalid schema") from exc
        return request, admission, manifest

    def _require_prepared(self, run: PreparedSemanticRun) -> None:
        resolved = run.directory.resolve()
        if not _is_relative_to(resolved, self._root):
            raise SemanticEvidenceError("semantic evidence run is outside the configured root")
        if not resolved.is_dir():
            raise SemanticEvidenceError("semantic evidence run directory is missing")
        if (resolved / self._protocol.provenance.manifest_document).exists():
            raise SemanticEvidenceError("semantic evidence run is already sealed")

    def _validate_prepared_snapshot(
        self,
        run: PreparedSemanticRun,
        request: ConcretizationInput,
    ) -> None:
        """Bind a provider response to the exact input and prompt archived at prepare time."""
        expected_payloads = {
            self._protocol.provenance.protocol_manifest: _canonical_json(self._protocol),
            self._protocol.provenance.input_document: _canonical_json(request),
            self._protocol.provenance.prompt_document: build_prompt(request).encode("utf-8"),
            self._protocol.provenance.response_schema_document: _canonical_json(response_schema()),
        }
        entries = list(run.directory.iterdir())
        if any(not path.is_file() or path.is_symlink() for path in entries):
            raise SemanticEvidenceError("prepared semantic evidence run contains an unsafe entry")
        expected_names = set(expected_payloads) | {_ledger_name()}
        present = {path.name for path in entries}
        if present != expected_names:
            raise SemanticEvidenceError(
                "prepared semantic evidence run does not contain exactly its initial artifacts"
            )
        artifacts: dict[str, ArtifactDigest] = {}
        for name, payload in expected_payloads.items():
            path = run.directory / name
            if path.read_bytes() != payload:
                raise SemanticEvidenceError(
                    f"prepared semantic evidence artifact differs from its input: {name}"
                )
            artifacts[name] = ArtifactDigest(
                path=name,
                sha256=_sha256_bytes(payload),
                bytes=len(payload),
            )
        self._verify_ledger_entries(run.directory, artifacts)

    def _require_no_recorded_output(self, run: PreparedSemanticRun) -> None:
        output_names = {
            self._protocol.provenance.raw_output_document,
            self._protocol.provenance.parsed_proposal_document,
            self._protocol.provenance.admission_document,
            self._protocol.provenance.rejection_document,
            self._protocol.provenance.transport_failure_document,
        }
        present = {path.name for path in run.directory.iterdir()}
        if present.intersection(output_names):
            raise SemanticEvidenceError("semantic evidence run already recorded an output")

    def _admit(
        self,
        request: ConcretizationInput,
        proposal: SemanticProposal,
    ) -> ConcretizationResult:
        result = SemanticConcretizer().concretize(request, proposal)
        blockers = _deduplicate(
            [
                *self._protocol.qualification_blockers(),
                *verify_model_attestation(self._project_root, self._protocol.provider),
                *result.qualification_blockers,
            ]
        )
        return result.model_copy(update={"qualification_blockers": blockers})

    def _run_qualification_blockers(self, run: PreparedSemanticRun) -> list[str]:
        """Keep semantic-stage eligibility separate from campaign claim eligibility."""
        blockers = [
            *self._protocol.qualification_blockers(),
            *verify_model_attestation(self._project_root, self._protocol.provider),
        ]
        admission_path = run.directory / self._protocol.provenance.admission_document
        if admission_path.is_file():
            admission = ConcretizationResult.model_validate_json(
                admission_path.read_text(encoding="utf-8")
            )
            blockers.extend(admission.qualification_blockers)
        else:
            transport_failure_path = (
                run.directory / self._protocol.provenance.transport_failure_document
            )
            if transport_failure_path.is_file():
                blockers.append("semantic provider transport failed before admission")
            else:
                blockers.append("semantic provider output was rejected before admission")
            blockers.append("semantic proposal is not campaign execution evidence")
        return _deduplicate(blockers)

    def _validate_output_layout(self, present: set[str]) -> None:
        """Require either an admitted safe payload or a digest-only rejection, never both."""
        raw_output = self._protocol.provenance.raw_output_document
        rejection = self._protocol.provenance.rejection_document
        transport_failure = self._protocol.provenance.transport_failure_document
        parsed = self._protocol.provenance.parsed_proposal_document
        admission = self._protocol.provenance.admission_document
        output_records = {raw_output, rejection, transport_failure} & present
        if len(output_records) != 1:
            raise SemanticEvidenceError(
                "semantic evidence run must contain exactly one output or transport-failure record"
            )
        if raw_output in output_records:
            missing = {parsed, admission} - present
            if missing:
                raise SemanticEvidenceError(
                    "accepted semantic output is missing derived artifacts: "
                    + ", ".join(sorted(missing))
                )
            return
        forbidden = {parsed, admission} & present
        if forbidden:
            raise SemanticEvidenceError(
                "rejected semantic output must not contain parsed or admitted artifacts: "
                + ", ".join(sorted(forbidden))
            )

    def _allowed_artifact_names(self, present: set[str]) -> set[str]:
        initial = {
            self._protocol.provenance.protocol_manifest,
            self._protocol.provenance.input_document,
            self._protocol.provenance.prompt_document,
            self._protocol.provenance.response_schema_document,
            _ledger_name(),
        }
        if self._protocol.provenance.raw_output_document in present:
            return initial | {
                self._protocol.provenance.raw_output_document,
                self._protocol.provenance.parsed_proposal_document,
                self._protocol.provenance.admission_document,
            }
        return initial | (
            {self._protocol.provenance.rejection_document}
            if self._protocol.provenance.rejection_document in present
            else {self._protocol.provenance.transport_failure_document}
        )

    def _verify_replayable_snapshot(
        self,
        directory: Path,
        *,
        source_bundle_path: Path,
    ) -> None:
        """Check that sealed inputs, prompt, parse, and admission still agree exactly."""
        protocol_path = directory / self._protocol.provenance.protocol_manifest
        if protocol_path.read_bytes() != _canonical_json(self._protocol):
            raise SemanticEvidenceError("sealed protocol manifest differs from the active protocol")
        input_path = directory / self._protocol.provenance.input_document
        try:
            request = ConcretizationInput.model_validate_json(
                input_path.read_text(encoding="utf-8")
            )
        except ValueError as exc:
            raise SemanticEvidenceError("sealed semantic input has an invalid schema") from exc
        if input_path.read_bytes() != _canonical_json(request):
            raise SemanticEvidenceError("sealed semantic input is not canonical")
        self._verify_request_source_bundle(request, source_bundle_path)
        prompt_path = directory / self._protocol.provenance.prompt_document
        if prompt_path.read_bytes() != build_prompt(request).encode("utf-8"):
            raise SemanticEvidenceError("sealed semantic prompt differs from the bounded input")
        schema_path = directory / self._protocol.provenance.response_schema_document
        if schema_path.read_bytes() != _canonical_json(response_schema()):
            raise SemanticEvidenceError(
                "sealed semantic response schema differs from the active schema"
            )
        raw_output_path = directory / self._protocol.provenance.raw_output_document
        if not raw_output_path.exists():
            rejection_path = directory / self._protocol.provenance.rejection_document
            if rejection_path.exists():
                try:
                    RejectedOutputRecord.model_validate_json(
                        rejection_path.read_text(encoding="utf-8")
                    )
                except ValueError as exc:
                    raise SemanticEvidenceError(
                        "sealed semantic rejection record has an invalid schema"
                    ) from exc
            else:
                failure_path = directory / self._protocol.provenance.transport_failure_document
                try:
                    TransportFailureRecord.model_validate_json(
                        failure_path.read_text(encoding="utf-8")
                    )
                except ValueError as exc:
                    raise SemanticEvidenceError(
                        "sealed semantic transport failure record has an invalid schema"
                    ) from exc
            return
        parsed_path = directory / self._protocol.provenance.parsed_proposal_document
        admission_path = directory / self._protocol.provenance.admission_document
        try:
            parsed = SemanticProposal.model_validate_json(parsed_path.read_text(encoding="utf-8"))
        except ValueError as exc:
            raise SemanticEvidenceError(
                "sealed parsed semantic proposal has an invalid schema"
            ) from exc
        try:
            replayed = parse_model_output(
                raw_output_path.read_text(encoding="utf-8"),
                request,
                self._protocol,
                reported_model_id=parsed.provider.reported_model_id,
            )
        except ValueError as exc:
            raise SemanticEvidenceError("sealed raw semantic output cannot be replayed") from exc
        if _canonical_json(parsed) != _canonical_json(replayed):
            raise SemanticEvidenceError("sealed parsed semantic proposal differs from raw output")
        try:
            admission = ConcretizationResult.model_validate_json(
                admission_path.read_text(encoding="utf-8")
            )
        except ValueError as exc:
            raise SemanticEvidenceError("sealed semantic admission has an invalid schema") from exc
        if _canonical_json(admission) != _canonical_json(self._admit(request, replayed)):
            raise SemanticEvidenceError(
                "sealed semantic admission differs from deterministic replay"
            )

    def _verify_request_source_bundle(
        self,
        request: ConcretizationInput,
        source_bundle_path: Path,
    ) -> None:
        """Bind every public CTI anchor to an object in the declared pinned STIX bundle."""
        source_path = source_bundle_path.resolve()
        if not _is_relative_to(source_path, self._project_root):
            raise SemanticEvidenceError("semantic source bundle is outside the project root")
        if not source_bundle_path.is_file() or source_bundle_path.is_symlink():
            raise SemanticEvidenceError("semantic source bundle is missing or unsafe")
        bundle_bytes = source_bundle_path.read_bytes()
        if _sha256_bytes(bundle_bytes) != request.source_bundle_sha256:
            raise SemanticEvidenceError(
                "semantic source bundle hash differs from the bounded input"
            )
        try:
            bundle = json.loads(bundle_bytes)
        except json.JSONDecodeError as exc:
            raise SemanticEvidenceError("semantic source bundle is not valid JSON") from exc
        if not isinstance(bundle, dict) or not isinstance(bundle.get("objects"), list):
            raise SemanticEvidenceError("semantic source bundle must contain an objects list")
        objects = bundle["objects"]
        if len(objects) != request.source_bundle_object_count:
            raise SemanticEvidenceError(
                "semantic source bundle object count differs from the bounded input"
            )
        indexed: dict[str, dict[str, object]] = {}
        for source_object in objects:
            if not isinstance(source_object, dict):
                raise SemanticEvidenceError("semantic source bundle contains a non-object entry")
            object_id = source_object.get("id")
            if not isinstance(object_id, str) or object_id in indexed:
                raise SemanticEvidenceError(
                    "semantic source bundle has an invalid or duplicate object id"
                )
            indexed[object_id] = source_object
        for anchor in request.evidence:
            source_object = indexed.get(anchor.source_object_id)
            if source_object is None:
                raise SemanticEvidenceError(
                    f"semantic source bundle is missing evidence object: {anchor.source_object_id}"
                )
            try:
                verify_evidence_anchor_against_stix_object(anchor, source_object)
            except ValueError as exc:
                raise SemanticEvidenceError(
                    f"semantic evidence anchor does not match its source object: {anchor.anchor_id}"
                ) from exc

    def _verify_ledger_entries(
        self,
        directory: Path,
        expected: dict[str, ArtifactDigest],
    ) -> None:
        ledger = directory / _ledger_name()
        if not ledger.is_file() or ledger.is_symlink():
            raise SemanticEvidenceError("semantic provenance ledger is missing or unsafe")
        raw_ledger = ledger.read_bytes()
        if not raw_ledger.endswith(b"\n"):
            raise SemanticEvidenceError("semantic provenance ledger is not newline terminated")
        entries: list[ArtifactDigest] = []
        for line_number, line in enumerate(raw_ledger.splitlines(), start=1):
            try:
                entries.append(ArtifactDigest.model_validate_json(line))
            except ValueError as exc:
                raise SemanticEvidenceError(
                    f"semantic provenance ledger has an invalid entry at line {line_number}"
                ) from exc
        observed = {entry.path: entry for entry in entries}
        if len(observed) != len(entries) or set(observed) != set(expected):
            raise SemanticEvidenceError(
                "semantic provenance ledger does not cover its artifacts exactly"
            )
        for path, artifact in expected.items():
            if observed[path] != artifact:
                raise SemanticEvidenceError(
                    f"semantic provenance ledger differs from artifact digest: {path}"
                )

    def _write_artifact(
        self, run: PreparedSemanticRun, name: str, payload: bytes
    ) -> ArtifactDigest:
        path = run.directory / name
        artifact = ArtifactDigest(
            path=name,
            sha256=_sha256_bytes(payload),
            bytes=len(payload),
        )
        _write_once(path, payload)
        _append_ledger(run.directory, artifact)
        return artifact


def _append_ledger(directory: Path, artifact: ArtifactDigest) -> None:
    """Append immutable per-file evidence without rewriting prior decisions."""
    ledger = directory / _ledger_name()
    line = _canonical_json(artifact) + b"\n"
    with ledger.open("ab") as destination:
        destination.write(line)
        destination.flush()
        os.fsync(destination.fileno())
    os.chmod(ledger, 0o600)


def _write_once(path: Path, payload: bytes) -> None:
    """Atomically create a private evidence file; replacing history is forbidden."""
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise SemanticEvidenceError(
            f"semantic evidence artifact already exists: {path.name}"
        ) from exc
    with os.fdopen(descriptor, "wb") as destination:
        destination.write(payload)
        destination.flush()
        os.fsync(destination.fileno())


def _canonical_json(value: object) -> bytes:
    if isinstance(value, StrictModel):
        value = value.model_dump(mode="json")
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _raw_output_audit_bytes(value: str) -> bytes:
    """Digest malformed text deterministically without copying it into evidence."""
    return value.encode("utf-8", errors="surrogatepass")


def _resolve_under_root(project_root: Path, relative_path: str) -> Path:
    candidate = (project_root / relative_path).resolve()
    if not _is_relative_to(candidate, project_root):
        raise SemanticEvidenceError("semantic evidence root escapes the project root")
    return candidate


def _is_relative_to(candidate: Path, root: Path) -> bool:
    try:
        candidate.relative_to(root)
    except ValueError:
        return False
    return True


def _safe_child_path(value: str) -> bool:
    return bool(value) and "/" not in value and "\\" not in value and value not in {".", ".."}


def _ledger_name() -> str:
    return "provenance.jsonl"


def _deduplicate(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))


__all__ = [
    "ArtifactDigest",
    "EVIDENCE_SCHEMA_VERSION",
    "PreparedSemanticRun",
    "RejectedOutputRecord",
    "SealedSemanticRun",
    "SemanticEvidenceError",
    "SemanticEvidenceStore",
    "SemanticOutputRejected",
    "TransportFailureRecord",
]
