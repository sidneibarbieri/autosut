"""Hash-bound human adjudication for native-Windows scope decisions.

This module deliberately does *not* infer operating-system semantics from
procedure prose.  It validates a frozen STICKS procedural-plan corpus, uses
ATT&CK platform labels only to select a review queue when the protocol asks for
that triage, and preserves the original relationship descriptions for a human
review.  A positive corpus-scope decision is emitted only after the declared
annotation protocol is complete.

The module has no execution, Docker, VM, network, or LLM dependency.  A corpus
outside this repository may be inspected as an explicit development input, but
that fact is retained in the output and cannot qualify a release decision.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Iterable, Literal, Sequence

from pydantic import BaseModel, ConfigDict, Field, model_validator

from src.planning.procedural_plan import ProceduralPlanInput, load_procedural_plan

PROJECT_ROOT = Path(__file__).resolve().parents[2]


class NativeWindowsAdjudicationError(ValueError):
    """Raised when a corpus, protocol, or annotation breaks the audit contract."""


class CorpusSourceMode(str, Enum):
    """Whether the inspected plan tree is eligible to be a release dependency."""

    EXTERNAL_DEVELOPMENT_INPUT = "external_development_input"
    VENDORED_SNAPSHOT = "vendored_snapshot"


class CandidateSelectionMode(str, Enum):
    """The complete corpus or a label-derived review queue to present to humans."""

    WINDOWS_PLATFORM_LABEL_TRIAGE = "windows_platform_label_triage"
    FULL_COMPILED_CORPUS = "full_compiled_corpus"


class AnnotationDecision(str, Enum):
    """A human conclusion under the bounded protocol, never an automatic inference."""

    REQUIRES_NATIVE_WINDOWS = "requires_native_windows"
    DOES_NOT_REQUIRE_NATIVE_WINDOWS = "does_not_require_native_windows"
    INSUFFICIENT_SOURCE_EVIDENCE = "insufficient_source_evidence"


class AnnotationReasonCode(str, Enum):
    """Identity-free structured rationale categories selected by the human reviewer."""

    EXPLICIT_WINDOWS_OS_OR_PROTOCOL_SEMANTICS = "explicit_windows_os_or_protocol_semantics"
    EXPLICIT_WINDOWS_IDENTITY_OR_DIRECTORY_SEMANTICS = (
        "explicit_windows_identity_or_directory_semantics"
    )
    EXPLICIT_WINDOWS_ONLY_ARTIFACT_OR_RUNTIME = "explicit_windows_only_artifact_or_runtime"
    NO_NATIVE_WINDOWS_SEMANTICS_IN_SCOPED_PROCEDURES = (
        "no_native_windows_semantics_in_scoped_procedures"
    )
    SOURCE_TEXT_INSUFFICIENT = "source_text_insufficient"


class AssessmentStatus(str, Enum):
    """The only states an adjudication gate may report."""

    REQUIRES_ADJUDICATION = "requires_adjudication"
    NOT_QUALIFIED = "not_qualified"
    QUALIFIED = "qualified"


class ScopeDecision(str, Enum):
    """A deliberately narrow conclusion about the reviewed corpus."""

    WITHHELD = "withheld"
    NATIVE_WINDOWS_SCOPE_INDICATED = "native_windows_scope_indicated"
    NATIVE_WINDOWS_SCOPE_NOT_INDICATED = "native_windows_scope_not_indicated"


class PlanCompilationStatus(str, Enum):
    COMPILED = "compiled"
    NOT_COMPILED = "not_compiled"


def _canonical_json_bytes(payload: Any) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_text(value: str) -> str:
    return _sha256_bytes(value.encode("utf-8"))


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _assert_sha256(value: str, field_name: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise NativeWindowsAdjudicationError(f"{field_name} must be a lowercase SHA-256 digest")


def _document_hash(model: BaseModel, field_name: str = "content_sha256") -> str:
    payload = model.model_dump(mode="json", exclude={field_name})
    return _sha256_bytes(_canonical_json_bytes(payload))


def _set_document_hash(model: BaseModel, field_name: str = "content_sha256") -> None:
    setattr(model, field_name, _document_hash(model, field_name))


def _verify_model_hash(model: BaseModel, label: str, field_name: str = "content_sha256") -> None:
    actual = getattr(model, field_name)
    if not isinstance(actual, str):
        raise NativeWindowsAdjudicationError(f"{label} is missing {field_name}")
    _assert_sha256(actual, f"{label}.{field_name}")
    if actual != _document_hash(model, field_name):
        raise NativeWindowsAdjudicationError(f"{label} {field_name} does not bind its model")


def _verify_document_hash(payload: dict[str, Any], field_name: str, label: str) -> None:
    actual = payload.get(field_name)
    if not isinstance(actual, str):
        raise NativeWindowsAdjudicationError(f"{label} is missing {field_name}")
    _assert_sha256(actual, f"{label}.{field_name}")
    expected = _sha256_bytes(
        _canonical_json_bytes({key: value for key, value in payload.items() if key != field_name})
    )
    if actual != expected:
        raise NativeWindowsAdjudicationError(f"{label} {field_name} does not bind its payload")


def _relative_plan_path(root: Path, relative_path: str) -> Path:
    relative = Path(relative_path)
    if relative.is_absolute() or ".." in relative.parts:
        raise NativeWindowsAdjudicationError(
            f"plan path must be a normalized relative path: {relative_path}"
        )
    candidate = (root / relative_path).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError as exc:
        raise NativeWindowsAdjudicationError(
            f"plan path escapes the declared corpus root: {relative_path}"
        ) from exc
    if candidate.suffix != ".json" or not candidate.name.endswith(".procedural-plan.json"):
        raise NativeWindowsAdjudicationError(
            f"plan path is not a procedural-plan JSON file: {relative_path}"
        )
    return candidate


def _ensure_under_project(path: Path, project_root: Path) -> None:
    try:
        path.resolve().relative_to(project_root.resolve())
    except ValueError as exc:
        raise NativeWindowsAdjudicationError(
            "a vendored_snapshot corpus must reside under the AutoSUT project root"
        ) from exc


def _external_id(stix_object: dict[str, Any]) -> str:
    for reference in stix_object.get("external_references", []):
        if reference.get("source_name") == "mitre-attack":
            return str(reference.get("external_id", ""))
    return ""


def _active_campaign_ids(bundle: dict[str, Any]) -> set[str]:
    """Return the full active Enterprise campaign denominator used by STICKS' compiler."""

    campaign_ids: set[str] = set()
    for item in bundle.get("objects", []):
        if not isinstance(item, dict):
            continue
        if item.get("type") != "campaign" or item.get("revoked") or item.get("x_mitre_deprecated"):
            continue
        campaign_id = _external_id(item)
        if campaign_id.startswith("C"):
            campaign_ids.add(campaign_id)
    return campaign_ids


def _stix_objects(bundle: dict[str, Any]) -> dict[str, dict[str, Any]]:
    objects = bundle.get("objects")
    if not isinstance(objects, list):
        raise NativeWindowsAdjudicationError("ATT&CK bundle objects must be a list")
    result: dict[str, dict[str, Any]] = {}
    for item in objects:
        if not isinstance(item, dict) or not isinstance(item.get("id"), str):
            continue
        if item["id"] in result:
            raise NativeWindowsAdjudicationError(f"duplicate ATT&CK object id: {item['id']}")
        result[item["id"]] = item
    return result


class ProceduralPlanIndexEntry(BaseModel):
    """A strict row from STICKS' compiled-plan index."""

    model_config = ConfigDict(extra="forbid")

    campaign_id: str = Field(min_length=1)
    campaign_name: str | None = Field(default=None, min_length=1)
    status: PlanCompilationStatus
    step_count: int | None = Field(default=None, ge=1)
    content_sha256: str | None = None
    path: str | None = Field(default=None, min_length=1)
    reason: str | None = Field(default=None, min_length=1)

    @model_validator(mode="after")
    def _status_fields_are_complete(self) -> "ProceduralPlanIndexEntry":
        if self.status is PlanCompilationStatus.COMPILED:
            missing = [
                name
                for name, value in (
                    ("campaign_name", self.campaign_name),
                    ("step_count", self.step_count),
                    ("content_sha256", self.content_sha256),
                    ("path", self.path),
                )
                if value is None
            ]
            if missing:
                raise ValueError(f"compiled index row is missing {missing}")
            if self.reason is not None:
                raise ValueError("compiled index row must not carry a non-compilation reason")
            _assert_sha256(str(self.content_sha256), "index.content_sha256")
        else:
            if self.reason is None:
                raise ValueError("not_compiled index row must explain why it was not compiled")
            unexpected = [
                name
                for name, value in (
                    ("campaign_name", self.campaign_name),
                    ("step_count", self.step_count),
                    ("content_sha256", self.content_sha256),
                    ("path", self.path),
                )
                if value is not None
            ]
            if unexpected:
                raise ValueError(f"not_compiled index row contains compiled fields {unexpected}")
        return self


class ProceduralPlanIndex(BaseModel):
    """Strict version-1 STICKS enterprise corpus index."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1"]
    bundle_sha256: str
    campaign_count: int = Field(ge=0)
    compiled_count: int = Field(ge=0)
    not_compiled_count: int = Field(ge=0)
    campaigns: list[ProceduralPlanIndexEntry]

    @model_validator(mode="after")
    def _counts_and_ids_are_consistent(self) -> "ProceduralPlanIndex":
        _assert_sha256(self.bundle_sha256, "index.bundle_sha256")
        campaign_ids = [entry.campaign_id for entry in self.campaigns]
        if len(campaign_ids) != len(set(campaign_ids)):
            raise ValueError("STICKS index contains duplicate campaign identifiers")
        if self.campaign_count != len(self.campaigns):
            raise ValueError("STICKS index campaign_count does not match its rows")
        compiled_count = sum(
            entry.status is PlanCompilationStatus.COMPILED for entry in self.campaigns
        )
        if self.compiled_count != compiled_count:
            raise ValueError("STICKS index compiled_count does not match its rows")
        if self.not_compiled_count != self.campaign_count - self.compiled_count:
            raise ValueError("STICKS index not_compiled_count does not match its rows")
        return self


class NativeWindowsAdjudicationProtocol(BaseModel):
    """The frozen protocol controlling candidate selection and consensus rules."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["native-windows-adjudication-protocol/v1"]
    protocol_id: str = Field(min_length=1)
    candidate_selection: CandidateSelectionMode
    required_independent_annotation_count: Literal[1, 2]
    agreement_rule: Literal["unanimous_per_campaign"]
    evidence_review_rule: Literal["review_all_preserved_relationship_evidence"]
    semantic_decision_method: Literal["human_adjudication_only"]
    content_sha256: str

    @model_validator(mode="after")
    def _policy_cannot_enable_automatic_semantics(self) -> "NativeWindowsAdjudicationProtocol":
        _assert_sha256(self.content_sha256, "protocol.content_sha256")
        return self


class FrozenCorpusDescriptor(BaseModel):
    """A path-free record of the inspected source tree and pinned ATT&CK bundle."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["sticks-corpus-source/v1"] = "sticks-corpus-source/v1"
    source_identifier: str = Field(min_length=1)
    source_mode: CorpusSourceMode
    index_sha256: str
    attack_bundle_sha256: str
    attack_bundle_object_count: int = Field(ge=1)
    campaign_count: int = Field(ge=0)
    compiled_count: int = Field(ge=0)
    not_compiled_count: int = Field(ge=0)
    source_root_recording: Literal["omitted_by_design"] = "omitted_by_design"
    release_dependency_status: Literal[
        "external_input_not_release_dependency", "vendored_under_autosut"
    ]

    @model_validator(mode="after")
    def _descriptor_is_self_consistent(self) -> "FrozenCorpusDescriptor":
        _assert_sha256(self.index_sha256, "corpus.index_sha256")
        _assert_sha256(self.attack_bundle_sha256, "corpus.attack_bundle_sha256")
        if self.campaign_count != self.compiled_count + self.not_compiled_count:
            raise ValueError("corpus descriptor campaign counts are inconsistent")
        expected_status = (
            "vendored_under_autosut"
            if self.source_mode is CorpusSourceMode.VENDORED_SNAPSHOT
            else "external_input_not_release_dependency"
        )
        if self.release_dependency_status != expected_status:
            raise ValueError("corpus descriptor source mode and release status disagree")
        return self


class ProcedureEvidenceItem(BaseModel):
    """One copied STIX uses-relationship, preserved without semantic interpretation."""

    model_config = ConfigDict(extra="forbid")

    evidence_item_id: str = Field(min_length=1)
    step_index: int = Field(ge=0)
    technique_id: str = Field(min_length=1)
    technique_stix_id: str = Field(min_length=1)
    technique_name: str = Field(min_length=1)
    technique_platform_labels: list[str]
    relationship_id: str = Field(min_length=1)
    procedure_description: str | None = None
    procedure_description_sha256: str | None = None

    @model_validator(mode="after")
    def _description_hash_binds_the_copied_text(self) -> "ProcedureEvidenceItem":
        if self.procedure_description is None:
            if self.procedure_description_sha256 is not None:
                raise ValueError("a missing procedure description cannot have a digest")
        else:
            if self.procedure_description_sha256 is None:
                raise ValueError("a retained procedure description must have a digest")
            _assert_sha256(self.procedure_description_sha256, "procedure_description_sha256")
            if self.procedure_description_sha256 != _sha256_text(self.procedure_description):
                raise ValueError("procedure description digest does not match copied text")
        return self


class NativeWindowsCandidate(BaseModel):
    """A campaign packet shown to an adjudicator, including all its procedure text."""

    model_config = ConfigDict(extra="forbid")

    candidate_id: str = Field(min_length=1)
    campaign_id: str = Field(min_length=1)
    campaign_name: str = Field(min_length=1)
    plan_relative_path: str = Field(min_length=1)
    plan_file_sha256: str
    plan_content_sha256: str
    source_campaign_stix_id: str = Field(min_length=1)
    source_campaign_external_id: str = Field(min_length=1)
    source_bundle_sha256: str
    source_object_count: int = Field(ge=1)
    triage_reason: Literal["included_by_windows_platform_label", "included_by_full_compiled_corpus"]
    windows_platform_label_technique_ids: list[str]
    evidence_items: list[ProcedureEvidenceItem] = Field(min_length=1)

    @model_validator(mode="after")
    def _candidate_provenance_is_complete(self) -> "NativeWindowsCandidate":
        for field_name in ("plan_file_sha256", "plan_content_sha256", "source_bundle_sha256"):
            _assert_sha256(str(getattr(self, field_name)), field_name)
        if self.candidate_id != self.campaign_id:
            raise ValueError("candidate_id must equal the stable campaign_id")
        if self.source_campaign_external_id != self.campaign_id:
            raise ValueError("candidate source campaign ID does not match candidate ID")
        evidence_ids = [item.evidence_item_id for item in self.evidence_items]
        if len(evidence_ids) != len(set(evidence_ids)):
            raise ValueError("candidate contains duplicate evidence item IDs")
        if self.triage_reason == "included_by_windows_platform_label" and not (
            self.windows_platform_label_technique_ids
        ):
            raise ValueError("label-triage candidates must retain their Windows-labeled techniques")
        return self


class NativeWindowsCandidateSet(BaseModel):
    """The replayable queue produced before any human semantic decision exists."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["native-windows-candidate-set/v1"] = "native-windows-candidate-set/v1"
    protocol_id: str = Field(min_length=1)
    protocol_sha256: str
    corpus: FrozenCorpusDescriptor
    corpus_descriptor_sha256: str
    candidate_selection: CandidateSelectionMode
    candidates: list[NativeWindowsCandidate]
    compiled_campaign_count: int = Field(ge=0)
    selected_candidate_count: int = Field(ge=0)
    nonselected_compiled_campaign_count: int = Field(ge=0)
    not_compiled_campaign_count: int = Field(ge=0)
    non_claim: str = Field(min_length=1)
    content_sha256: str

    @model_validator(mode="after")
    def _candidate_set_is_counted_and_bound(self) -> "NativeWindowsCandidateSet":
        _assert_sha256(self.protocol_sha256, "candidate_set.protocol_sha256")
        _assert_sha256(self.corpus_descriptor_sha256, "candidate_set.corpus_descriptor_sha256")
        _assert_sha256(self.content_sha256, "candidate_set.content_sha256")
        if self.corpus_descriptor_sha256 != corpus_descriptor_sha256(self.corpus):
            raise ValueError("candidate set corpus descriptor digest does not match its descriptor")
        if self.selected_candidate_count != len(self.candidates):
            raise ValueError("candidate set selected_candidate_count does not match candidates")
        if self.compiled_campaign_count != (
            self.selected_candidate_count + self.nonselected_compiled_campaign_count
        ):
            raise ValueError("candidate set compiled campaign accounting is inconsistent")
        if self.not_compiled_campaign_count != self.corpus.not_compiled_count:
            raise ValueError("candidate set not-compiled accounting differs from corpus descriptor")
        if self.compiled_campaign_count != self.corpus.compiled_count:
            raise ValueError("candidate set compiled accounting differs from corpus descriptor")
        candidate_ids = [candidate.campaign_id for candidate in self.candidates]
        if candidate_ids != sorted(candidate_ids):
            raise ValueError("candidate set must use deterministic campaign-ID order")
        if len(candidate_ids) != len(set(candidate_ids)):
            raise ValueError("candidate set contains duplicate campaigns")
        return self


class AnnotationTemplateEntry(BaseModel):
    """An identity-free annotation form paired with immutable evidence packets."""

    model_config = ConfigDict(extra="forbid")

    candidate: NativeWindowsCandidate
    reviewed_evidence_item_ids: list[str]
    decision: None = None
    reason_codes: list[AnnotationReasonCode] = Field(default_factory=list)
    supporting_evidence_item_ids: list[str] = Field(default_factory=list)


class NativeWindowsAnnotationTemplate(BaseModel):
    """A form that intentionally has no annotator identity or free-text fields."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["native-windows-annotation-template/v1"] = (
        "native-windows-annotation-template/v1"
    )
    protocol_id: str = Field(min_length=1)
    protocol_sha256: str
    candidate_set_sha256: str
    corpus_descriptor_sha256: str
    annotation_set_schema_version: Literal["native-windows-annotations/v1"] = (
        "native-windows-annotations/v1"
    )
    identity_policy: Literal["no_personal_or_operator_identity_fields"] = (
        "no_personal_or_operator_identity_fields"
    )
    instructions: list[str] = Field(min_length=1)
    entries: list[AnnotationTemplateEntry]
    content_sha256: str

    @model_validator(mode="after")
    def _template_hashes_are_well_formed(self) -> "NativeWindowsAnnotationTemplate":
        for field_name in (
            "protocol_sha256",
            "candidate_set_sha256",
            "corpus_descriptor_sha256",
            "content_sha256",
        ):
            _assert_sha256(str(getattr(self, field_name)), f"annotation_template.{field_name}")
        return self


class CampaignAnnotation(BaseModel):
    """One structured, identity-free campaign decision made by a human reviewer."""

    model_config = ConfigDict(extra="forbid")

    campaign_id: str = Field(min_length=1)
    decision: AnnotationDecision
    reviewed_evidence_item_ids: list[str] = Field(min_length=1)
    reason_codes: list[AnnotationReasonCode] = Field(min_length=1)
    supporting_evidence_item_ids: list[str] = Field(min_length=1)

    @model_validator(mode="after")
    def _reason_codes_match_the_decision(self) -> "CampaignAnnotation":
        required_codes = {
            AnnotationReasonCode.EXPLICIT_WINDOWS_OS_OR_PROTOCOL_SEMANTICS,
            AnnotationReasonCode.EXPLICIT_WINDOWS_IDENTITY_OR_DIRECTORY_SEMANTICS,
            AnnotationReasonCode.EXPLICIT_WINDOWS_ONLY_ARTIFACT_OR_RUNTIME,
        }
        if self.decision is AnnotationDecision.REQUIRES_NATIVE_WINDOWS:
            if not set(self.reason_codes) <= required_codes:
                raise ValueError("requires_native_windows must cite a Windows-specific reason code")
        elif self.decision is AnnotationDecision.DOES_NOT_REQUIRE_NATIVE_WINDOWS:
            if set(self.reason_codes) != {
                AnnotationReasonCode.NO_NATIVE_WINDOWS_SEMANTICS_IN_SCOPED_PROCEDURES
            }:
                raise ValueError(
                    "does_not_require_native_windows must use the bounded no-native-semantics code"
                )
        elif set(self.reason_codes) != {AnnotationReasonCode.SOURCE_TEXT_INSUFFICIENT}:
            raise ValueError(
                "insufficient_source_evidence must use the source-text-insufficient code"
            )
        if not set(self.supporting_evidence_item_ids) <= set(self.reviewed_evidence_item_ids):
            raise ValueError("supporting evidence must be a subset of reviewed evidence")
        return self


class NativeWindowsAnnotationSet(BaseModel):
    """One completed annotation set with a non-identifying set ID."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["native-windows-annotations/v1"] = "native-windows-annotations/v1"
    protocol_id: str = Field(min_length=1)
    protocol_sha256: str
    candidate_set_sha256: str
    corpus_descriptor_sha256: str
    annotation_set_id: str = Field(min_length=1)
    recorded_at_utc: str = Field(min_length=1)
    annotations: list[CampaignAnnotation]
    content_sha256: str

    @model_validator(mode="after")
    def _annotation_set_is_identity_free_and_time_bound(self) -> "NativeWindowsAnnotationSet":
        for field_name in (
            "protocol_sha256",
            "candidate_set_sha256",
            "corpus_descriptor_sha256",
            "content_sha256",
        ):
            _assert_sha256(str(getattr(self, field_name)), f"annotation_set.{field_name}")
        try:
            timestamp = datetime.fromisoformat(self.recorded_at_utc.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("recorded_at_utc must be an ISO-8601 UTC timestamp") from exc
        if timestamp.tzinfo is None or timestamp.utcoffset() != timedelta(0):
            raise ValueError("recorded_at_utc must use UTC")
        campaign_ids = [annotation.campaign_id for annotation in self.annotations]
        if len(campaign_ids) != len(set(campaign_ids)):
            raise ValueError("annotation set contains duplicate campaign annotations")
        return self


class CampaignAgreement(BaseModel):
    """Agreement accounting for one candidate, not a semantic inference."""

    model_config = ConfigDict(extra="forbid")

    campaign_id: str
    decisions: list[AnnotationDecision]
    agreement: Literal["not_assessed", "single_annotation_protocol", "unanimous", "disagreement"]
    consensus_decision: AnnotationDecision | None = None


class NativeWindowsAdjudicationAssessment(BaseModel):
    """Derived status of a protocol run; no data are silently promoted into claims."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["native-windows-adjudication-assessment/v1"] = (
        "native-windows-adjudication-assessment/v1"
    )
    protocol_id: str
    protocol_sha256: str
    candidate_set_sha256: str
    corpus_descriptor_sha256: str
    annotation_set_ids: list[str]
    required_independent_annotation_count: Literal[1, 2]
    received_annotation_set_count: int = Field(ge=0)
    declared_independence_status: Literal[
        "not_applicable_single_annotation_protocol",
        "distinct_nonidentifying_set_ids_only_independence_not_verifiable",
    ]
    agreements: list[CampaignAgreement]
    adjudication_status: AssessmentStatus
    release_scope_decision_status: AssessmentStatus
    scope_decision: ScopeDecision
    blockers: list[str]
    non_claim: str
    content_sha256: str

    @model_validator(mode="after")
    def _assessment_is_bound_and_counted(self) -> "NativeWindowsAdjudicationAssessment":
        for field_name in (
            "protocol_sha256",
            "candidate_set_sha256",
            "corpus_descriptor_sha256",
            "content_sha256",
        ):
            _assert_sha256(str(getattr(self, field_name)), f"assessment.{field_name}")
        if self.received_annotation_set_count != len(self.annotation_set_ids):
            raise ValueError("assessment annotation-set count does not match its identifiers")
        if self.annotation_set_ids != sorted(self.annotation_set_ids):
            raise ValueError("assessment annotation IDs must be ordered deterministically")
        return self


def corpus_descriptor_sha256(descriptor: FrozenCorpusDescriptor) -> str:
    """Return the path-free descriptor digest copied into every downstream record."""

    return _sha256_bytes(_canonical_json_bytes(descriptor.model_dump(mode="json")))


def new_protocol(
    *,
    protocol_id: str,
    candidate_selection: CandidateSelectionMode = CandidateSelectionMode.WINDOWS_PLATFORM_LABEL_TRIAGE,
    required_independent_annotation_count: Literal[1, 2] = 2,
) -> NativeWindowsAdjudicationProtocol:
    """Create a versioned protocol that must be persisted before human annotation."""

    protocol = NativeWindowsAdjudicationProtocol(
        schema_version="native-windows-adjudication-protocol/v1",
        protocol_id=protocol_id,
        candidate_selection=candidate_selection,
        required_independent_annotation_count=required_independent_annotation_count,
        agreement_rule="unanimous_per_campaign",
        evidence_review_rule="review_all_preserved_relationship_evidence",
        semantic_decision_method="human_adjudication_only",
        content_sha256="0" * 64,
    )
    _set_document_hash(protocol)
    return protocol


def load_protocol(path: Path) -> NativeWindowsAdjudicationProtocol:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise NativeWindowsAdjudicationError("adjudication protocol must be a JSON object")
    _verify_document_hash(payload, "content_sha256", "adjudication protocol")
    return NativeWindowsAdjudicationProtocol.model_validate(payload)


def load_candidate_set(path: Path) -> NativeWindowsCandidateSet:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise NativeWindowsAdjudicationError("candidate set must be a JSON object")
    _verify_document_hash(payload, "content_sha256", "candidate set")
    return NativeWindowsCandidateSet.model_validate(payload)


def load_annotation_set(path: Path) -> NativeWindowsAnnotationSet:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise NativeWindowsAdjudicationError("annotation set must be a JSON object")
    _verify_document_hash(payload, "content_sha256", "annotation set")
    return NativeWindowsAnnotationSet.model_validate(payload)


def finalize_annotation_set(
    annotation_set: NativeWindowsAnnotationSet,
) -> NativeWindowsAnnotationSet:
    """Bind a completed identity-free annotation record before it is persisted."""

    _set_document_hash(annotation_set)
    return annotation_set


def _load_index(corpus_root: Path) -> tuple[ProceduralPlanIndex, str]:
    index_path = corpus_root / "index.json"
    if not index_path.is_file():
        raise NativeWindowsAdjudicationError(f"missing STICKS corpus index: {index_path}")
    raw = index_path.read_bytes()
    payload = json.loads(raw)
    if not isinstance(payload, dict):
        raise NativeWindowsAdjudicationError("STICKS corpus index must be a JSON object")
    return ProceduralPlanIndex.model_validate(payload), _sha256_bytes(raw)


def _verify_plan_provenance(
    *,
    plan_path: Path,
    index_row: ProceduralPlanIndexEntry,
    index: ProceduralPlanIndex,
    stix_objects: dict[str, dict[str, Any]],
    stix_object_count: int,
) -> tuple[ProceduralPlanInput, list[ProcedureEvidenceItem]]:
    """Verify every copied procedure description against its source uses-link."""

    plan = load_procedural_plan(plan_path)
    if plan.campaign_id != index_row.campaign_id:
        raise NativeWindowsAdjudicationError(f"{plan_path}: campaign ID disagrees with index")
    if plan.campaign_name != index_row.campaign_name:
        raise NativeWindowsAdjudicationError(f"{plan_path}: campaign name disagrees with index")
    if len(plan.steps) != index_row.step_count:
        raise NativeWindowsAdjudicationError(f"{plan_path}: step count disagrees with index")
    if plan.content_sha256 != index_row.content_sha256:
        raise NativeWindowsAdjudicationError(f"{plan_path}: content hash disagrees with index")
    if plan.source.bundle_sha256 != index.bundle_sha256:
        raise NativeWindowsAdjudicationError(f"{plan_path}: plan bundle hash disagrees with index")
    if plan.source.object_count != stix_object_count:
        raise NativeWindowsAdjudicationError(
            f"{plan_path}: plan object count disagrees with ATT&CK"
        )
    if plan.source.campaign_external_id != plan.campaign_id:
        raise NativeWindowsAdjudicationError(f"{plan_path}: plan source campaign ID disagrees")

    campaign = stix_objects.get(plan.source.campaign_stix_id)
    if campaign is None or campaign.get("type") != "campaign":
        raise NativeWindowsAdjudicationError(f"{plan_path}: source campaign object is absent")
    if _external_id(campaign) != plan.campaign_id:
        raise NativeWindowsAdjudicationError(
            f"{plan_path}: source campaign ATT&CK external ID disagrees"
        )

    evidence: list[ProcedureEvidenceItem] = []
    observed_relationships: set[str] = set()
    for step_index, step in enumerate(plan.steps):
        technique = stix_objects.get(step.technique_stix_id)
        if technique is None or technique.get("type") != "attack-pattern":
            raise NativeWindowsAdjudicationError(
                f"{plan_path}: source technique is absent for {step.technique_id}"
            )
        if _external_id(technique) != step.technique_id:
            raise NativeWindowsAdjudicationError(
                f"{plan_path}: source technique ATT&CK external ID disagrees for {step.technique_id}"
            )
        platforms = sorted({str(value) for value in technique.get("x_mitre_platforms", [])})
        if step.platforms != platforms:
            raise NativeWindowsAdjudicationError(
                f"{plan_path}: copied platform labels disagree for {step.technique_id}"
            )
        relationships: list[dict[str, Any]] = []
        descriptions: list[str] = []
        for relationship_id in step.relationship_ids:
            if relationship_id in observed_relationships:
                raise NativeWindowsAdjudicationError(
                    f"{plan_path}: duplicate uses-relationship identifier {relationship_id}"
                )
            observed_relationships.add(relationship_id)
            relationship = stix_objects.get(relationship_id)
            if relationship is None:
                raise NativeWindowsAdjudicationError(
                    f"{plan_path}: source relationship is absent for {step.technique_id}"
                )
            relationship_matches_plan = all(
                (
                    relationship.get("type") == "relationship",
                    relationship.get("relationship_type") == "uses",
                    relationship.get("source_ref") == plan.source.campaign_stix_id,
                    relationship.get("target_ref") == step.technique_stix_id,
                )
            )
            if not relationship_matches_plan:
                raise NativeWindowsAdjudicationError(
                    f"{plan_path}: relationship does not bind {step.technique_id} to its campaign"
                )
            relationships.append(relationship)
            if relationship.get("description"):
                descriptions.append(str(relationship["description"]))
        if step.procedure_descriptions != descriptions:
            raise NativeWindowsAdjudicationError(
                f"{plan_path}: copied procedure descriptions do not match source relationships"
            )
        for relationship in relationships:
            description = relationship.get("description")
            copied_description = str(description) if description else None
            relationship_id = str(relationship["id"])
            evidence.append(
                ProcedureEvidenceItem(
                    evidence_item_id=f"{plan.campaign_id}:{relationship_id}",
                    step_index=step_index,
                    technique_id=step.technique_id,
                    technique_stix_id=step.technique_stix_id,
                    technique_name=step.name,
                    technique_platform_labels=platforms,
                    relationship_id=relationship_id,
                    procedure_description=copied_description,
                    procedure_description_sha256=(
                        _sha256_text(copied_description) if copied_description is not None else None
                    ),
                )
            )
    if not evidence:
        raise NativeWindowsAdjudicationError(
            f"{plan_path}: compiled plan has no relationship evidence"
        )
    return plan, evidence


def _iter_compiled_candidates(
    *,
    corpus_root: Path,
    index: ProceduralPlanIndex,
    stix_objects: dict[str, dict[str, Any]],
    stix_object_count: int,
    selection: CandidateSelectionMode,
) -> Iterable[NativeWindowsCandidate]:
    for index_row in sorted(index.campaigns, key=lambda row: row.campaign_id):
        if index_row.status is not PlanCompilationStatus.COMPILED:
            continue
        plan_path = _relative_plan_path(corpus_root, str(index_row.path))
        if not plan_path.is_file():
            raise NativeWindowsAdjudicationError(f"indexed plan is missing: {plan_path}")
        plan, evidence = _verify_plan_provenance(
            plan_path=plan_path,
            index_row=index_row,
            index=index,
            stix_objects=stix_objects,
            stix_object_count=stix_object_count,
        )
        windows_techniques = sorted(
            {step.technique_id for step in plan.steps if "Windows" in step.platforms}
        )
        included = selection is CandidateSelectionMode.FULL_COMPILED_CORPUS or bool(
            windows_techniques
        )
        if not included:
            continue
        yield NativeWindowsCandidate(
            candidate_id=plan.campaign_id,
            campaign_id=plan.campaign_id,
            campaign_name=plan.campaign_name,
            plan_relative_path=str(index_row.path),
            plan_file_sha256=_sha256_file(plan_path),
            plan_content_sha256=plan.content_sha256,
            source_campaign_stix_id=plan.source.campaign_stix_id,
            source_campaign_external_id=plan.source.campaign_external_id,
            source_bundle_sha256=plan.source.bundle_sha256,
            source_object_count=plan.source.object_count,
            triage_reason=(
                "included_by_full_compiled_corpus"
                if selection is CandidateSelectionMode.FULL_COMPILED_CORPUS
                else "included_by_windows_platform_label"
            ),
            windows_platform_label_technique_ids=windows_techniques,
            evidence_items=evidence,
        )


def build_candidate_set(
    *,
    corpus_root: Path,
    attack_bundle_path: Path,
    source_identifier: str,
    source_mode: CorpusSourceMode,
    protocol: NativeWindowsAdjudicationProtocol,
    project_root: Path = PROJECT_ROOT,
) -> NativeWindowsCandidateSet:
    """Validate a pinned STICKS corpus and emit only a review queue, not a conclusion."""

    _verify_model_hash(protocol, "adjudication protocol")
    corpus_root = corpus_root.resolve()
    if not corpus_root.is_dir():
        raise NativeWindowsAdjudicationError(
            f"STICKS corpus root is not a directory: {corpus_root}"
        )
    if source_mode is CorpusSourceMode.VENDORED_SNAPSHOT:
        _ensure_under_project(corpus_root, project_root)
    if not attack_bundle_path.is_file():
        raise NativeWindowsAdjudicationError(
            f"pinned ATT&CK bundle is not a file: {attack_bundle_path}"
        )
    if source_mode is CorpusSourceMode.VENDORED_SNAPSHOT:
        _ensure_under_project(attack_bundle_path, project_root)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", source_identifier):
        raise NativeWindowsAdjudicationError(
            "source_identifier must be a path-free logical identifier using letters, digits, '.', '_', or '-'"
        )

    index, index_sha256 = _load_index(corpus_root)
    bundle_bytes = attack_bundle_path.read_bytes()
    bundle_sha256 = _sha256_bytes(bundle_bytes)
    if index.bundle_sha256 != bundle_sha256:
        raise NativeWindowsAdjudicationError(
            "STICKS index bundle digest differs from the explicitly supplied ATT&CK bundle"
        )
    attack_bundle = json.loads(bundle_bytes)
    if not isinstance(attack_bundle, dict):
        raise NativeWindowsAdjudicationError("ATT&CK bundle must be a JSON object")
    expected_campaign_ids = _active_campaign_ids(attack_bundle)
    indexed_campaign_ids = {row.campaign_id for row in index.campaigns}
    if indexed_campaign_ids != expected_campaign_ids:
        missing = sorted(expected_campaign_ids - indexed_campaign_ids)
        unexpected = sorted(indexed_campaign_ids - expected_campaign_ids)
        raise NativeWindowsAdjudicationError(
            "STICKS index is not a full active-campaign corpus for the supplied ATT&CK bundle: "
            f"missing={missing}, unexpected={unexpected}"
        )
    stix_objects = _stix_objects(attack_bundle)
    stix_object_count = len(attack_bundle.get("objects", []))
    candidates = list(
        _iter_compiled_candidates(
            corpus_root=corpus_root,
            index=index,
            stix_objects=stix_objects,
            stix_object_count=stix_object_count,
            selection=protocol.candidate_selection,
        )
    )
    descriptor = FrozenCorpusDescriptor(
        source_identifier=source_identifier,
        source_mode=source_mode,
        index_sha256=index_sha256,
        attack_bundle_sha256=bundle_sha256,
        attack_bundle_object_count=stix_object_count,
        campaign_count=index.campaign_count,
        compiled_count=index.compiled_count,
        not_compiled_count=index.not_compiled_count,
        release_dependency_status=(
            "vendored_under_autosut"
            if source_mode is CorpusSourceMode.VENDORED_SNAPSHOT
            else "external_input_not_release_dependency"
        ),
    )
    candidate_set = NativeWindowsCandidateSet(
        protocol_id=protocol.protocol_id,
        protocol_sha256=protocol.content_sha256,
        corpus=descriptor,
        corpus_descriptor_sha256=corpus_descriptor_sha256(descriptor),
        candidate_selection=protocol.candidate_selection,
        candidates=candidates,
        compiled_campaign_count=index.compiled_count,
        selected_candidate_count=len(candidates),
        nonselected_compiled_campaign_count=index.compiled_count - len(candidates),
        not_compiled_campaign_count=index.not_compiled_count,
        non_claim=(
            "This is a deterministic human-review queue. ATT&CK platform labels only select "
            "candidates; no native-Windows semantic conclusion was inferred from labels, "
            "procedure text, keywords, or an LLM. Nonselected campaigns were not semantically "
            "adjudicated by this queue."
        ),
        content_sha256="0" * 64,
    )
    _set_document_hash(candidate_set)
    return candidate_set


def build_annotation_template(
    *,
    candidate_set: NativeWindowsCandidateSet,
    protocol: NativeWindowsAdjudicationProtocol,
) -> NativeWindowsAnnotationTemplate:
    """Create a no-identity form with all source text needed for manual review."""

    _validate_protocol_matches_candidate_set(protocol, candidate_set)
    template = NativeWindowsAnnotationTemplate(
        protocol_id=protocol.protocol_id,
        protocol_sha256=protocol.content_sha256,
        candidate_set_sha256=candidate_set.content_sha256,
        corpus_descriptor_sha256=candidate_set.corpus_descriptor_sha256,
        instructions=[
            "Review every preserved relationship-evidence item for each campaign.",
            "ATT&CK platform labels are triage metadata, not semantic proof.",
            "Do not add names, email addresses, host names, credentials, or free-text notes.",
            "Select only a protocol decision and structured reason code supported by the preserved evidence.",
            "If source text does not justify a decision, select insufficient_source_evidence.",
        ],
        entries=[
            AnnotationTemplateEntry(
                candidate=candidate,
                reviewed_evidence_item_ids=[
                    item.evidence_item_id for item in candidate.evidence_items
                ],
            )
            for candidate in candidate_set.candidates
        ],
        content_sha256="0" * 64,
    )
    _set_document_hash(template)
    return template


def _validate_protocol_matches_candidate_set(
    protocol: NativeWindowsAdjudicationProtocol,
    candidate_set: NativeWindowsCandidateSet,
) -> None:
    _verify_model_hash(protocol, "adjudication protocol")
    _verify_model_hash(candidate_set, "candidate set")
    if candidate_set.protocol_id != protocol.protocol_id:
        raise NativeWindowsAdjudicationError("candidate set protocol ID does not match protocol")
    if candidate_set.protocol_sha256 != protocol.content_sha256:
        raise NativeWindowsAdjudicationError(
            "candidate set protocol digest does not match protocol"
        )
    if candidate_set.candidate_selection is not protocol.candidate_selection:
        raise NativeWindowsAdjudicationError("candidate set selection differs from protocol")


def _expected_evidence_ids(candidate: NativeWindowsCandidate) -> list[str]:
    return [item.evidence_item_id for item in candidate.evidence_items]


def validate_annotation_set(
    *,
    annotation_set: NativeWindowsAnnotationSet,
    candidate_set: NativeWindowsCandidateSet,
    protocol: NativeWindowsAdjudicationProtocol,
) -> None:
    """Reject incomplete, unbound, or identity-expanding annotation records."""

    _validate_protocol_matches_candidate_set(protocol, candidate_set)
    _verify_model_hash(annotation_set, "annotation set")
    if annotation_set.protocol_id != protocol.protocol_id:
        raise NativeWindowsAdjudicationError("annotation protocol ID does not match")
    if annotation_set.protocol_sha256 != protocol.content_sha256:
        raise NativeWindowsAdjudicationError("annotation protocol digest does not match")
    if annotation_set.candidate_set_sha256 != candidate_set.content_sha256:
        raise NativeWindowsAdjudicationError("annotation candidate set digest does not match")
    if annotation_set.corpus_descriptor_sha256 != candidate_set.corpus_descriptor_sha256:
        raise NativeWindowsAdjudicationError("annotation corpus descriptor digest does not match")

    annotations_by_campaign = {
        annotation.campaign_id: annotation for annotation in annotation_set.annotations
    }
    expected_campaigns = [candidate.campaign_id for candidate in candidate_set.candidates]
    if set(annotations_by_campaign) != set(expected_campaigns):
        missing = sorted(set(expected_campaigns) - set(annotations_by_campaign))
        unexpected = sorted(set(annotations_by_campaign) - set(expected_campaigns))
        raise NativeWindowsAdjudicationError(
            f"annotation coverage differs from candidate set: missing={missing}, unexpected={unexpected}"
        )
    for candidate in candidate_set.candidates:
        annotation = annotations_by_campaign[candidate.campaign_id]
        expected_evidence = _expected_evidence_ids(candidate)
        if annotation.reviewed_evidence_item_ids != expected_evidence:
            raise NativeWindowsAdjudicationError(
                f"{candidate.campaign_id}: reviewed evidence must be the complete ordered packet"
            )
        if not set(annotation.supporting_evidence_item_ids) <= set(expected_evidence):
            raise NativeWindowsAdjudicationError(
                f"{candidate.campaign_id}: supporting evidence is outside the candidate packet"
            )


def _agreement_rows(
    candidate_set: NativeWindowsCandidateSet,
    annotation_sets: Sequence[NativeWindowsAnnotationSet],
    required_count: Literal[1, 2],
) -> list[CampaignAgreement]:
    annotations_by_set = [
        {annotation.campaign_id: annotation for annotation in annotation_set.annotations}
        for annotation_set in annotation_sets
    ]
    rows: list[CampaignAgreement] = []
    for candidate in candidate_set.candidates:
        decisions = [
            by_campaign[candidate.campaign_id].decision for by_campaign in annotations_by_set
        ]
        if len(decisions) < required_count:
            rows.append(
                CampaignAgreement(
                    campaign_id=candidate.campaign_id,
                    decisions=decisions,
                    agreement="not_assessed",
                )
            )
        elif required_count == 1:
            rows.append(
                CampaignAgreement(
                    campaign_id=candidate.campaign_id,
                    decisions=decisions,
                    agreement="single_annotation_protocol",
                    consensus_decision=decisions[0],
                )
            )
        elif len(set(decisions)) == 1:
            rows.append(
                CampaignAgreement(
                    campaign_id=candidate.campaign_id,
                    decisions=decisions,
                    agreement="unanimous",
                    consensus_decision=decisions[0],
                )
            )
        else:
            rows.append(
                CampaignAgreement(
                    campaign_id=candidate.campaign_id,
                    decisions=decisions,
                    agreement="disagreement",
                )
            )
    return rows


def assess_adjudication(
    *,
    candidate_set: NativeWindowsCandidateSet,
    protocol: NativeWindowsAdjudicationProtocol,
    annotation_sets: Sequence[NativeWindowsAnnotationSet],
) -> NativeWindowsAdjudicationAssessment:
    """Account for annotation completeness and consensus without resolving disagreement."""

    _validate_protocol_matches_candidate_set(protocol, candidate_set)
    if len(annotation_sets) > protocol.required_independent_annotation_count:
        raise NativeWindowsAdjudicationError(
            "received more annotation sets than the frozen protocol permits"
        )
    annotation_ids = [annotation_set.annotation_set_id for annotation_set in annotation_sets]
    if len(annotation_ids) != len(set(annotation_ids)):
        raise NativeWindowsAdjudicationError("annotation set IDs must be distinct")
    for annotation_set in annotation_sets:
        validate_annotation_set(
            annotation_set=annotation_set,
            candidate_set=candidate_set,
            protocol=protocol,
        )

    ordered_annotation_sets = sorted(annotation_sets, key=lambda item: item.annotation_set_id)
    agreements = _agreement_rows(
        candidate_set,
        ordered_annotation_sets,
        protocol.required_independent_annotation_count,
    )
    blockers: list[str] = []
    if not candidate_set.candidates:
        blockers.append(
            "the selected candidate set is empty, so no corpus scope can be established"
        )
    if len(ordered_annotation_sets) < protocol.required_independent_annotation_count:
        blockers.append(
            "the frozen protocol requires "
            f"{protocol.required_independent_annotation_count} complete annotation set(s), but "
            f"only {len(ordered_annotation_sets)} were supplied"
        )
    if any(row.agreement == "disagreement" for row in agreements):
        blockers.append("at least one campaign has unresolved annotation disagreement")

    if blockers:
        adjudication_status = AssessmentStatus.REQUIRES_ADJUDICATION
    elif any(
        row.consensus_decision is AnnotationDecision.INSUFFICIENT_SOURCE_EVIDENCE
        for row in agreements
    ):
        adjudication_status = AssessmentStatus.NOT_QUALIFIED
        blockers.append(
            "at least one complete consensus reports insufficient source text for a semantic decision"
        )
    else:
        adjudication_status = AssessmentStatus.QUALIFIED

    scope_decision = ScopeDecision.WITHHELD
    release_scope_status = adjudication_status
    if candidate_set.corpus.source_mode is CorpusSourceMode.EXTERNAL_DEVELOPMENT_INPUT:
        release_scope_status = AssessmentStatus.NOT_QUALIFIED
        blockers.append(
            "the inspected corpus is an explicit external development input and has not been "
            "vendored under AutoSUT; it cannot become a release dependency"
        )
    elif adjudication_status is AssessmentStatus.QUALIFIED:
        consensus = [row.consensus_decision for row in agreements]
        if AnnotationDecision.REQUIRES_NATIVE_WINDOWS in consensus:
            scope_decision = ScopeDecision.NATIVE_WINDOWS_SCOPE_INDICATED
        elif candidate_set.candidate_selection is CandidateSelectionMode.FULL_COMPILED_CORPUS:
            scope_decision = ScopeDecision.NATIVE_WINDOWS_SCOPE_NOT_INDICATED
        else:
            release_scope_status = AssessmentStatus.NOT_QUALIFIED
            blockers.append(
                "a platform-label triage queue can establish a positive witness but cannot "
                "establish a negative corpus-wide native-Windows conclusion for nonselected campaigns"
            )

    independence_status = (
        "not_applicable_single_annotation_protocol"
        if protocol.required_independent_annotation_count == 1
        else "distinct_nonidentifying_set_ids_only_independence_not_verifiable"
    )
    assessment = NativeWindowsAdjudicationAssessment(
        protocol_id=protocol.protocol_id,
        protocol_sha256=protocol.content_sha256,
        candidate_set_sha256=candidate_set.content_sha256,
        corpus_descriptor_sha256=candidate_set.corpus_descriptor_sha256,
        annotation_set_ids=sorted(annotation_ids),
        required_independent_annotation_count=protocol.required_independent_annotation_count,
        received_annotation_set_count=len(ordered_annotation_sets),
        declared_independence_status=independence_status,
        agreements=agreements,
        adjudication_status=adjudication_status,
        release_scope_decision_status=release_scope_status,
        scope_decision=scope_decision,
        blockers=sorted(set(blockers)),
        non_claim=(
            "This assessment does not qualify a Windows backend, VM image, campaign execution, "
            "or historical replay. It only accounts for a hash-bound human adjudication protocol."
        ),
        content_sha256="0" * 64,
    )
    _set_document_hash(assessment)
    return assessment


def write_json(path: Path, document: BaseModel) -> None:
    """Persist a canonical pretty JSON view whose embedded digest binds the canonical payload."""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(document.model_dump_json(indent=2) + "\n", encoding="utf-8")
