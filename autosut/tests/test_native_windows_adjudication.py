"""Tests for the non-decisive STICKS corpus and Windows-scope review protocol."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.cti.native_windows_adjudication import (  # noqa: E402
    AnnotationDecision,
    AnnotationReasonCode,
    AssessmentStatus,
    CandidateSelectionMode,
    CampaignAnnotation,
    CorpusSourceMode,
    NativeWindowsAnnotationSet,
    NativeWindowsAdjudicationError,
    ScopeDecision,
    assess_adjudication,
    build_annotation_template,
    build_candidate_set,
    finalize_annotation_set,
    load_annotation_set,
    new_protocol,
    write_json,
)


def _canonical_sha256(payload: dict) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _write_plan(
    path: Path,
    *,
    campaign_id: str,
    campaign_name: str,
    campaign_stix_id: str,
    technique_id: str,
    technique_stix_id: str,
    technique_name: str,
    platforms: list[str],
    relationship_id: str,
    description: str,
    object_count: int,
    bundle_sha256: str,
) -> dict:
    payload = {
        "schema_version": "1",
        "compiler_version": "1",
        "campaign_id": campaign_id,
        "campaign_name": campaign_name,
        "source": {
            "bundle_sha256": bundle_sha256,
            "object_count": object_count,
            "campaign_stix_id": campaign_stix_id,
            "campaign_external_id": campaign_id,
        },
        "ordering_policy": "tactic_rank_then_technique_id",
        "steps": [
            {
                "technique_id": technique_id,
                "technique_stix_id": technique_stix_id,
                "name": technique_name,
                "execution_domain": "target",
                "tactics": ["execution"],
                "platforms": platforms,
                "permissions_required": [],
                "system_requirements": [],
                "relationship_ids": [relationship_id],
                "procedure_descriptions": [description],
            }
        ],
        "limitations": [],
    }
    payload["content_sha256"] = _canonical_sha256(payload)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return payload


def _write_corpus(tmp_path: Path) -> tuple[Path, Path]:
    corpus_root = tmp_path / "source" / "enterprise"
    corpus_root.mkdir(parents=True)
    attack_bundle = {
        "type": "bundle",
        "objects": [
            {
                "id": "campaign--windows",
                "type": "campaign",
                "external_references": [{"source_name": "mitre-attack", "external_id": "CWIN"}],
            },
            {
                "id": "campaign--linux",
                "type": "campaign",
                "external_references": [{"source_name": "mitre-attack", "external_id": "CLINUX"}],
            },
            {
                "id": "campaign--empty",
                "type": "campaign",
                "external_references": [{"source_name": "mitre-attack", "external_id": "CEMPTY"}],
            },
            {
                "id": "attack-pattern--windows",
                "type": "attack-pattern",
                "name": "Windows-capable technique",
                "x_mitre_platforms": ["Linux", "Windows"],
                "external_references": [{"source_name": "mitre-attack", "external_id": "T9001"}],
            },
            {
                "id": "attack-pattern--linux",
                "type": "attack-pattern",
                "name": "Linux technique",
                "x_mitre_platforms": ["Linux"],
                "external_references": [{"source_name": "mitre-attack", "external_id": "T9002"}],
            },
            {
                "id": "relationship--windows",
                "type": "relationship",
                "relationship_type": "uses",
                "source_ref": "campaign--windows",
                "target_ref": "attack-pattern--windows",
                "description": "The procedure uses a declared laboratory service.",
            },
            {
                "id": "relationship--linux",
                "type": "relationship",
                "relationship_type": "uses",
                "source_ref": "campaign--linux",
                "target_ref": "attack-pattern--linux",
                "description": "The source prose happens to mention Windows but labels this technique Linux.",
            },
        ],
    }
    bundle_path = tmp_path / "attack" / "enterprise-attack.json"
    bundle_path.parent.mkdir(parents=True)
    bundle_path.write_text(json.dumps(attack_bundle, indent=2) + "\n", encoding="utf-8")
    bundle_sha256 = hashlib.sha256(bundle_path.read_bytes()).hexdigest()
    object_count = len(attack_bundle["objects"])
    windows = _write_plan(
        corpus_root / "CWIN.procedural-plan.json",
        campaign_id="CWIN",
        campaign_name="Windows candidate",
        campaign_stix_id="campaign--windows",
        technique_id="T9001",
        technique_stix_id="attack-pattern--windows",
        technique_name="Windows-capable technique",
        platforms=["Linux", "Windows"],
        relationship_id="relationship--windows",
        description="The procedure uses a declared laboratory service.",
        object_count=object_count,
        bundle_sha256=bundle_sha256,
    )
    linux = _write_plan(
        corpus_root / "CLINUX.procedural-plan.json",
        campaign_id="CLINUX",
        campaign_name="Linux-only candidate",
        campaign_stix_id="campaign--linux",
        technique_id="T9002",
        technique_stix_id="attack-pattern--linux",
        technique_name="Linux technique",
        platforms=["Linux"],
        relationship_id="relationship--linux",
        description="The source prose happens to mention Windows but labels this technique Linux.",
        object_count=object_count,
        bundle_sha256=bundle_sha256,
    )
    index = {
        "schema_version": "1",
        "bundle_sha256": bundle_sha256,
        "campaign_count": 3,
        "compiled_count": 2,
        "not_compiled_count": 1,
        "campaigns": [
            {
                "campaign_id": "CWIN",
                "campaign_name": "Windows candidate",
                "status": "compiled",
                "step_count": 1,
                "content_sha256": windows["content_sha256"],
                "path": "CWIN.procedural-plan.json",
            },
            {
                "campaign_id": "CLINUX",
                "campaign_name": "Linux-only candidate",
                "status": "compiled",
                "step_count": 1,
                "content_sha256": linux["content_sha256"],
                "path": "CLINUX.procedural-plan.json",
            },
            {
                "campaign_id": "CEMPTY",
                "status": "not_compiled",
                "reason": "campaign CEMPTY has no active technique uses-links",
            },
        ],
    }
    (corpus_root / "index.json").write_text(json.dumps(index, indent=2) + "\n", encoding="utf-8")
    return corpus_root, bundle_path


def _annotation_set(
    *,
    candidate_set,
    protocol,
    annotation_set_id: str,
    decisions: dict[str, AnnotationDecision],
) -> NativeWindowsAnnotationSet:
    annotations = []
    for candidate in candidate_set.candidates:
        evidence_ids = [item.evidence_item_id for item in candidate.evidence_items]
        decision = decisions[candidate.campaign_id]
        if decision is AnnotationDecision.REQUIRES_NATIVE_WINDOWS:
            reasons = [AnnotationReasonCode.EXPLICIT_WINDOWS_OS_OR_PROTOCOL_SEMANTICS]
        elif decision is AnnotationDecision.DOES_NOT_REQUIRE_NATIVE_WINDOWS:
            reasons = [AnnotationReasonCode.NO_NATIVE_WINDOWS_SEMANTICS_IN_SCOPED_PROCEDURES]
        else:
            reasons = [AnnotationReasonCode.SOURCE_TEXT_INSUFFICIENT]
        annotations.append(
            CampaignAnnotation(
                campaign_id=candidate.campaign_id,
                decision=decision,
                reviewed_evidence_item_ids=evidence_ids,
                reason_codes=reasons,
                supporting_evidence_item_ids=[evidence_ids[0]],
            )
        )
    return finalize_annotation_set(
        NativeWindowsAnnotationSet(
            protocol_id=protocol.protocol_id,
            protocol_sha256=protocol.content_sha256,
            candidate_set_sha256=candidate_set.content_sha256,
            corpus_descriptor_sha256=candidate_set.corpus_descriptor_sha256,
            annotation_set_id=annotation_set_id,
            recorded_at_utc="2026-08-09T00:00:00Z",
            annotations=annotations,
            content_sha256="0" * 64,
        )
    )


def test_triage_uses_platform_labels_not_procedure_keywords_and_preserves_text(
    tmp_path: Path,
) -> None:
    corpus_root, bundle_path = _write_corpus(tmp_path)
    protocol = new_protocol(protocol_id="test-triage-v1")

    candidate_set = build_candidate_set(
        corpus_root=corpus_root,
        attack_bundle_path=bundle_path,
        source_identifier="test-sticks-corpus",
        source_mode=CorpusSourceMode.EXTERNAL_DEVELOPMENT_INPUT,
        protocol=protocol,
        project_root=tmp_path / "autosut",
    )

    assert candidate_set.compiled_campaign_count == 2
    assert candidate_set.selected_candidate_count == 1
    assert candidate_set.nonselected_compiled_campaign_count == 1
    candidate = candidate_set.candidates[0]
    assert candidate.campaign_id == "CWIN"
    assert candidate.windows_platform_label_technique_ids == ["T9001"]
    assert candidate.evidence_items[0].procedure_description == (
        "The procedure uses a declared laboratory service."
    )
    assert "Windows" not in candidate.evidence_items[0].procedure_description
    assert str(corpus_root) not in candidate_set.model_dump_json()
    assert candidate_set.corpus.release_dependency_status == "external_input_not_release_dependency"
    assert "not semantically adjudicated" in candidate_set.non_claim

    template = build_annotation_template(candidate_set=candidate_set, protocol=protocol)
    assert template.identity_policy == "no_personal_or_operator_identity_fields"
    assert template.entries[0].reviewed_evidence_item_ids == [
        candidate.evidence_items[0].evidence_item_id
    ]
    assert template.entries[0].decision is None


def test_full_corpus_selection_does_not_turn_platform_labels_into_semantic_conclusions(
    tmp_path: Path,
) -> None:
    corpus_root, bundle_path = _write_corpus(tmp_path)
    protocol = new_protocol(
        protocol_id="test-full-v1",
        candidate_selection=CandidateSelectionMode.FULL_COMPILED_CORPUS,
    )

    candidate_set = build_candidate_set(
        corpus_root=corpus_root,
        attack_bundle_path=bundle_path,
        source_identifier="test-sticks-corpus",
        source_mode=CorpusSourceMode.EXTERNAL_DEVELOPMENT_INPUT,
        protocol=protocol,
        project_root=tmp_path / "autosut",
    )

    assert [candidate.campaign_id for candidate in candidate_set.candidates] == ["CLINUX", "CWIN"]
    linux_candidate = candidate_set.candidates[0]
    assert linux_candidate.windows_platform_label_technique_ids == []
    assert "Windows" in str(linux_candidate.evidence_items[0].procedure_description)
    assert linux_candidate.triage_reason == "included_by_full_compiled_corpus"


def test_tampered_procedure_text_fails_provenance_validation(tmp_path: Path) -> None:
    corpus_root, bundle_path = _write_corpus(tmp_path)
    plan_path = corpus_root / "CWIN.procedural-plan.json"
    payload = json.loads(plan_path.read_text(encoding="utf-8"))
    payload["steps"][0]["procedure_descriptions"] = ["A different description."]
    hash_payload = {key: value for key, value in payload.items() if key != "content_sha256"}
    payload["content_sha256"] = _canonical_sha256(hash_payload)
    plan_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    index = json.loads((corpus_root / "index.json").read_text(encoding="utf-8"))
    index["campaigns"][0]["content_sha256"] = payload["content_sha256"]
    (corpus_root / "index.json").write_text(json.dumps(index, indent=2) + "\n", encoding="utf-8")

    protocol = new_protocol(protocol_id="test-tamper-v1")
    with pytest.raises(NativeWindowsAdjudicationError, match="copied procedure descriptions"):
        build_candidate_set(
            corpus_root=corpus_root,
            attack_bundle_path=bundle_path,
            source_identifier="test-sticks-corpus",
            source_mode=CorpusSourceMode.EXTERNAL_DEVELOPMENT_INPUT,
            protocol=protocol,
            project_root=tmp_path / "autosut",
        )


def test_index_must_cover_every_active_campaign_in_the_pinned_bundle(tmp_path: Path) -> None:
    corpus_root, bundle_path = _write_corpus(tmp_path)
    index_path = corpus_root / "index.json"
    index = json.loads(index_path.read_text(encoding="utf-8"))
    index["campaigns"] = index["campaigns"][:-1]
    index["campaign_count"] = 2
    index["not_compiled_count"] = 0
    index_path.write_text(json.dumps(index, indent=2) + "\n", encoding="utf-8")

    with pytest.raises(NativeWindowsAdjudicationError, match="not a full active-campaign corpus"):
        build_candidate_set(
            corpus_root=corpus_root,
            attack_bundle_path=bundle_path,
            source_identifier="test-sticks-corpus",
            source_mode=CorpusSourceMode.EXTERNAL_DEVELOPMENT_INPUT,
            protocol=new_protocol(protocol_id="test-completeness-v1"),
            project_root=tmp_path / "autosut",
        )


def test_annotation_assessment_requires_two_complete_agreeing_sets_for_a_vendored_scope(
    tmp_path: Path,
) -> None:
    project_root = tmp_path / "autosut"
    corpus_root, bundle_path = _write_corpus(project_root)
    protocol = new_protocol(
        protocol_id="test-adjudication-v1",
        candidate_selection=CandidateSelectionMode.FULL_COMPILED_CORPUS,
        required_independent_annotation_count=2,
    )
    candidate_set = build_candidate_set(
        corpus_root=corpus_root,
        attack_bundle_path=bundle_path,
        source_identifier="vendored-test-sticks-corpus",
        source_mode=CorpusSourceMode.VENDORED_SNAPSHOT,
        protocol=protocol,
        project_root=project_root,
    )
    decisions = {
        "CLINUX": AnnotationDecision.DOES_NOT_REQUIRE_NATIVE_WINDOWS,
        "CWIN": AnnotationDecision.REQUIRES_NATIVE_WINDOWS,
    }
    first = _annotation_set(
        candidate_set=candidate_set,
        protocol=protocol,
        annotation_set_id="blind-a",
        decisions=decisions,
    )
    first_path = tmp_path / "blind-a.annotations.json"
    write_json(first_path, first)
    first = load_annotation_set(first_path)
    pending = assess_adjudication(
        candidate_set=candidate_set,
        protocol=protocol,
        annotation_sets=[first],
    )
    assert pending.adjudication_status is AssessmentStatus.REQUIRES_ADJUDICATION
    assert pending.release_scope_decision_status is AssessmentStatus.REQUIRES_ADJUDICATION

    second = _annotation_set(
        candidate_set=candidate_set,
        protocol=protocol,
        annotation_set_id="blind-b",
        decisions=decisions,
    )
    assessed = assess_adjudication(
        candidate_set=candidate_set,
        protocol=protocol,
        annotation_sets=[second, first],
    )
    assert assessed.adjudication_status is AssessmentStatus.QUALIFIED
    assert assessed.release_scope_decision_status is AssessmentStatus.QUALIFIED
    assert assessed.scope_decision is ScopeDecision.NATIVE_WINDOWS_SCOPE_INDICATED
    assert assessed.declared_independence_status == (
        "distinct_nonidentifying_set_ids_only_independence_not_verifiable"
    )
    assert all(row.agreement == "unanimous" for row in assessed.agreements)


def test_disagreeing_annotation_sets_remain_requires_adjudication(tmp_path: Path) -> None:
    project_root = tmp_path / "autosut"
    corpus_root, bundle_path = _write_corpus(project_root)
    protocol = new_protocol(
        protocol_id="test-disagreement-v1",
        candidate_selection=CandidateSelectionMode.FULL_COMPILED_CORPUS,
    )
    candidate_set = build_candidate_set(
        corpus_root=corpus_root,
        attack_bundle_path=bundle_path,
        source_identifier="vendored-test-sticks-corpus",
        source_mode=CorpusSourceMode.VENDORED_SNAPSHOT,
        protocol=protocol,
        project_root=project_root,
    )
    first = _annotation_set(
        candidate_set=candidate_set,
        protocol=protocol,
        annotation_set_id="blind-a",
        decisions={
            "CLINUX": AnnotationDecision.DOES_NOT_REQUIRE_NATIVE_WINDOWS,
            "CWIN": AnnotationDecision.REQUIRES_NATIVE_WINDOWS,
        },
    )
    second = _annotation_set(
        candidate_set=candidate_set,
        protocol=protocol,
        annotation_set_id="blind-b",
        decisions={
            "CLINUX": AnnotationDecision.DOES_NOT_REQUIRE_NATIVE_WINDOWS,
            "CWIN": AnnotationDecision.INSUFFICIENT_SOURCE_EVIDENCE,
        },
    )

    assessed = assess_adjudication(
        candidate_set=candidate_set,
        protocol=protocol,
        annotation_sets=[first, second],
    )
    by_campaign = {row.campaign_id: row for row in assessed.agreements}
    assert assessed.adjudication_status is AssessmentStatus.REQUIRES_ADJUDICATION
    assert assessed.release_scope_decision_status is AssessmentStatus.REQUIRES_ADJUDICATION
    assert by_campaign["CWIN"].agreement == "disagreement"
    assert by_campaign["CWIN"].consensus_decision is None


def test_label_triage_cannot_support_a_negative_corpus_decision(tmp_path: Path) -> None:
    project_root = tmp_path / "autosut"
    corpus_root, bundle_path = _write_corpus(project_root)
    protocol = new_protocol(protocol_id="test-negative-triage-v1")
    candidate_set = build_candidate_set(
        corpus_root=corpus_root,
        attack_bundle_path=bundle_path,
        source_identifier="vendored-test-sticks-corpus",
        source_mode=CorpusSourceMode.VENDORED_SNAPSHOT,
        protocol=protocol,
        project_root=project_root,
    )
    decisions = {"CWIN": AnnotationDecision.DOES_NOT_REQUIRE_NATIVE_WINDOWS}
    assessed = assess_adjudication(
        candidate_set=candidate_set,
        protocol=protocol,
        annotation_sets=[
            _annotation_set(
                candidate_set=candidate_set,
                protocol=protocol,
                annotation_set_id="blind-a",
                decisions=decisions,
            ),
            _annotation_set(
                candidate_set=candidate_set,
                protocol=protocol,
                annotation_set_id="blind-b",
                decisions=decisions,
            ),
        ],
    )
    assert assessed.adjudication_status is AssessmentStatus.QUALIFIED
    assert assessed.release_scope_decision_status is AssessmentStatus.NOT_QUALIFIED
    assert assessed.scope_decision is ScopeDecision.WITHHELD
    assert any("negative corpus-wide" in blocker for blocker in assessed.blockers)


def test_annotation_models_reject_identity_fields_and_incomplete_evidence(tmp_path: Path) -> None:
    corpus_root, bundle_path = _write_corpus(tmp_path)
    protocol = new_protocol(protocol_id="test-identity-v1")
    candidate_set = build_candidate_set(
        corpus_root=corpus_root,
        attack_bundle_path=bundle_path,
        source_identifier="test-sticks-corpus",
        source_mode=CorpusSourceMode.EXTERNAL_DEVELOPMENT_INPUT,
        protocol=protocol,
        project_root=tmp_path / "autosut",
    )
    with pytest.raises(ValidationError):
        NativeWindowsAnnotationSet.model_validate(
            {
                "schema_version": "native-windows-annotations/v1",
                "protocol_id": protocol.protocol_id,
                "protocol_sha256": protocol.content_sha256,
                "candidate_set_sha256": candidate_set.content_sha256,
                "corpus_descriptor_sha256": candidate_set.corpus_descriptor_sha256,
                "annotation_set_id": "blind-a",
                "recorded_at_utc": "2026-08-09T00:00:00Z",
                "annotations": [],
                "content_sha256": "0" * 64,
                "annotator_email": "reviewer@example.test",
            }
        )

    incomplete = _annotation_set(
        candidate_set=candidate_set,
        protocol=protocol,
        annotation_set_id="blind-a",
        decisions={"CWIN": AnnotationDecision.INSUFFICIENT_SOURCE_EVIDENCE},
    )
    incomplete.annotations[0].reviewed_evidence_item_ids = []
    finalize_annotation_set(incomplete)
    with pytest.raises(NativeWindowsAdjudicationError, match="complete ordered packet"):
        assess_adjudication(
            candidate_set=candidate_set,
            protocol=protocol,
            annotation_sets=[incomplete],
        )


def test_direct_annotation_mutation_cannot_bypass_the_hash_binding(tmp_path: Path) -> None:
    corpus_root, bundle_path = _write_corpus(tmp_path)
    protocol = new_protocol(protocol_id="test-hash-binding-v1")
    candidate_set = build_candidate_set(
        corpus_root=corpus_root,
        attack_bundle_path=bundle_path,
        source_identifier="test-sticks-corpus",
        source_mode=CorpusSourceMode.EXTERNAL_DEVELOPMENT_INPUT,
        protocol=protocol,
        project_root=tmp_path / "autosut",
    )
    annotation = _annotation_set(
        candidate_set=candidate_set,
        protocol=protocol,
        annotation_set_id="blind-a",
        decisions={"CWIN": AnnotationDecision.INSUFFICIENT_SOURCE_EVIDENCE},
    )
    annotation.annotations[0].decision = AnnotationDecision.DOES_NOT_REQUIRE_NATIVE_WINDOWS

    with pytest.raises(NativeWindowsAdjudicationError, match="does not bind its model"):
        assess_adjudication(
            candidate_set=candidate_set,
            protocol=protocol,
            annotation_sets=[annotation],
        )
