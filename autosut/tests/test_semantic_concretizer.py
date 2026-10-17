"""Closed-schema regression tests for the non-executing Step-2 protocol."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from cti.semantic_concretizer import (  # noqa: E402
    ArtifactConfig,
    AttestationEvidence,
    ConcretizationInput,
    Decision,
    EvidenceAnchor,
    GenerationPolicy,
    LocalOpenAICompatibleProvider,
    LocalModelAttestationRecord,
    ModelAttestation,
    ModelAttestationStatus,
    MAX_MODEL_OUTPUT_BYTES,
    MAX_PUBLIC_CTI_EXCERPT_CHARS,
    PlatformFamily,
    ProtocolLifecycle,
    PublicCtiExcerptDerivation,
    PublicCtiSourceKind,
    ProviderKind,
    ProvenanceLayout,
    SemanticConcretizer,
    SemanticEnrichmentProtocol,
    SemanticFieldKind,
    build_openai_compatible_request,
    derive_evidence_anchor_from_stix_object,
    derive_public_cti_excerpt,
    load_artifact_config,
    parse_model_output,
    response_schema,
    verify_model_attestation,
    verify_evidence_anchor_against_stix_object,
)

_SOURCE_OBJECT = {
    "id": "attack-pattern--example",
    "type": "attack-pattern",
    "description": "The procedure targets a public-facing web service before later access.",
}
_SOURCE_BUNDLE_BYTES = json.dumps(
    {"type": "bundle", "objects": [_SOURCE_OBJECT]},
    sort_keys=True,
    separators=(",", ":"),
).encode("utf-8")
_SOURCE_BUNDLE_SHA256 = hashlib.sha256(_SOURCE_BUNDLE_BYTES).hexdigest()


def _request() -> ConcretizationInput:
    return ConcretizationInput(
        campaign_id="C0045",
        technique_id="T1190",
        source_bundle_sha256=_SOURCE_BUNDLE_SHA256,
        source_bundle_object_count=1,
        allowed_platforms=[PlatformFamily.LINUX],
        evidence=[
            derive_evidence_anchor_from_stix_object(
                anchor_id="attack-platforms",
                source_object=_SOURCE_OBJECT,
                source_field="description",
                source_kind=PublicCtiSourceKind.STIX_PROCEDURE,
            )
        ],
        unresolved_fields=[
            SemanticFieldKind.SOFTWARE_ROLE,
            SemanticFieldKind.NETWORK_EXPOSURE,
        ],
    )


def _protocol(
    *,
    lifecycle: ProtocolLifecycle = ProtocolLifecycle.DRAFT,
    attestation: ModelAttestation | None = None,
) -> SemanticEnrichmentProtocol:
    return SemanticEnrichmentProtocol(
        protocol_id="autosut-step2-semantic-enrichment-v1",
        lifecycle=lifecycle,
        provider=LocalOpenAICompatibleProvider(
            kind=ProviderKind.LOCAL_OPENAI_COMPATIBLE,
            base_url="http://127.0.0.1:1234/v1",
            model_id="local-test-model",
            generation=GenerationPolicy(seed=0, max_output_tokens=512),
            model_attestation=attestation or ModelAttestation(),
        ),
        provenance=ProvenanceLayout(root="release/experiments/semantic_enrichment/runs"),
    )


def _payload(*, fields: list[dict[str, object]] | None = None) -> str:
    return json.dumps(
        {
            "campaign_id": "C0045",
            "technique_id": "T1190",
            "fields": fields
            or [
                {
                    "kind": "software_role",
                    "value": "web_service",
                    "evidence_ids": ["attack-platforms"],
                },
                {
                    "kind": "network_exposure",
                    "value": "controlled_ingress",
                    "evidence_ids": ["attack-platforms"],
                },
            ],
        },
        sort_keys=True,
    )


def test_no_proposal_preserves_unresolved_information() -> None:
    result = SemanticConcretizer().concretize(_request())
    assert result.decision is Decision.REQUIRES_ENRICHMENT
    assert result.proposal is None
    assert result.qualification_blockers == ["no Step-2 proposal was available"]


def test_closed_payload_is_admitted_but_unverified_model_blocks_qualification() -> None:
    request = _request()
    proposal = parse_model_output(
        _payload(), request, _protocol(), reported_model_id="local-test-model"
    )

    result = SemanticConcretizer().concretize(request, proposal)

    assert result.decision is Decision.ACCEPTED
    assert result.proposal is not None
    assert result.qualification_blockers == [
        "semantic proposal is not campaign execution evidence",
        "local model identity is unverified",
    ]


def test_platform_outside_declared_boundary_is_rejected() -> None:
    request = _request()
    raw = _payload(
        fields=[
            {
                "kind": "platform",
                "value": "windows",
                "evidence_ids": ["attack-platforms"],
            }
        ]
    )
    proposal = parse_model_output(raw, request, _protocol(), reported_model_id="local-test-model")

    result = SemanticConcretizer().concretize(request, proposal)

    assert result.decision is Decision.REJECTED
    assert "proposal platform is outside allowed_platforms" in result.rejected_reasons


def test_unrequested_semantic_field_is_rejected() -> None:
    request = _request()
    raw = _payload(
        fields=[
            {
                "kind": "credential_requirement",
                "value": "valid_account",
                "evidence_ids": ["attack-platforms"],
            }
        ]
    )
    proposal = parse_model_output(raw, request, _protocol(), reported_model_id="local-test-model")

    result = SemanticConcretizer().concretize(request, proposal)

    assert result.decision is Decision.REJECTED
    assert "proposal includes fields not declared unresolved" in result.rejected_reasons[0]


def test_unknown_evidence_anchor_is_rejected() -> None:
    request = _request()
    raw = _payload(
        fields=[
            {
                "kind": "software_role",
                "value": "web_service",
                "evidence_ids": ["invented-anchor"],
            }
        ]
    )
    proposal = parse_model_output(raw, request, _protocol(), reported_model_id="local-test-model")

    result = SemanticConcretizer().concretize(request, proposal)

    assert result.decision is Decision.REJECTED
    assert "software_role references unknown evidence anchors" in result.rejected_reasons[0]


def test_free_form_commands_parameters_and_credentials_are_not_in_response_schema() -> None:
    request = _request()
    raw = _payload(
        fields=[
            {
                "kind": "software_role",
                "value": "curl target",
                "evidence_ids": ["attack-platforms"],
                "parameters": "--dangerous",
            }
        ]
    )

    with pytest.raises(ValidationError):
        parse_model_output(raw, request, _protocol(), reported_model_id="local-test-model")


def test_provider_response_identity_is_required_and_must_match_the_request() -> None:
    request = _request()

    with pytest.raises(ValueError, match="omitted its model identifier"):
        parse_model_output(_payload(), request, _protocol())
    with pytest.raises(ValueError, match="differs from the requested model"):
        parse_model_output(
            _payload(),
            request,
            _protocol(),
            reported_model_id="different-local-model",
        )


def test_duplicate_keys_and_unbounded_raw_output_are_rejected_before_admission() -> None:
    request = _request()
    duplicate_key_payload = (
        '{"campaign_id":"C0045","technique_id":"T1190","fields":['
        '{"kind":"software_role","value":"password=not-a-credential",'
        '"value":"web_service","evidence_ids":["attack-platforms"]}]}'
    )
    with pytest.raises(ValueError, match="invalid JSON output"):
        parse_model_output(
            duplicate_key_payload,
            request,
            _protocol(),
            reported_model_id="local-test-model",
        )

    oversized = "{" + (" " * MAX_MODEL_OUTPUT_BYTES) + "}"
    with pytest.raises(ValueError, match="byte limit"):
        parse_model_output(
            oversized,
            request,
            _protocol(),
            reported_model_id="local-test-model",
        )


def test_evidence_ids_cannot_carry_free_text() -> None:
    raw = _payload(
        fields=[
            {
                "kind": "software_role",
                "value": "web_service",
                "evidence_ids": ["api_key=not-a-credential"],
            }
        ]
    )

    with pytest.raises(ValidationError, match="compact protocol identifiers"):
        parse_model_output(
            raw,
            _request(),
            _protocol(),
            reported_model_id="local-test-model",
        )


def test_identifier_paths_reject_token_shaped_text() -> None:
    token_shaped_value = "sk-abcdefghijklmnop"
    request_payload = _request().model_dump(mode="json")
    request_payload["campaign_id"] = token_shaped_value
    with pytest.raises(ValidationError, match="campaign_id"):
        ConcretizationInput.model_validate(request_payload)

    raw = _payload().replace('"C0045"', f'"{token_shaped_value}"', 1)
    with pytest.raises(ValidationError, match="campaign_id"):
        parse_model_output(
            raw,
            _request(),
            _protocol(),
            reported_model_id="local-test-model",
        )

    with pytest.raises(ValidationError, match="model_id"):
        LocalOpenAICompatibleProvider(
            kind=ProviderKind.LOCAL_OPENAI_COMPATIBLE,
            base_url="http://127.0.0.1:1234/v1",
            model_id=token_shaped_value,
            generation=GenerationPolicy(seed=0, max_output_tokens=512),
            model_attestation=ModelAttestation(),
        )


def test_openai_compatible_request_is_only_a_serializable_contract() -> None:
    request = _request()
    provider_request = build_openai_compatible_request(_protocol(), request)

    assert provider_request.provider_kind is ProviderKind.LOCAL_OPENAI_COMPATIBLE
    assert provider_request.endpoint == "http://127.0.0.1:1234/v1/chat/completions"
    assert provider_request.temperature == 0.0
    assert provider_request.seed == 0
    assert "api_key" not in provider_request.model_dump_json().lower()
    assert request.input_sha256 in provider_request.messages[1].content
    assert "Response schema JSON:" in provider_request.messages[1].content
    assert request.evidence[0].excerpt.text in provider_request.messages[1].content
    assert request.evidence[0].excerpt.text_sha256 in provider_request.messages[1].content
    assert "127.0.0.1:1234" not in provider_request.messages[1].content
    assert "local-test-model" not in provider_request.messages[1].content
    assert "api_key" not in provider_request.messages[1].content


def test_public_cti_excerpt_digest_binds_the_exact_prompt_content() -> None:
    request = _request()
    payload = request.evidence[0].model_dump(mode="json")
    payload["excerpt"]["text"] = "tampered public source text"

    with pytest.raises(ValidationError, match="text_sha256"):
        EvidenceAnchor.model_validate(payload)

    payload = request.evidence[0].model_dump(mode="json")
    payload["excerpt"]["source_field_sha256"] = "b" * 64
    with pytest.raises(ValidationError, match="exact source text"):
        EvidenceAnchor.model_validate(payload)

    changed_excerpt = derive_public_cti_excerpt(
        "The procedure targets a different public-facing service.",
        source_kind=PublicCtiSourceKind.STIX_PROCEDURE,
    )
    changed_request = ConcretizationInput(
        campaign_id=request.campaign_id,
        technique_id=request.technique_id,
        source_bundle_sha256=request.source_bundle_sha256,
        source_bundle_object_count=request.source_bundle_object_count,
        allowed_platforms=request.allowed_platforms,
        evidence=[request.evidence[0].model_copy(update={"excerpt": changed_excerpt})],
        unresolved_fields=request.unresolved_fields,
    )
    assert changed_request.input_sha256 != request.input_sha256


def test_evidence_anchor_can_be_recomputed_against_its_pinned_stix_object() -> None:
    source_object = {
        "id": "relationship--example",
        "type": "relationship",
        "description": "The public procedure targets a web service.",
    }
    anchor = derive_evidence_anchor_from_stix_object(
        anchor_id="uses-procedure",
        source_object=source_object,
        source_field="description",
        source_kind=PublicCtiSourceKind.STIX_PROCEDURE,
    )

    verify_evidence_anchor_against_stix_object(anchor, source_object)

    changed_object = {**source_object, "description": "Different source text."}
    with pytest.raises(ValueError, match="does not match"):
        verify_evidence_anchor_against_stix_object(anchor, changed_object)


def test_public_cti_excerpt_is_bounded_and_rejects_disallowed_controls() -> None:
    with pytest.raises(ValueError, match="control character"):
        derive_public_cti_excerpt(
            "procedure\x00text",
            source_kind=PublicCtiSourceKind.STIX_PROCEDURE,
        )

    with pytest.raises(ValidationError, match="at most"):
        derive_public_cti_excerpt(
            "x" * (MAX_PUBLIC_CTI_EXCERPT_CHARS + 1),
            source_kind=PublicCtiSourceKind.STIX_PROCEDURE,
        )


def test_public_cti_normalization_redacts_material_like_configuration_values() -> None:
    source_text = "Public reporting notes api_key=private-value for the service."
    with pytest.raises(ValidationError, match="credential data"):
        derive_public_cti_excerpt(
            source_text,
            source_kind=PublicCtiSourceKind.STIX_SOURCE_TEXT,
        )

    excerpt = derive_public_cti_excerpt(
        source_text,
        source_kind=PublicCtiSourceKind.STIX_SOURCE_TEXT,
        derivation=PublicCtiExcerptDerivation.NORMALIZED_PUBLIC_CONTEXT_V1,
    )
    assert "private-value" not in excerpt.text
    assert "api_key=[REDACTED]" in excerpt.text

    with pytest.raises(ValidationError):
        EvidenceAnchor.model_validate(
            {
                **_request().evidence[0].model_dump(mode="json"),
                "api_key": "must-not-cross-the-boundary",
            }
        )


def test_normalized_public_cti_context_binds_the_original_source_field() -> None:
    first = derive_public_cti_excerpt(
        "The procedure   targets a public-facing web service.\n",
        source_kind=PublicCtiSourceKind.STIX_PROCEDURE,
        derivation=PublicCtiExcerptDerivation.NORMALIZED_PUBLIC_CONTEXT_V1,
    )
    second = derive_public_cti_excerpt(
        "The procedure targets a public-facing web service.",
        source_kind=PublicCtiSourceKind.STIX_PROCEDURE,
        derivation=PublicCtiExcerptDerivation.NORMALIZED_PUBLIC_CONTEXT_V1,
    )

    assert first.text == second.text
    assert first.text_sha256 == second.text_sha256
    assert first.source_field_sha256 != second.source_field_sha256


def test_noncanonical_or_secret_bearing_endpoint_configuration_is_rejected() -> None:
    with pytest.raises(ValidationError, match="canonical local endpoint"):
        LocalOpenAICompatibleProvider(
            kind=ProviderKind.LOCAL_OPENAI_COMPATIBLE,
            base_url="https://example.invalid/v1",
            model_id="model",
            generation=GenerationPolicy(seed=0, max_output_tokens=512),
            model_attestation=ModelAttestation(),
        )

    with pytest.raises(ValidationError, match="credentials"):
        LocalOpenAICompatibleProvider(
            kind=ProviderKind.LOCAL_OPENAI_COMPATIBLE,
            base_url="http://user:secret@127.0.0.1:1234/v1",
            model_id="model",
            generation=GenerationPolicy(seed=0, max_output_tokens=512),
            model_attestation=ModelAttestation(),
        )

    with pytest.raises(ValidationError, match="canonical local endpoint"):
        LocalOpenAICompatibleProvider(
            kind=ProviderKind.LOCAL_OPENAI_COMPATIBLE,
            base_url="http://localhost:1234/v1",
            model_id="model",
            generation=GenerationPolicy(seed=0, max_output_tokens=512),
            model_attestation=ModelAttestation(),
        )

    with pytest.raises(ValidationError, match="canonical local endpoint"):
        LocalOpenAICompatibleProvider(
            kind=ProviderKind.LOCAL_OPENAI_COMPATIBLE,
            base_url="http://127.0.0.1:11434/v1",
            model_id="model",
            generation=GenerationPolicy(seed=0, max_output_tokens=512),
            model_attestation=ModelAttestation(),
        )

    with pytest.raises(ValidationError, match="canonical local endpoint"):
        LocalOpenAICompatibleProvider(
            kind=ProviderKind.LOCAL_OPENAI_COMPATIBLE,
            base_url="http://[::1]:1234/v1",
            model_id="model",
            generation=GenerationPolicy(seed=0, max_output_tokens=512),
            model_attestation=ModelAttestation(),
        )


def test_model_digest_is_not_self_attesting() -> None:
    unverified = ModelAttestation(reported_model_digest="b" * 64)
    assert not unverified.is_qualification_eligible
    assert _protocol(attestation=unverified).qualification_blockers() == [
        "semantic-enrichment protocol is not frozen",
        "local model identity is unverified",
    ]


def test_frozen_protocol_requires_hash_bound_attestation_evidence() -> None:
    verified = ModelAttestation(
        status=ModelAttestationStatus.VERIFIED,
        reported_model_digest="b" * 64,
        evidence=AttestationEvidence(
            method="runtime_inventory_sha256",
            record_path="release/experiments/semantic_enrichment/model-inventory.json",
            record_sha256="c" * 64,
            attested_model_digest="b" * 64,
        ),
    )

    assert (
        _protocol(
            lifecycle=ProtocolLifecycle.FROZEN,
            attestation=verified,
        ).qualification_blockers()
        == []
    )


def test_verified_attestation_must_match_a_real_hash_bound_record(tmp_path: Path) -> None:
    record = LocalModelAttestationRecord(
        provider_kind=ProviderKind.LOCAL_OPENAI_COMPATIBLE,
        model_id="local-test-model",
        observed_model_digest="b" * 64,
        method="runtime_inventory_sha256",
    )
    record_path = tmp_path / "release" / "experiments" / "semantic_enrichment" / "model.json"
    record_path.parent.mkdir(parents=True)
    record_bytes = record.model_dump_json().encode("utf-8")
    record_path.write_bytes(record_bytes)
    verified = ModelAttestation(
        status=ModelAttestationStatus.VERIFIED,
        reported_model_digest="b" * 64,
        evidence=AttestationEvidence(
            method="runtime_inventory_sha256",
            record_path="release/experiments/semantic_enrichment/model.json",
            record_sha256=hashlib.sha256(record_bytes).hexdigest(),
            attested_model_digest="b" * 64,
        ),
    )
    protocol = _protocol(lifecycle=ProtocolLifecycle.FROZEN, attestation=verified)

    assert verify_model_attestation(tmp_path, protocol.provider) == ()

    record_path.write_text("tampered\n", encoding="utf-8")
    assert verify_model_attestation(tmp_path, protocol.provider) == (
        "model attestation evidence hash differs",
    )


def test_example_config_is_strict_and_documents_the_only_canonical_provider() -> None:
    config = load_artifact_config(str(PROJECT_ROOT / "config.example.json"))

    assert isinstance(config, ArtifactConfig)
    assert config.semantic_enrichment.provider.kind is ProviderKind.LOCAL_OPENAI_COMPATIBLE
    assert config.semantic_enrichment.provider.request_timeout_seconds == 60
    assert config.semantic_enrichment.lifecycle is ProtocolLifecycle.DRAFT
    assert config.semantic_enrichment.provenance.root == "results/evidence/semantic_enrichment/runs"
    assert config.semantic_enrichment.qualification_blockers() == [
        "semantic-enrichment protocol is not frozen",
        "local model identity is unverified",
    ]

    payload = config.model_dump(mode="json")
    payload["semantic_enrichment"]["provider"]["api_key_env"] = "SHOULD_NOT_EXIST"
    with pytest.raises(ValidationError):
        ArtifactConfig.model_validate(payload)


def test_response_schema_is_closed_and_versioned() -> None:
    schema = response_schema()

    assert schema["$id"] == "autosut.step2.semantic-enrichment.response/v1"
    assert schema["additionalProperties"] is False
