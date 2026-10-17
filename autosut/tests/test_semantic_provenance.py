"""Evidence-store tests for immutable non-executing Step-2 provenance."""

from __future__ import annotations

import json
import hashlib
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from cti.semantic_concretizer import (  # noqa: E402
    AttestationEvidence,
    ConcretizationInput,
    GenerationPolicy,
    LocalOpenAICompatibleProvider,
    ModelAttestation,
    ModelAttestationStatus,
    PlatformFamily,
    ProtocolLifecycle,
    PublicCtiSourceKind,
    ProviderKind,
    ProvenanceLayout,
    SemanticEnrichmentProtocol,
    SemanticFieldKind,
    derive_evidence_anchor_from_stix_object,
)
from cti.semantic_provenance import (  # noqa: E402
    SemanticEvidenceError,
    SemanticEvidenceStore,
    SemanticOutputRejected,
)

_SOURCE_OBJECT = {
    "id": "attack-pattern--example",
    "type": "attack-pattern",
    "description": "The public procedure relies on a web service in the laboratory.",
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
                anchor_id="stix-platforms",
                source_object=_SOURCE_OBJECT,
                source_field="description",
                source_kind=PublicCtiSourceKind.STIX_PROCEDURE,
            )
        ],
        unresolved_fields=[SemanticFieldKind.SOFTWARE_ROLE],
    )


def _write_source_bundle(tmp_path: Path) -> Path:
    source_path = tmp_path / "data" / "stix" / "enterprise-attack.json"
    source_path.parent.mkdir(parents=True, exist_ok=True)
    source_path.write_bytes(_SOURCE_BUNDLE_BYTES)
    return source_path


def _prepare(
    store: SemanticEvidenceStore,
    tmp_path: Path,
    run_id: str,
    request: ConcretizationInput,
):
    return store.prepare(
        run_id,
        request,
        source_bundle_path=_write_source_bundle(tmp_path),
    )


def _protocol(
    tmp_path: Path,
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
        provenance=ProvenanceLayout(root="evidence-runs"),
    )


def _valid_output() -> str:
    return json.dumps(
        {
            "campaign_id": "C0045",
            "technique_id": "T1190",
            "fields": [
                {
                    "kind": "software_role",
                    "value": "web_service",
                    "evidence_ids": ["stix-platforms"],
                }
            ],
        },
        sort_keys=True,
    )


def test_store_seals_and_verifies_the_complete_safe_provenance_chain(tmp_path: Path) -> None:
    protocol = _protocol(tmp_path)
    store = SemanticEvidenceStore(tmp_path, protocol)
    source_bundle_path = _write_source_bundle(tmp_path)
    run = store.prepare("SE-0001", _request(), source_bundle_path=source_bundle_path)

    result = store.record_output(
        run, _request(), _valid_output(), reported_model_id="local-test-model"
    )
    manifest = store.seal(run)
    verified = store.verify(run.directory, source_bundle_path=source_bundle_path)

    assert result.decision.value == "accepted"
    assert result.qualification_blockers == [
        "semantic-enrichment protocol is not frozen",
        "local model identity is unverified",
        "semantic proposal is not campaign execution evidence",
    ]
    assert not manifest.is_qualification_eligible
    assert verified == manifest
    assert (run.directory / "raw-model-output.json").is_file()
    assert (run.directory / "parsed-proposal.json").is_file()
    assert (run.directory / "admission.json").is_file()
    assert (run.directory / "provenance.jsonl").is_file()
    stored_input = json.loads((run.directory / "input.json").read_text(encoding="utf-8"))
    stored_excerpt = stored_input["evidence"][0]["excerpt"]
    assert (
        stored_excerpt["text"] == "The public procedure relies on a web service in the laboratory."
    )
    assert stored_excerpt["text_sha256"] == _request().evidence[0].excerpt.text_sha256

    with pytest.raises(SemanticEvidenceError, match="already sealed"):
        store.record_output(run, _request(), _valid_output())

    raw_output_path = run.directory / "raw-model-output.json"
    raw_output_path.write_text("tampered", encoding="utf-8")
    with pytest.raises(SemanticEvidenceError, match="differs"):
        store.verify(run.directory, source_bundle_path=source_bundle_path)


def test_malformed_output_is_never_archived_verbatim_but_its_digest_is_recorded(
    tmp_path: Path,
) -> None:
    store = SemanticEvidenceStore(tmp_path, _protocol(tmp_path))
    source_bundle_path = _write_source_bundle(tmp_path)
    run = store.prepare("SE-0002", _request(), source_bundle_path=source_bundle_path)

    with pytest.raises(SemanticOutputRejected, match="closed-schema"):
        store.record_output(run, _request(), "not-json-with-a-secret-like-value")

    assert not (run.directory / "raw-model-output.json").exists()
    rejection = json.loads((run.directory / "rejected-output.json").read_text(encoding="utf-8"))
    assert rejection["rejection_type"] == "closed_schema_rejected"
    assert "not-json" not in (run.directory / "rejected-output.json").read_text(encoding="utf-8")

    manifest = store.seal(run)
    assert store.verify(run.directory, source_bundle_path=source_bundle_path) == manifest


def test_schema_rejected_command_json_is_never_archived_verbatim(tmp_path: Path) -> None:
    store = SemanticEvidenceStore(tmp_path, _protocol(tmp_path))
    run = _prepare(store, tmp_path, "SE-0004", _request())
    unsafe_output = json.dumps(
        {
            "campaign_id": "C0045",
            "technique_id": "T1190",
            "fields": [
                {
                    "kind": "software_role",
                    "value": "web_service",
                    "evidence_ids": ["stix-platforms"],
                    "command": "not admitted",
                }
            ],
        }
    )

    with pytest.raises(SemanticOutputRejected):
        store.record_output(run, _request(), unsafe_output)

    assert not (run.directory / "raw-model-output.json").exists()
    assert "command" not in (run.directory / "rejected-output.json").read_text(encoding="utf-8")


def test_duplicate_key_output_is_never_archived_verbatim(tmp_path: Path) -> None:
    store = SemanticEvidenceStore(tmp_path, _protocol(tmp_path))
    source_bundle_path = _write_source_bundle(tmp_path)
    run = store.prepare(
        "SE-0004-duplicate",
        _request(),
        source_bundle_path=source_bundle_path,
    )
    unsafe_output = (
        '{"campaign_id":"C0045","technique_id":"T1190","fields":['
        '{"kind":"software_role","value":"password=not-a-credential",'
        '"value":"web_service","evidence_ids":["stix-platforms"]}]}'
    )

    with pytest.raises(SemanticOutputRejected):
        store.record_output(
            run,
            _request(),
            unsafe_output,
            reported_model_id="local-test-model",
        )

    assert not (run.directory / "raw-model-output.json").exists()
    rejection = (run.directory / "rejected-output.json").read_text(encoding="utf-8")
    assert "password" not in rejection
    manifest = store.seal(run)
    assert manifest.run_id == "SE-0004-duplicate"
    assert store.verify(run.directory, source_bundle_path=source_bundle_path) == manifest


def test_invalid_unicode_output_is_quarantined_without_leaving_an_unsealed_run(
    tmp_path: Path,
) -> None:
    store = SemanticEvidenceStore(tmp_path, _protocol(tmp_path))
    source_bundle_path = _write_source_bundle(tmp_path)
    run = store.prepare(
        "SE-0004-invalid-unicode",
        _request(),
        source_bundle_path=source_bundle_path,
    )

    with pytest.raises(SemanticOutputRejected):
        store.record_output(
            run,
            _request(),
            "\ud800",
            reported_model_id="local-test-model",
        )

    assert not (run.directory / "raw-model-output.json").exists()
    manifest = store.seal(run)
    assert store.verify(run.directory, source_bundle_path=source_bundle_path) == manifest


def test_record_output_cannot_switch_the_bounded_input_after_prepare(tmp_path: Path) -> None:
    store = SemanticEvidenceStore(tmp_path, _protocol(tmp_path))
    original = _request()
    run = _prepare(store, tmp_path, "SE-0004-switched-input", original)
    changed = ConcretizationInput(
        campaign_id="C0046",
        technique_id=original.technique_id,
        source_bundle_sha256=original.source_bundle_sha256,
        source_bundle_object_count=original.source_bundle_object_count,
        allowed_platforms=original.allowed_platforms,
        evidence=original.evidence,
        unresolved_fields=original.unresolved_fields,
    )

    with pytest.raises(SemanticEvidenceError, match="differs from its input"):
        store.record_output(
            run,
            changed,
            _valid_output(),
            reported_model_id="local-test-model",
        )

    assert not (run.directory / "raw-model-output.json").exists()
    assert not (run.directory / "rejected-output.json").exists()


def test_source_bundle_is_verified_before_prepare_and_during_replay(tmp_path: Path) -> None:
    store = SemanticEvidenceStore(tmp_path, _protocol(tmp_path))
    source_bundle_path = _write_source_bundle(tmp_path)
    source_bundle_path.write_text('{"objects":[]}', encoding="utf-8")

    with pytest.raises(SemanticEvidenceError, match="hash differs"):
        store.prepare(
            "SE-0004-source-mismatch",
            _request(),
            source_bundle_path=source_bundle_path,
        )

    source_bundle_path = _write_source_bundle(tmp_path)
    run = store.prepare(
        "SE-0004-source-replay",
        _request(),
        source_bundle_path=source_bundle_path,
    )
    store.record_output(
        run,
        _request(),
        _valid_output(),
        reported_model_id="local-test-model",
    )
    store.seal(run)
    source_bundle_path.write_text('{"objects":[]}', encoding="utf-8")

    with pytest.raises(SemanticEvidenceError, match="hash differs"):
        store.verify(run.directory, source_bundle_path=source_bundle_path)


def test_rejected_output_consumes_the_one_output_slot(tmp_path: Path) -> None:
    store = SemanticEvidenceStore(tmp_path, _protocol(tmp_path))
    run = _prepare(store, tmp_path, "SE-0004-one-output", _request())

    with pytest.raises(SemanticOutputRejected):
        store.record_output(run, _request(), "not-json")
    with pytest.raises(SemanticEvidenceError, match="already recorded an output"):
        store.record_output(
            run,
            _request(),
            _valid_output(),
            reported_model_id="local-test-model",
        )


def test_seal_rejects_an_unlisted_artifact_before_creating_a_manifest(tmp_path: Path) -> None:
    store = SemanticEvidenceStore(tmp_path, _protocol(tmp_path))
    run = _prepare(store, tmp_path, "SE-0004-unlisted", _request())
    store.record_output(
        run,
        _request(),
        _valid_output(),
        reported_model_id="local-test-model",
    )
    (run.directory / "unlisted.txt").write_text("not evidence", encoding="utf-8")

    with pytest.raises(SemanticEvidenceError, match="unexpected artifacts"):
        store.seal(run)


def test_store_checks_attestation_file_instead_of_trusting_verified_flag(tmp_path: Path) -> None:
    attestation = ModelAttestation(
        status=ModelAttestationStatus.VERIFIED,
        reported_model_digest="b" * 64,
        evidence=AttestationEvidence(
            method="runtime_inventory_sha256",
            record_path="release/experiments/semantic_enrichment/missing-model.json",
            record_sha256="c" * 64,
            attested_model_digest="b" * 64,
        ),
    )
    protocol = _protocol(
        tmp_path,
        lifecycle=ProtocolLifecycle.FROZEN,
        attestation=attestation,
    )
    store = SemanticEvidenceStore(tmp_path, protocol)
    run = _prepare(store, tmp_path, "SE-0005", _request())

    result = store.record_output(
        run,
        _request(),
        _valid_output(),
        reported_model_id="local-test-model",
    )

    assert "model attestation evidence file is missing or unsafe" in result.qualification_blockers
    assert "semantic proposal is not campaign execution evidence" in result.qualification_blockers


def test_existing_run_id_cannot_overwrite_prior_inputs(tmp_path: Path) -> None:
    store = SemanticEvidenceStore(tmp_path, _protocol(tmp_path))
    _prepare(store, tmp_path, "SE-0003", _request())

    with pytest.raises(SemanticEvidenceError, match="already exists"):
        _prepare(store, tmp_path, "SE-0003", _request())


def test_sealing_rejects_a_partial_provenance_directory(tmp_path: Path) -> None:
    store = SemanticEvidenceStore(tmp_path, _protocol(tmp_path))
    run = _prepare(store, tmp_path, "SE-0006", _request())
    store.record_output(
        run,
        _request(),
        _valid_output(),
        reported_model_id="local-test-model",
    )
    (run.directory / "input.json").unlink()

    with pytest.raises(SemanticEvidenceError, match="missing required provenance artifacts"):
        store.seal(run)
