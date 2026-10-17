"""Tests for the planning-only Step-2 to CampaignRequirements bridge."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.cti.semantic_concretizer import (  # noqa: E402
    ConcretizationInput,
    Decision,
    GenerationPolicy,
    LocalOpenAICompatibleProvider,
    ModelAttestation,
    PlatformFamily as SemanticPlatformFamily,
    ProtocolLifecycle,
    PublicCtiSourceKind,
    ProviderKind,
    ProvenanceLayout,
    SemanticConcretizer,
    SemanticEnrichmentProtocol,
    SemanticFieldKind,
    derive_evidence_anchor_from_stix_object,
    parse_model_output,
)
from src.cti.semantic_provenance import SemanticEvidenceError, SemanticEvidenceStore  # noqa: E402
from src.planning.procedural_plan import (  # noqa: E402
    ProceduralPlanInput,
    ProceduralPlanSourceInput,
    ProcedureStepInput,
)
from src.planning.requirements_admission import (  # noqa: E402
    RequirementsAdmissionError,
    compile_admitted_campaign_requirements,
    compile_from_verified_semantic_evidence,
)


_SOURCE_OBJECT = {
    "id": "attack-pattern--example",
    "type": "attack-pattern",
    "description": "Public CTI text is source evidence only; it never becomes a command.",
}
_SOURCE_BUNDLE_BYTES = json.dumps(
    {"type": "bundle", "objects": [_SOURCE_OBJECT]},
    sort_keys=True,
    separators=(",", ":"),
).encode("utf-8")
_SOURCE_BUNDLE_SHA256 = hashlib.sha256(_SOURCE_BUNDLE_BYTES).hexdigest()


def _protocol() -> SemanticEnrichmentProtocol:
    return SemanticEnrichmentProtocol(
        protocol_id="autosut-step2-semantic-enrichment-v1",
        lifecycle=ProtocolLifecycle.DRAFT,
        provider=LocalOpenAICompatibleProvider(
            kind=ProviderKind.LOCAL_OPENAI_COMPATIBLE,
            base_url="http://127.0.0.1:1234/v1",
            model_id="local-test-model",
            generation=GenerationPolicy(seed=0, max_output_tokens=512),
            model_attestation=ModelAttestation(),
        ),
        provenance=ProvenanceLayout(root="release/experiments/semantic_enrichment/runs"),
    )


def _request(
    *,
    allowed_platforms: list[SemanticPlatformFamily] | None = None,
    unresolved_fields: list[SemanticFieldKind] | None = None,
) -> ConcretizationInput:
    return ConcretizationInput(
        campaign_id="C0045",
        technique_id="T1190",
        source_bundle_sha256=_SOURCE_BUNDLE_SHA256,
        source_bundle_object_count=1,
        allowed_platforms=allowed_platforms or [SemanticPlatformFamily.LINUX],
        evidence=[
            derive_evidence_anchor_from_stix_object(
                anchor_id="step-evidence",
                source_object=_SOURCE_OBJECT,
                source_field="description",
                source_kind=PublicCtiSourceKind.STIX_PROCEDURE,
            )
        ],
        unresolved_fields=unresolved_fields
        or [SemanticFieldKind.SOFTWARE_ROLE, SemanticFieldKind.NETWORK_EXPOSURE],
    )


def _raw_output(*, fields: list[dict[str, object]] | None = None) -> str:
    return json.dumps(
        {
            "campaign_id": "C0045",
            "technique_id": "T1190",
            "fields": fields
            or [
                {
                    "kind": "software_role",
                    "value": "web_service",
                    "evidence_ids": ["step-evidence"],
                },
                {
                    "kind": "network_exposure",
                    "value": "controlled_ingress",
                    "evidence_ids": ["step-evidence"],
                },
            ],
        },
        sort_keys=True,
    )


def _with_content_hash(payload: dict[str, object]) -> dict[str, object]:
    payload["content_sha256"] = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return payload


def _plan(*, additional_step: bool = False) -> ProceduralPlanInput:
    steps = [
        ProcedureStepInput(
            technique_id="T1190",
            technique_stix_id="attack-pattern--example",
            name="ignored-input-name",
            execution_domain="boundary",
            platforms=["Linux", "Windows"],
            relationship_ids=["relationship--step-example"],
            procedure_descriptions=[
                "untrusted free-text command --secret password=supersecret never crosses the bridge"
            ],
        )
    ]
    if additional_step:
        steps.append(
            ProcedureStepInput(
                technique_id="T1105",
                technique_stix_id="attack-pattern--other",
                name="other-input-name",
                execution_domain="target",
                platforms=["Linux"],
                relationship_ids=["relationship--other"],
                procedure_descriptions=["other raw procedure prose"],
            )
        )
    payload: dict[str, object] = {
        "schema_version": "1",
        "compiler_version": "1",
        "campaign_id": "C0045",
        "campaign_name": "untrusted campaign name",
        "source": {
            "bundle_sha256": _SOURCE_BUNDLE_SHA256,
            "object_count": 1,
            "campaign_stix_id": "campaign--example",
            "campaign_external_id": "C0045",
        },
        "ordering_policy": "fixed-test-order",
        "steps": [step.model_dump(mode="json") for step in steps],
        "limitations": [],
    }
    return ProceduralPlanInput.model_validate(_with_content_hash(payload))


def _accepted_admission(request: ConcretizationInput):
    proposal = parse_model_output(
        _raw_output(), request, _protocol(), reported_model_id="local-test-model"
    )
    result = SemanticConcretizer().concretize(request, proposal)
    assert result.decision is Decision.ACCEPTED
    return result


def test_accepted_closed_proposal_compiles_to_hash_bound_planning_only_requirements() -> None:
    request = _request()
    result = _accepted_admission(request)

    compiled = compile_admitted_campaign_requirements(_plan(), request, result)

    requirements = compiled.requirements
    assert requirements.source_bundle_sha256 == _SOURCE_BUNDLE_SHA256
    assert [platform.value for platform in requirements.target_platforms] == ["linux"]
    assert requirements.hosts[0].host_id == "sut-1"
    assert requirements.hosts[0].role == "web-service"
    assert requirements.network_exposures[0].service_name == "web-service"
    assert requirements.network_exposures[0].port == 8443
    assert requirements.procedure_requirements[0].execution_domain == "network"
    assert requirements.content_sha256() == compiled.receipt.requirements_sha256
    assert compiled.receipt.is_execution_evidence is False
    assert "admitted requirements are not campaign execution evidence" in (
        compiled.receipt.qualification_blockers
    )
    assert "untrusted free-text command" not in json.dumps(requirements.canonical_payload())
    assert "untrusted campaign name" not in json.dumps(requirements.canonical_payload())
    assert "supersecret" not in json.dumps(requirements.canonical_payload())
    unresolved = {item.item_id: item for item in requirements.unresolved_items}
    assert unresolved["semantic-evidence-verification"].blocks_materialization is True
    assert unresolved["semantic-qualification"].blocks_materialization is True


def test_partial_admission_blocks_materialization_for_other_environment_steps() -> None:
    request = _request()
    compiled = compile_admitted_campaign_requirements(
        _plan(additional_step=True), request, _accepted_admission(request)
    )

    unresolved = {item.item_id: item for item in compiled.requirements.unresolved_items}
    assert unresolved["unresolved-t1105"].blocks_materialization is True
    assert unresolved["software-catalog-binding"].blocks_materialization is True
    assert unresolved["semantic-not-execution-evidence"].blocks_materialization is False


def test_replay_verified_semantic_evidence_binds_the_sealed_manifest(tmp_path: Path) -> None:
    request = _request()
    source_bundle_path = tmp_path / "data" / "stix" / "enterprise-attack.json"
    source_bundle_path.parent.mkdir(parents=True)
    source_bundle_path.write_bytes(_SOURCE_BUNDLE_BYTES)
    store = SemanticEvidenceStore(tmp_path, _protocol())
    run = store.prepare("SE-0001", request, source_bundle_path=source_bundle_path)
    store.record_output(
        run,
        request,
        _raw_output(),
        reported_model_id="local-test-model",
    )
    store.seal(run)

    compiled = compile_from_verified_semantic_evidence(
        _plan(),
        store,
        run.directory,
        source_bundle_path=source_bundle_path,
    )

    manifest_digest = hashlib.sha256((run.directory / "manifest.json").read_bytes()).hexdigest()
    assert compiled.receipt.semantic_evidence_verified is True
    assert compiled.receipt.semantic_evidence_manifest_sha256 == manifest_digest
    semantic_record = next(
        item for item in compiled.requirements.provenance if item.provenance_id == "semantic-admission"
    )
    assert semantic_record.source_sha256 == manifest_digest
    unresolved = {item.item_id: item for item in compiled.requirements.unresolved_items}
    assert "semantic-evidence-verification" not in unresolved
    assert unresolved["semantic-qualification"].blocks_materialization is True

    (run.directory / "raw-model-output.json").write_text("tampered", encoding="utf-8")
    with pytest.raises(SemanticEvidenceError, match="differs"):
        compile_from_verified_semantic_evidence(
            _plan(),
            store,
            run.directory,
            source_bundle_path=source_bundle_path,
        )


def test_nonaccepted_or_tampered_admission_fails_closed() -> None:
    request = _request()
    result = _accepted_admission(request)
    tampered = result.model_copy(update={"input_sha256": "0" * 64})

    with pytest.raises(RequirementsAdmissionError, match="input digest"):
        compile_admitted_campaign_requirements(_plan(), request, tampered)

    stripped_blockers = result.model_copy(update={"qualification_blockers": []})
    with pytest.raises(RequirementsAdmissionError, match="omits deterministic qualification blockers"):
        compile_admitted_campaign_requirements(_plan(), request, stripped_blockers)

    stale_input = request.model_copy(update={"input_sha256": "1" * 64})
    with pytest.raises(RequirementsAdmissionError, match="bounded input digest"):
        compile_admitted_campaign_requirements(_plan(), stale_input, result)

    not_accepted = SemanticConcretizer().concretize(request)
    with pytest.raises(RequirementsAdmissionError, match="only an accepted"):
        compile_admitted_campaign_requirements(_plan(), request, not_accepted)


def test_tampered_procedural_plan_or_source_binding_fails_closed() -> None:
    request = _request()
    result = _accepted_admission(request)
    plan = _plan()

    with pytest.raises(RequirementsAdmissionError, match="content_sha256"):
        compile_admitted_campaign_requirements(
            plan.model_copy(update={"content_sha256": "0" * 64}), request, result
        )

    bad_source = plan.model_copy(
        update={
            "source": ProceduralPlanSourceInput(
                bundle_sha256="f" * 64,
                object_count=1,
                campaign_stix_id="campaign--example",
                campaign_external_id="C0045",
            )
        }
    )
    with pytest.raises(RequirementsAdmissionError, match="content_sha256"):
        compile_admitted_campaign_requirements(bad_source, request, result)


def test_evidence_must_point_to_the_selected_procedural_plan_step() -> None:
    request = _request()
    result = _accepted_admission(request)
    plan = _plan().model_copy(
        update={
            "steps": [
                ProcedureStepInput(
                    technique_id="T1190",
                    technique_stix_id="attack-pattern--different",
                    name="ignored",
                    execution_domain="boundary",
                    platforms=["Linux"],
                    relationship_ids=["relationship--different"],
                )
            ]
        }
    )
    plan_payload = plan.model_dump(mode="json", exclude={"content_sha256"})
    bound_plan = plan.model_copy(
        update={
            "content_sha256": hashlib.sha256(
                json.dumps(plan_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
        }
    )

    with pytest.raises(RequirementsAdmissionError, match="not bound"):
        compile_admitted_campaign_requirements(bound_plan, request, result)


def test_admitted_platform_cannot_override_procedural_plan_constraints() -> None:
    request = _request(
        allowed_platforms=[SemanticPlatformFamily.LINUX, SemanticPlatformFamily.WINDOWS],
        unresolved_fields=[SemanticFieldKind.PLATFORM],
    )
    raw = _raw_output(
        fields=[
            {
                "kind": "platform",
                "value": "windows",
                "evidence_ids": ["step-evidence"],
            }
        ]
    )
    proposal = parse_model_output(raw, request, _protocol(), reported_model_id="local-test-model")
    result = SemanticConcretizer().concretize(request, proposal)
    assert result.decision is Decision.ACCEPTED
    plan = _plan().model_copy(
        update={
            "steps": [
                ProcedureStepInput(
                    technique_id="T1190",
                    technique_stix_id="attack-pattern--example",
                    name="ignored",
                    execution_domain="boundary",
                    platforms=["Linux"],
                    relationship_ids=["relationship--step-example"],
                )
            ]
        }
    )
    payload = plan.model_dump(mode="json", exclude={"content_sha256"})
    linux_only_plan = plan.model_copy(
        update={
            "content_sha256": hashlib.sha256(
                json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
        }
    )

    with pytest.raises(RequirementsAdmissionError, match="not supported"):
        compile_admitted_campaign_requirements(linux_only_plan, request, result)


def test_unrepresentable_privilege_or_unbound_service_fails_closed() -> None:
    privilege_request = _request(
        unresolved_fields=[
            SemanticFieldKind.PRIVILEGE,
            SemanticFieldKind.CREDENTIAL_REQUIREMENT,
        ]
    )
    privilege_proposal = parse_model_output(
        _raw_output(
            fields=[
                {
                    "kind": "privilege",
                    "value": "root",
                    "evidence_ids": ["step-evidence"],
                },
                {
                    "kind": "credential_requirement",
                    "value": "privileged_account",
                    "evidence_ids": ["step-evidence"],
                },
            ]
        ),
        privilege_request,
        _protocol(),
        reported_model_id="local-test-model",
    )
    privilege_result = SemanticConcretizer().concretize(privilege_request, privilege_proposal)
    assert privilege_result.decision is Decision.ACCEPTED
    with pytest.raises(RequirementsAdmissionError, match="not representable"):
        compile_admitted_campaign_requirements(_plan(), privilege_request, privilege_result)

    network_request = _request(unresolved_fields=[SemanticFieldKind.NETWORK_EXPOSURE])
    network_proposal = parse_model_output(
        _raw_output(
            fields=[
                {
                    "kind": "network_exposure",
                    "value": "controlled_ingress",
                    "evidence_ids": ["step-evidence"],
                }
            ]
        ),
        network_request,
        _protocol(),
        reported_model_id="local-test-model",
    )
    network_result = SemanticConcretizer().concretize(network_request, network_proposal)
    assert network_result.decision is Decision.ACCEPTED
    with pytest.raises(RequirementsAdmissionError, match="requires an admitted service role"):
        compile_admitted_campaign_requirements(_plan(), network_request, network_result)
