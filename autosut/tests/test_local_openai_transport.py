"""Tests for the mockable, draft-only local Step-2 transport."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest
from urllib.request import ProxyHandler

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

import cti.local_openai_transport as local_openai_transport  # noqa: E402
from cti.local_openai_transport import (  # noqa: E402
    DraftSemanticEnrichmentRunner,
    DraftSemanticRunnerError,
    LocalChatCompletion,
    LocalOpenAICompatibleTransport,
    LocalOpenAITransportError,
)
from cti.semantic_concretizer import (  # noqa: E402
    ConcretizationInput,
    GenerationPolicy,
    LocalOpenAICompatibleProvider,
    ModelAttestation,
    OpenAICompatibleMessage,
    OpenAICompatibleRequest,
    PlatformFamily,
    ProtocolLifecycle,
    PublicCtiSourceKind,
    ProviderKind,
    ProvenanceLayout,
    SemanticEnrichmentProtocol,
    SemanticFieldKind,
    build_openai_compatible_request,
    derive_evidence_anchor_from_stix_object,
)
from cti.semantic_provenance import (  # noqa: E402
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


def _source_bundle_path(tmp_path: Path) -> Path:
    path = tmp_path / "data" / "stix" / "enterprise-attack.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_SOURCE_BUNDLE_BYTES)
    return path


def _protocol(
    *, lifecycle: ProtocolLifecycle = ProtocolLifecycle.DRAFT
) -> SemanticEnrichmentProtocol:
    return SemanticEnrichmentProtocol(
        protocol_id="autosut-step2-semantic-enrichment-v1",
        lifecycle=lifecycle,
        provider=LocalOpenAICompatibleProvider(
            kind=ProviderKind.LOCAL_OPENAI_COMPATIBLE,
            base_url="http://127.0.0.1:1234/v1",
            model_id="local-test-model",
            request_timeout_seconds=41,
            generation=GenerationPolicy(seed=0, max_output_tokens=512),
            model_attestation=ModelAttestation(),
        ),
        provenance=ProvenanceLayout(root="evidence-runs"),
    )


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


class _FakeTransport:
    def __init__(self, completion: LocalChatCompletion | Exception) -> None:
        self.completion = completion
        self.requests = []

    def complete(self, request: OpenAICompatibleRequest) -> LocalChatCompletion:
        self.requests.append(request)
        if isinstance(self.completion, Exception):
            raise self.completion
        return self.completion


def test_loopback_transport_submits_no_authorization_and_uses_fixed_controls() -> None:
    captured: dict[str, object] = {}

    def opener(request, timeout_seconds: float) -> bytes:
        captured["url"] = request.full_url
        captured["headers"] = {key.lower(): value for key, value in request.header_items()}
        captured["body"] = json.loads(request.data.decode("utf-8"))
        captured["timeout"] = timeout_seconds
        return json.dumps(
            {
                "model": "local-test-model",
                "choices": [{"message": {"content": _valid_output()}}],
            }
        ).encode("utf-8")

    completion = LocalOpenAICompatibleTransport(
        timeout_seconds=41,
        opener=opener,
    ).complete(build_openai_compatible_request(_protocol(), _request()))

    assert completion == LocalChatCompletion(_valid_output(), "local-test-model")
    assert captured["url"] == "http://127.0.0.1:1234/v1/chat/completions"
    assert "authorization" not in captured["headers"]
    assert captured["timeout"] == 41.0
    assert captured["body"] == {
        "max_tokens": 512,
        "messages": [
            {
                "content": (
                    "You produce only the closed AutoSUT Step-2 semantic-enrichment JSON "
                    "schema. You cannot emit executable content."
                ),
                "role": "system",
            },
            {
                "content": build_openai_compatible_request(_protocol(), _request())
                .messages[1]
                .content,
                "role": "user",
            },
        ],
        "model": "local-test-model",
        "response_format": {"type": "json_object"},
        "seed": 0,
        "temperature": 0.0,
    }


def test_default_transport_opener_disables_environment_proxy_routes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HTTP_PROXY", "http://proxy.invalid:8080")
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalid:8080")

    opener = local_openai_transport._build_direct_loopback_opener()
    proxy_handlers = [handler for handler in opener.handlers if isinstance(handler, ProxyHandler)]

    assert proxy_handlers == []


def test_transport_refuses_a_forged_non_loopback_request() -> None:
    request = OpenAICompatibleRequest(
        provider_kind=ProviderKind.LOCAL_OPENAI_COMPATIBLE,
        endpoint="http://localhost:1234/v1/chat/completions",
        model="local-test-model",
        messages=[
            OpenAICompatibleMessage(role="system", content="schema"),
            OpenAICompatibleMessage(role="user", content="input"),
        ],
        temperature=0.0,
        seed=0,
        max_tokens=64,
    )

    with pytest.raises(LocalOpenAITransportError, match="noncanonical loopback"):
        LocalOpenAICompatibleTransport(timeout_seconds=60).complete(request)


def test_draft_runner_seals_a_non_promotable_proposal_with_mocked_transport(
    tmp_path: Path,
) -> None:
    protocol = _protocol()
    fake_transport = _FakeTransport(LocalChatCompletion(_valid_output(), "local-test-model"))
    runner = DraftSemanticEnrichmentRunner(tmp_path, protocol, transport=fake_transport)
    source_bundle_path = _source_bundle_path(tmp_path)

    draft_run = runner.run(
        "SE-transport-ok",
        _request(),
        source_bundle_path=source_bundle_path,
    )

    assert not draft_run.is_claim_eligible
    assert draft_run.result.decision.value == "accepted"
    assert (
        "semantic proposal is not campaign execution evidence"
        in draft_run.result.qualification_blockers
    )
    assert len(fake_transport.requests) == 1
    assert (
        SemanticEvidenceStore(tmp_path, protocol).verify(
            draft_run.prepared_run.directory,
            source_bundle_path=source_bundle_path,
        )
        == draft_run.manifest
    )


def test_draft_runner_quarantines_invalid_output_without_promoting_it(tmp_path: Path) -> None:
    protocol = _protocol()
    fake_transport = _FakeTransport(
        LocalChatCompletion(
            '{"campaign_id":"C0045","technique_id":"T1190","fields":[],"command":"unsafe"}',
            "local-test-model",
        )
    )
    runner = DraftSemanticEnrichmentRunner(tmp_path, protocol, transport=fake_transport)
    source_bundle_path = _source_bundle_path(tmp_path)

    with pytest.raises(SemanticOutputRejected):
        runner.run(
            "SE-transport-rejected",
            _request(),
            source_bundle_path=source_bundle_path,
        )

    run_directory = tmp_path / "evidence-runs" / "SE-transport-rejected"
    assert (run_directory / "rejected-output.json").is_file()
    assert not (run_directory / "raw-model-output.json").exists()
    SemanticEvidenceStore(tmp_path, protocol).verify(
        run_directory,
        source_bundle_path=source_bundle_path,
    )


def test_draft_runner_records_a_message_free_transport_failure_and_reraises(tmp_path: Path) -> None:
    protocol = _protocol()
    failure = ConnectionRefusedError("hypothetical-secret-message")
    runner = DraftSemanticEnrichmentRunner(
        tmp_path,
        protocol,
        transport=_FakeTransport(failure),
    )
    source_bundle_path = _source_bundle_path(tmp_path)

    with pytest.raises(ConnectionRefusedError, match="hypothetical-secret-message"):
        runner.run(
            "SE-transport-failed",
            _request(),
            source_bundle_path=source_bundle_path,
        )

    run_directory = tmp_path / "evidence-runs" / "SE-transport-failed"
    failure_record = (run_directory / "transport-failure.json").read_text(encoding="utf-8")
    assert "hypothetical-secret-message" not in failure_record
    assert "ConnectionRefusedError" in failure_record
    SemanticEvidenceStore(tmp_path, protocol).verify(
        run_directory,
        source_bundle_path=source_bundle_path,
    )


def test_runner_refuses_a_non_draft_protocol_before_it_can_call_transport(tmp_path: Path) -> None:
    fake_transport = _FakeTransport(LocalChatCompletion(_valid_output(), "local-test-model"))

    with pytest.raises(DraftSemanticRunnerError, match="only permits draft protocols"):
        DraftSemanticEnrichmentRunner(
            tmp_path,
            _protocol(lifecycle=ProtocolLifecycle.FROZEN),
            transport=fake_transport,
        )

    assert fake_transport.requests == []
