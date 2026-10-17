"""Draft-only local OpenAI-compatible transport for the Step-2 protocol.

The transport deliberately has one narrow role: submit the already typed
``OpenAICompatibleRequest`` to an LM Studio-style loopback endpoint and hand
the response to the closed-schema provenance store. It has no API-key field,
no cloud-provider fallback, no retry policy, and no execution integration.
Failures are recorded only by their exception class and then re-raised.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Protocol
from urllib.request import ProxyHandler, Request, build_opener

from .semantic_concretizer import (
    ConcretizationInput,
    ConcretizationResult,
    OpenAICompatibleRequest,
    ProtocolLifecycle,
    SemanticEnrichmentProtocol,
    build_openai_compatible_request,
)
from .semantic_provenance import (
    PreparedSemanticRun,
    SealedSemanticRun,
    SemanticEvidenceStore,
    SemanticOutputRejected,
)


class LocalOpenAITransportError(RuntimeError):
    """The loopback server returned a response outside the local contract."""


class DraftSemanticRunnerError(RuntimeError):
    """The caller attempted to use the draft runner outside its declared lifecycle."""


@dataclass(frozen=True)
class LocalChatCompletion:
    """The two response fields needed by closed-schema provenance."""

    content: str
    model_id: str


@dataclass(frozen=True)
class DraftSemanticRun:
    """A sealed draft proposal attempt that cannot promote a campaign claim."""

    prepared_run: PreparedSemanticRun
    manifest: SealedSemanticRun
    result: ConcretizationResult

    @property
    def is_claim_eligible(self) -> bool:
        """Draft semantic enrichment alone never becomes campaign evidence."""
        return False


class CompletionTransport(Protocol):
    """Small dependency-injection surface for tests and future local transports."""

    def complete(self, request: OpenAICompatibleRequest) -> LocalChatCompletion:
        """Return the provider content and the model identity reported by that response."""


RequestOpener = Callable[[Request, float], bytes]

_CANONICAL_COMPLETION_ENDPOINT = "http://127.0.0.1:1234/v1/chat/completions"


def _build_direct_loopback_opener():
    """Create an opener that cannot consult proxy environment variables."""
    return build_opener(ProxyHandler({}))


_DIRECT_LOOPBACK_OPENER = _build_direct_loopback_opener()


def _default_open(request: Request, timeout_seconds: float) -> bytes:
    """Send one direct loopback request and propagate network errors unchanged."""
    with _DIRECT_LOOPBACK_OPENER.open(request, timeout=timeout_seconds) as response:
        return response.read()


class LocalOpenAICompatibleTransport:
    """Minimal, injectable HTTP transport for a literal-loopback chat endpoint."""

    def __init__(
        self,
        *,
        timeout_seconds: float,
        opener: RequestOpener = _default_open,
    ) -> None:
        if not 1 <= timeout_seconds <= 600:
            raise ValueError("timeout_seconds must be between 1 and 600")
        self._timeout_seconds = timeout_seconds
        self._opener = opener

    def complete(self, request: OpenAICompatibleRequest) -> LocalChatCompletion:
        """Submit exactly one local request, with no authorization header or retries."""
        _require_canonical_loopback_endpoint(request.endpoint)
        request_body = json.dumps(
            {
                "model": request.model,
                "messages": [message.model_dump(mode="json") for message in request.messages],
                "temperature": request.temperature,
                "seed": request.seed,
                "max_tokens": request.max_tokens,
                "response_format": {"type": request.response_format},
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        http_request = Request(
            request.endpoint,
            data=request_body,
            headers={"Accept": "application/json", "Content-Type": "application/json"},
            method="POST",
        )
        response_bytes = self._opener(http_request, float(self._timeout_seconds))
        return _parse_completion_response(response_bytes)


class DraftSemanticEnrichmentRunner:
    """Execute one draft-only local proposal and seal its provenance directory."""

    def __init__(
        self,
        project_root: Path,
        protocol: SemanticEnrichmentProtocol,
        *,
        transport: CompletionTransport | None = None,
    ) -> None:
        if protocol.lifecycle is not ProtocolLifecycle.DRAFT:
            raise DraftSemanticRunnerError(
                "the local transport runner only permits draft protocols"
            )
        self._protocol = protocol
        self._store = SemanticEvidenceStore(project_root, protocol)
        self._transport = transport or LocalOpenAICompatibleTransport(
            timeout_seconds=protocol.provider.request_timeout_seconds
        )

    def run(
        self,
        run_id: str,
        request: ConcretizationInput,
        *,
        source_bundle_path: Path,
    ) -> DraftSemanticRun:
        """Run and seal one non-promotable semantic proposal attempt.

        The only broad exception boundary is the transport call itself. It
        records a message-free failure class for auditability and then re-raises
        the original failure rather than converting it into a success value.
        """
        if self._protocol.lifecycle is not ProtocolLifecycle.DRAFT:
            raise DraftSemanticRunnerError(
                "the local transport runner only permits draft protocols"
            )
        prepared_run = self._store.prepare(
            run_id,
            request,
            source_bundle_path=source_bundle_path,
        )
        provider_request = build_openai_compatible_request(self._protocol, request)
        try:
            completion = self._transport.complete(provider_request)
        except Exception as error:
            self._store.record_transport_failure(prepared_run, error)
            self._store.seal(prepared_run)
            raise
        try:
            result = self._store.record_output(
                prepared_run,
                request,
                completion.content,
                reported_model_id=completion.model_id,
            )
        except SemanticOutputRejected:
            self._store.seal(prepared_run)
            raise
        manifest = self._store.seal(prepared_run)
        return DraftSemanticRun(
            prepared_run=prepared_run,
            manifest=manifest,
            result=result,
        )


def _require_canonical_loopback_endpoint(endpoint: str) -> None:
    """Defend the network boundary even if a caller forged a request DTO."""
    if endpoint != _CANONICAL_COMPLETION_ENDPOINT:
        raise LocalOpenAITransportError("Step-2 transport refuses a noncanonical loopback endpoint")


def _parse_completion_response(response_bytes: bytes) -> LocalChatCompletion:
    """Read only the OpenAI-compatible model identifier and first text completion."""
    try:
        response = json.loads(response_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise LocalOpenAITransportError("local provider returned invalid JSON") from error
    if not isinstance(response, dict):
        raise LocalOpenAITransportError("local provider returned a non-object response")
    model_id = response.get("model")
    choices = response.get("choices")
    if not isinstance(model_id, str) or not isinstance(choices, list) or not choices:
        raise LocalOpenAITransportError("local provider response is missing model or choices")
    first_choice = choices[0]
    if not isinstance(first_choice, dict):
        raise LocalOpenAITransportError("local provider response has an invalid choice")
    message = first_choice.get("message")
    if not isinstance(message, dict) or not isinstance(message.get("content"), str):
        raise LocalOpenAITransportError("local provider response is missing message content")
    return LocalChatCompletion(content=message["content"], model_id=model_id)


__all__ = [
    "CompletionTransport",
    "DraftSemanticEnrichmentRunner",
    "DraftSemanticRun",
    "DraftSemanticRunnerError",
    "LocalChatCompletion",
    "LocalOpenAICompatibleTransport",
    "LocalOpenAITransportError",
]
