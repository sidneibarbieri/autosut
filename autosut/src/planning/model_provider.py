"""Build a completion callable from a JSON config that names an environment variable.

The tool never embeds an API key. A config file declares the provider, the model, and the
*name* of the environment variable that holds the key (``api_key_env``); the key itself is read
from the environment at call time. ``config.openai.example.json`` is the public template a
reviewer copies and points at their own ``OPENAI_API_KEY``.

Both ``openai`` and ``openai_compatible`` (a local server such as Ollama or LM Studio) speak the
same chat-completions schema, so one transport serves both. Transport errors are not caught here:
an HTTP failure or a malformed reply is a real error the caller must see, not a silent fallback.
"""

from __future__ import annotations

import json
import os
import urllib.request
from pathlib import Path
from typing import Callable, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator

# A completion callable maps (system_prompt, user_prompt) to the model's raw text reply. This is
# the same surface ``procedure_generator`` and the execution engine consume.
CompletionFn = Callable[[str, str], str]

# The transport posts a request body to a chat-completions endpoint and returns the parsed reply.
# It is injectable so tests exercise the config and message plumbing without a live network call.
PostFn = Callable[[str, str, dict, int], dict]


class MissingApiKey(RuntimeError):
    """The environment variable the config names holds no key."""


class BudgetExceeded(RuntimeError):
    """The run reached the request ceiling the config declared."""


class UnexpectedModelReply(RuntimeError):
    """The provider response carried no assistant message."""


class ReplayMismatch(RuntimeError):
    """A replayed run asked for a prompt the recorded transcript does not hold in order."""


CHAT_REQUEST_TOKEN_OVERHEAD = 64


def _validate_cost_ceiling(
    max_estimated_usd: float | None,
    input_rate: float | None,
    output_rate: float | None,
) -> None:
    rates = (input_rate, output_rate)
    if max_estimated_usd is not None and None in rates:
        raise ValueError("max_estimated_usd requires input and output token rates")
    if max_estimated_usd is None and any(rate is not None for rate in rates):
        raise ValueError("token rates require max_estimated_usd")


class ProviderBudget(BaseModel):
    """Hard caps applied before a provider request is sent."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    max_requests: int = Field(default=40, ge=1)
    max_prompt_tokens: int | None = Field(default=None, ge=1)
    max_completion_tokens: int | None = Field(default=None, ge=1)
    max_estimated_usd: float | None = Field(default=None, ge=0)
    input_usd_per_million_tokens: float | None = Field(default=None, ge=0)
    output_usd_per_million_tokens: float | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def requires_rates_for_cost_cap(self) -> "ProviderBudget":
        _validate_cost_ceiling(
            self.max_estimated_usd,
            self.input_usd_per_million_tokens,
            self.output_usd_per_million_tokens,
        )
        return self


class ProviderConfig(BaseModel):
    """The ``llm`` block of a tool config: how to reach the model, and where its key lives."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    provider: Literal["openai", "openai_compatible", "replay"]
    model: str = "replayed"
    base_url: str = ""
    api_key_env: str = ""
    temperature: float = 0.0
    max_output_tokens: int = Field(default=1200, ge=1)
    timeout_seconds: int = Field(default=60, ge=1)
    max_requests: int = Field(default=40, ge=1)
    max_prompt_tokens: int | None = Field(default=None, ge=1)
    max_completion_tokens: int | None = Field(default=None, ge=1)
    max_estimated_usd: float | None = Field(default=None, ge=0)
    input_usd_per_million_tokens: float | None = Field(default=None, ge=0)
    output_usd_per_million_tokens: float | None = Field(default=None, ge=0)
    # Only for the replay provider: the recorded transcript to reproduce a run without a key.
    transcript_path: Optional[str] = None

    @model_validator(mode="after")
    def validates_cost_configuration(self) -> "ProviderConfig":
        _validate_cost_ceiling(
            self.max_estimated_usd,
            self.input_usd_per_million_tokens,
            self.output_usd_per_million_tokens,
        )
        return self

    @classmethod
    def from_file(cls, path: Path) -> "ProviderConfig":
        document = json.loads(Path(path).read_text(encoding="utf-8"))
        block = document.get("llm", document)
        if not isinstance(block, dict):
            raise ValueError("provider config must contain an object at 'llm'")
        allowed = {
            "provider",
            "model",
            "base_url",
            "api_key_env",
            "temperature",
            "max_output_tokens",
            "timeout_seconds",
            "budget",
            "transcript_path",
        }
        unexpected = sorted(set(block) - allowed)
        if unexpected:
            raise ValueError(f"provider config has unsupported fields: {', '.join(unexpected)}")
        budget = ProviderBudget.model_validate(block.get("budget") or {})
        return cls(
            provider=block["provider"],
            model=block.get("model", "replayed"),
            base_url=block.get("base_url", ""),
            api_key_env=block.get("api_key_env", ""),
            temperature=block.get("temperature", 0.0),
            max_output_tokens=block.get("max_output_tokens", 1200),
            timeout_seconds=block.get("timeout_seconds", 60),
            max_requests=budget.max_requests,
            max_prompt_tokens=budget.max_prompt_tokens,
            max_completion_tokens=budget.max_completion_tokens,
            max_estimated_usd=budget.max_estimated_usd,
            input_usd_per_million_tokens=budget.input_usd_per_million_tokens,
            output_usd_per_million_tokens=budget.output_usd_per_million_tokens,
            transcript_path=block.get("transcript_path"),
        )


class BudgetReservation(BaseModel):
    """Conservative token and cost reservations for one completion callable."""

    model_config = ConfigDict(extra="forbid")

    requests: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    estimated_usd: float = 0.0


def _prompt_token_upper_bound(system_prompt: str, user_prompt: str) -> int:
    """Return a conservative token upper bound without a provider-specific tokenizer."""

    return (
        CHAT_REQUEST_TOKEN_OVERHEAD
        + len(system_prompt.encode("utf-8"))
        + len(user_prompt.encode("utf-8"))
    )


def _estimated_request_cost(config: ProviderConfig, prompt_tokens: int) -> float:
    if config.max_estimated_usd is None:
        return 0.0
    assert config.input_usd_per_million_tokens is not None
    assert config.output_usd_per_million_tokens is not None
    return (
        prompt_tokens * config.input_usd_per_million_tokens
        + config.max_output_tokens * config.output_usd_per_million_tokens
    ) / 1_000_000


def _reserve_budget(
    reservation: BudgetReservation,
    config: ProviderConfig,
    system_prompt: str,
    user_prompt: str,
) -> None:
    """Reserve worst-case request capacity before the provider can bill it."""

    prompt_tokens = _prompt_token_upper_bound(system_prompt, user_prompt)
    completion_tokens = config.max_output_tokens
    if reservation.requests + 1 > config.max_requests:
        raise BudgetExceeded(f"reached the {config.max_requests}-request ceiling for this run")
    if (
        config.max_prompt_tokens is not None
        and reservation.prompt_tokens + prompt_tokens > config.max_prompt_tokens
    ):
        raise BudgetExceeded("request would exceed the configured prompt-token ceiling")
    if (
        config.max_completion_tokens is not None
        and reservation.completion_tokens + completion_tokens > config.max_completion_tokens
    ):
        raise BudgetExceeded("request would exceed the configured completion-token ceiling")
    estimated_cost = _estimated_request_cost(config, prompt_tokens)
    if (
        config.max_estimated_usd is not None
        and reservation.estimated_usd + estimated_cost > config.max_estimated_usd
    ):
        raise BudgetExceeded("request would exceed the configured estimated-cost ceiling")
    reservation.requests += 1
    reservation.prompt_tokens += prompt_tokens
    reservation.completion_tokens += completion_tokens
    reservation.estimated_usd += estimated_cost


def _post_openai_chat(base_url: str, api_key: str, body: dict, timeout_seconds: int) -> dict:
    """POST one chat-completions request and return the parsed JSON. Errors bubble."""
    request = urllib.request.Request(
        f"{base_url.rstrip('/')}/chat/completions",
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"},
    )
    with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
        return json.loads(response.read())


def _message_text(reply: dict) -> str:
    choices = reply.get("choices")
    if not choices:
        raise UnexpectedModelReply("provider reply carried no choices")
    return choices[0]["message"]["content"]


class TranscriptEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    system: str
    user: str
    response: str


def recording_completion(inner: CompletionFn, transcript_path: Path) -> CompletionFn:
    """Wrap a completion callable so every prompt and reply is appended to a transcript on disk."""
    entries: list[TranscriptEntry] = []

    def complete(system_prompt: str, user_prompt: str) -> str:
        response = inner(system_prompt, user_prompt)
        entries.append(TranscriptEntry(system=system_prompt, user=user_prompt, response=response))
        Path(transcript_path).write_text(
            json.dumps([entry.model_dump() for entry in entries], indent=2), encoding="utf-8"
        )
        return response

    return complete


def replay_completion(transcript_path: Path) -> CompletionFn:
    """Replay a recorded transcript in call order, reproducing a run without a live model or key."""
    recorded = [TranscriptEntry.model_validate(item) for item in json.loads(Path(transcript_path).read_text())]
    pending = iter(recorded)

    def complete(system_prompt: str, user_prompt: str) -> str:
        entry = next(pending, None)
        if entry is None:
            raise ReplayMismatch("the run made more model calls than the transcript recorded")
        if entry.system != system_prompt or entry.user != user_prompt:
            raise ReplayMismatch("a prompt diverged from the recorded transcript")
        return entry.response

    return complete


def build_completion(config: ProviderConfig, *, post: PostFn = _post_openai_chat) -> CompletionFn:
    """Return a completion callable bound to ``config`` and the key in its named environment var."""
    if config.provider == "replay":
        if not config.transcript_path:
            raise ValueError("replay provider needs a transcript_path")
        return replay_completion(Path(config.transcript_path))

    api_key = os.environ.get(config.api_key_env)
    if not api_key:
        raise MissingApiKey(f"environment variable {config.api_key_env} is not set")

    reservation = BudgetReservation()

    def complete(system_prompt: str, user_prompt: str) -> str:
        _reserve_budget(reservation, config, system_prompt, user_prompt)
        body = {
            "model": config.model,
            "temperature": config.temperature,
            "max_tokens": config.max_output_tokens,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }
        return _message_text(post(config.base_url, api_key, body, config.timeout_seconds))

    return complete
