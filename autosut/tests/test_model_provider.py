from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from planning.model_provider import (  # noqa: E402
    BudgetExceeded,
    MissingApiKey,
    ProviderConfig,
    UnexpectedModelReply,
    build_completion,
)


def _config(**overrides) -> ProviderConfig:
    base = dict(provider="openai", model="gpt-4o-mini",
                base_url="https://api.openai.com/v1", api_key_env="TEST_KEY_ENV")
    base.update(overrides)
    return ProviderConfig(**base)


def test_reads_the_shipped_openai_example_config():
    config = ProviderConfig.from_file(PROJECT_ROOT / "config.openai.example.json")
    assert config.provider == "openai"
    assert config.api_key_env == "OPENAI_API_KEY"
    assert config.max_requests == 60  # from the example budget block
    assert config.max_prompt_tokens == 100000
    assert config.max_completion_tokens == 24000
    assert config.max_estimated_usd == 5.0


def test_missing_env_key_is_a_clear_error(monkeypatch):
    monkeypatch.delenv("TEST_KEY_ENV", raising=False)
    with pytest.raises(MissingApiKey):
        build_completion(_config())


def test_request_carries_messages_and_returns_assistant_text(monkeypatch):
    monkeypatch.setenv("TEST_KEY_ENV", "sk-test")
    seen = {}

    def fake_post(base_url, api_key, body, timeout):
        seen["base_url"] = base_url
        seen["api_key"] = api_key
        seen["body"] = body
        return {"choices": [{"message": {"content": "hello"}}]}

    complete = build_completion(_config(), post=fake_post)
    assert complete("SYS", "USR") == "hello"
    assert seen["api_key"] == "sk-test"
    assert seen["body"]["messages"][0] == {"role": "system", "content": "SYS"}
    assert seen["body"]["messages"][1] == {"role": "user", "content": "USR"}


def test_budget_ceiling_stops_further_requests(monkeypatch):
    monkeypatch.setenv("TEST_KEY_ENV", "sk-test")
    complete = build_completion(
        _config(max_requests=1),
        post=lambda *a: {"choices": [{"message": {"content": "ok"}}]},
    )
    assert complete("s", "u") == "ok"
    with pytest.raises(BudgetExceeded):
        complete("s", "u")


def test_prompt_budget_is_reserved_before_provider_call(monkeypatch):
    monkeypatch.setenv("TEST_KEY_ENV", "sk-test")
    calls = []
    complete = build_completion(
        _config(max_prompt_tokens=4),
        post=lambda *args: calls.append(args) or {"choices": [{"message": {"content": "ok"}}]},
    )

    with pytest.raises(BudgetExceeded, match="prompt-token"):
        complete("sys", "us")
    assert calls == []


def test_completion_budget_reserves_requested_output_before_provider_call(monkeypatch):
    monkeypatch.setenv("TEST_KEY_ENV", "sk-test")
    complete = build_completion(
        _config(max_requests=3, max_output_tokens=2, max_completion_tokens=3),
        post=lambda *args: {"choices": [{"message": {"content": "ok"}}]},
    )

    assert complete("s", "u") == "ok"
    with pytest.raises(BudgetExceeded, match="completion-token"):
        complete("s", "u")


def test_cost_budget_requires_a_safe_reservation(monkeypatch):
    monkeypatch.setenv("TEST_KEY_ENV", "sk-test")
    calls = []
    complete = build_completion(
        _config(
            max_output_tokens=2,
            max_estimated_usd=1.0,
            input_usd_per_million_tokens=0.0,
            output_usd_per_million_tokens=1_000_000.0,
        ),
        post=lambda *args: calls.append(args) or {"choices": [{"message": {"content": "ok"}}]},
    )

    with pytest.raises(BudgetExceeded, match="estimated-cost"):
        complete("s", "u")
    assert calls == []


def test_cost_budget_rejects_an_incomplete_rate_configuration(tmp_path):
    path = tmp_path / "invalid.json"
    path.write_text(json.dumps({"llm": {
        "provider": "openai",
        "budget": {"max_estimated_usd": 1.0},
    }}), encoding="utf-8")

    with pytest.raises(ValueError, match="requires input and output token rates"):
        ProviderConfig.from_file(path)


def test_config_rejects_unknown_fields(tmp_path):
    path = tmp_path / "invalid.json"
    path.write_text(json.dumps({"llm": {
        "provider": "openai",
        "unexpected": "typo",
    }}), encoding="utf-8")

    with pytest.raises(ValueError, match="unsupported fields: unexpected"):
        ProviderConfig.from_file(path)


def test_empty_choices_raises_rather_than_returning_none(monkeypatch):
    monkeypatch.setenv("TEST_KEY_ENV", "sk-test")
    complete = build_completion(_config(), post=lambda *a: {"choices": []})
    with pytest.raises(UnexpectedModelReply):
        complete("s", "u")


def test_record_then_replay_reproduces_responses_without_a_key(tmp_path):
    from planning.model_provider import recording_completion, replay_completion, ProviderConfig, build_completion
    transcript = tmp_path / "t.json"
    live = iter(["one", "two"])
    recorder = recording_completion(lambda s, u: next(live), transcript)
    assert recorder("S1", "U1") == "one"
    assert recorder("S2", "U2") == "two"

    replay = replay_completion(transcript)
    assert replay("S1", "U1") == "one"
    assert replay("S2", "U2") == "two"

    cfg = ProviderConfig(provider="replay", transcript_path=str(transcript))
    replay2 = build_completion(cfg)
    assert replay2("S1", "U1") == "one"


def test_replay_raises_when_a_prompt_diverges(tmp_path):
    from planning.model_provider import recording_completion, replay_completion, ReplayMismatch
    transcript = tmp_path / "t.json"
    recording_completion(lambda s, u: "x", transcript)("S", "U")
    replay = replay_completion(transcript)
    import pytest as _pytest
    with _pytest.raises(ReplayMismatch):
        replay("DIFFERENT", "PROMPT")
