from __future__ import annotations

import pytest

from scripts.release_clock import release_isoformat


def test_release_clock_uses_frozen_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SOURCE_DATE_EPOCH", raising=False)
    assert release_isoformat() == "2026-07-18T00:00:00Z"


def test_release_clock_honors_source_date_epoch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "0")
    assert release_isoformat() == "1970-01-01T00:00:00Z"


def test_release_clock_rejects_invalid_epoch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "not-an-integer")
    with pytest.raises(ValueError, match="must be an integer"):
        release_isoformat()
