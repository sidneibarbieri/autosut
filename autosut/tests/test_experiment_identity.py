from __future__ import annotations

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from infrastructure.experiment_identity import seeded_hex, seeded_uuid  # noqa: E402


def test_seeded_identifiers_are_stable_and_domain_separated() -> None:
    assert seeded_hex(7, "credential", 16) == seeded_hex(7, "credential", 16)
    assert seeded_hex(7, "credential", 16) != seeded_hex(8, "credential", 16)
    assert seeded_hex(7, "credential", 16) != seeded_hex(7, "agent", 16)
    assert seeded_uuid(7, "ability") == seeded_uuid(7, "ability")
    assert seeded_uuid(7, "ability") != seeded_uuid(7, "other")


def test_seeded_hex_rejects_invalid_requests() -> None:
    with pytest.raises(ValueError, match="purpose"):
        seeded_hex(1, "", 8)
    with pytest.raises(ValueError, match="length"):
        seeded_hex(1, "value", 65)
