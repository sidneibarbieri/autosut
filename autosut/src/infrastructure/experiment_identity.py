"""Deterministic identifiers for seeded experiments."""

from __future__ import annotations

import hashlib
import uuid


def seeded_hex(seed: int, purpose: str, length: int) -> str:
    if not purpose:
        raise ValueError("seeded identity purpose cannot be empty")
    if length < 1 or length > 64:
        raise ValueError("seeded hex length must be between 1 and 64")
    payload = f"autosut-experiment/v1\0{seed}\0{purpose}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:length]


def seeded_uuid(seed: int, purpose: str) -> uuid.UUID:
    token = seeded_hex(seed, purpose, 64)
    return uuid.uuid5(uuid.NAMESPACE_URL, f"autosut-experiment/v1/{token}")
