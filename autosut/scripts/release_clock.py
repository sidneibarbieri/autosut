#!/usr/bin/env python3
"""Deterministic clock for generated reviewer-facing release files.

Research artifacts should not change merely because a reviewer reruns a
generator on a different day.  ``SOURCE_DATE_EPOCH`` is the standard override
used by reproducible-build tooling.  When it is absent, AutoSUT uses the frozen
2026-07-18 artifact snapshot date.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone


DEFAULT_SOURCE_DATE_EPOCH = 1_784_332_800  # 2026-07-18T00:00:00Z


def source_date_epoch() -> int:
    """Return a validated non-negative release epoch."""
    raw = os.environ.get("SOURCE_DATE_EPOCH", str(DEFAULT_SOURCE_DATE_EPOCH))
    try:
        epoch = int(raw)
    except ValueError as exc:
        raise ValueError("SOURCE_DATE_EPOCH must be an integer") from exc
    if epoch < 0:
        raise ValueError("SOURCE_DATE_EPOCH must be non-negative")
    return epoch


def release_datetime() -> datetime:
    """Return the release timestamp as a timezone-aware UTC datetime."""
    return datetime.fromtimestamp(source_date_epoch(), tz=timezone.utc)


def release_isoformat() -> str:
    """Return the release timestamp in an unambiguous ISO-8601 UTC form."""
    return release_datetime().isoformat(timespec="seconds").replace("+00:00", "Z")
