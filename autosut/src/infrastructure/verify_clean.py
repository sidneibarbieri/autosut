"""Confirm a run left nothing behind by sampling over a grace period, not in a single glance.

Container teardown is asynchronous: a container can still be listed for a few seconds after its own
removal was requested. A single check therefore cannot tell a real leak from a teardown still in
flight. This samples the run's residual resources repeatedly until they clear or a deadline passes,
records every sample, and reports the cleanup latency and a verdict that distinguishes an immediate
clean, a clean reached after a grace period, and a genuine leak.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from enum import Enum

from pydantic import BaseModel, ConfigDict


class CleanVerdict(str, Enum):
    """The three outcomes a temporal residual check can reach."""

    CLEAN = "clean"                                # empty on the first sample
    CLEAN_AFTER_GRACE_PERIOD = "clean_after_grace_period"  # cleared within the grace window
    DIRTY = "dirty"                                # still present when the window closed


class ResidualSample(BaseModel):
    """The run's residual resources at one instant."""

    model_config = ConfigDict(extra="forbid")

    at_seconds: float
    resources: list[str]


class TemporalResidualReport(BaseModel):
    """The full sampling timeline, the cleanup latency, and the verdict it yields."""

    model_config = ConfigDict(extra="forbid")

    scope: str
    samples: list[ResidualSample]
    cleanup_latency_seconds: float | None
    verdict: CleanVerdict

    @property
    def clean(self) -> bool:
        return self.verdict is not CleanVerdict.DIRTY


def sample_until_clean(
    scope: str,
    inventory: Callable[[], list[str]],
    grace_seconds: int = 15,
    interval_seconds: float = 2.0,
) -> TemporalResidualReport:
    """Sample the run's residual inventory until it clears or the grace window closes."""
    started = time.monotonic()
    samples: list[ResidualSample] = []
    cleanup_latency: float | None = None

    while True:
        at = round(time.monotonic() - started, 1)
        resources = sorted(inventory())
        samples.append(ResidualSample(at_seconds=at, resources=resources))
        if not resources and cleanup_latency is None:
            cleanup_latency = at
            break
        if at >= grace_seconds:
            break
        time.sleep(interval_seconds)

    verdict = _verdict(samples, cleanup_latency)
    return TemporalResidualReport(
        scope=scope,
        samples=samples,
        cleanup_latency_seconds=cleanup_latency,
        verdict=verdict,
    )


def _verdict(samples: list[ResidualSample], cleanup_latency: float | None) -> CleanVerdict:
    if cleanup_latency is None:
        return CleanVerdict.DIRTY
    if cleanup_latency == 0.0 and len(samples) == 1:
        return CleanVerdict.CLEAN
    return CleanVerdict.CLEAN_AFTER_GRACE_PERIOD
