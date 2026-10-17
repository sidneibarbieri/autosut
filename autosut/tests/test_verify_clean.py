"""Temporal residual sampling distinguishes an immediate clean, a delayed clean, and a leak.

A resource gone on the first look is clean; one that clears within the grace window is
clean_after_grace_period with its latency recorded; one that never clears is dirty.
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from infrastructure.verify_clean import CleanVerdict, sample_until_clean  # noqa: E402


def test_empty_on_first_sample_is_clean():
    report = sample_until_clean("docker", inventory=lambda: [])
    assert report.verdict is CleanVerdict.CLEAN
    assert report.cleanup_latency_seconds == 0.0
    assert len(report.samples) == 1


def test_a_resource_that_clears_within_grace_is_clean_after_grace_period():
    calls = {"n": 0}

    def inventory():
        calls["n"] += 1
        return ["autosut-abc-target"] if calls["n"] < 3 else []

    report = sample_until_clean(
        "docker", inventory=inventory, grace_seconds=15, interval_seconds=0.05
    )
    assert report.verdict is CleanVerdict.CLEAN_AFTER_GRACE_PERIOD
    assert report.cleanup_latency_seconds is not None
    assert report.clean is True


def test_a_resource_that_never_clears_is_dirty():
    report = sample_until_clean(
        "docker",
        inventory=lambda: ["autosut-abc-target"],
        grace_seconds=0,
        interval_seconds=0.05,
    )
    assert report.verdict is CleanVerdict.DIRTY
    assert report.cleanup_latency_seconds is None
    assert report.clean is False


def test_every_sample_is_timestamped_and_recorded():
    report = sample_until_clean("docker", inventory=lambda: [])
    assert all(sample.at_seconds >= 0 for sample in report.samples)
