"""Structural regression tests for the environment-provenance report (S31).

These run the report generator against the *real* catalog, so they guard the
end-to-end contract — resolve -> summarize -> merge — without hard-coding
campaign counts that legitimately change as the corpus grows. They assert
invariants (counts reconcile, the policy holds, every element is traceable)
rather than specific numbers.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import generate_provenance_report as gpr  # noqa: E402
from orchestrator import catalog, provenance  # noqa: E402


def test_report_covers_every_implemented_campaign():
    summaries, skipped = gpr.collect_summaries()
    accounted = {s.campaign_id for s in summaries} | set(skipped)
    for campaign_id in catalog.implemented_campaigns():
        assert campaign_id in accounted


def test_counts_reconcile_with_total():
    summaries, _ = gpr.collect_summaries()
    merged = provenance.merge_summaries(summaries)
    # by_source must sum to the element count.
    assert sum(merged.by_source.values()) == merged.total_elements
    # by_dimension must independently sum to the same total.
    dim_total = sum(sum(counts.values()) for counts in merged.by_dimension.values())
    assert dim_total == merged.total_elements
    # Percentages reconcile to 100 within rounding tolerance.
    assert abs(sum(merged.percentages.values()) - 100.0) < 0.5


def test_inferred_is_never_assigned():
    # The Hybrid policy drops `inferred`; it stays in the enum but no element
    # may carry it. If this ever fails, the dashboard/report must grow a 4th
    # column — a deliberate decision, not an accident.
    summaries, _ = gpr.collect_summaries()
    merged = provenance.merge_summaries(summaries)
    assert merged.by_source["inferred"] == 0


def test_every_element_is_traceable():
    summaries, _ = gpr.collect_summaries()
    assert summaries  # the catalog is non-empty
    for summary in summaries:
        for element in summary.elements:
            assert element.identifier
            assert element.dimension in provenance.DIMENSIONS
