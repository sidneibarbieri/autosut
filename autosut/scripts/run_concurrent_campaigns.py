"""Concurrent campaign execution runner.

Where the frozen ``sticks/scripts/run_all_lab_campaigns.py`` runs every
campaign sequentially through a shared 3-VM stack (the docstring on its
line 3 reads "Sequential VM-backed batch runner"), AutoSUT can dispatch
multiple campaigns concurrently. Each campaign owns its own per-run
container (or container fleet on its own private Docker network), so
there is no shared substrate to serialize on. Caldera is shared, but
operations are per-paw so concurrent dispatch is safe.

This runner is the architectural proof of that capability: it accepts a
list of campaign IDs and a maximum concurrency, executes them in
parallel, and writes a TSV summary identical in shape to the frozen
batch output so the comparison is direct.

Usage::

    .venv/bin/python scripts/run_concurrent_campaigns.py \\
        --campaigns 0.cve_2021_41773 0.pivot_demo 0.caldera_linux_demo \\
        --max-workers 3
"""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from orchestrator import build_default


PROJECT_ROOT = Path(__file__).resolve().parent.parent
RELEASE_DIR = PROJECT_ROOT / "release"


@dataclass(frozen=True)
class BatchRow:
    campaign_id: str
    status: str
    techniques_total: int
    techniques_success: int
    duration_seconds: float
    manifest_path: str


def _run_one_campaign(campaign_id: str) -> BatchRow:
    """Execute a single campaign and return a BatchRow.

    Errors propagate as exceptions - the parent will record them in the
    BatchRow with status="error" instead of masking them.
    """
    orchestrator = build_default()
    started_at = time.monotonic()
    result = orchestrator.run_campaign(campaign_id)
    duration = time.monotonic() - started_at
    return BatchRow(
        campaign_id=campaign_id,
        status="ok" if result.successful == result.total_techniques else "partial",
        techniques_total=result.total_techniques,
        techniques_success=result.successful,
        duration_seconds=round(duration, 2),
        manifest_path=result.manifest_path or "",
    )


def _run_one_campaign_safe(campaign_id: str) -> BatchRow:
    """Wrapper that converts unexpected exceptions into a BatchRow with
    status='error'. We log the exception type + message so a reviewer can
    see exactly what failed - we never silently swallow."""
    try:
        return _run_one_campaign(campaign_id)
    except (RuntimeError, ValueError, OSError) as exc:
        # Re-raise unexpected exception types so they surface to the user;
        # only handle exceptions we anticipate from upstream code.
        return BatchRow(
            campaign_id=campaign_id,
            status=f"error:{type(exc).__name__}",
            techniques_total=0,
            techniques_success=0,
            duration_seconds=0.0,
            manifest_path=f"({type(exc).__name__}: {exc})",
        )


def run(campaigns: list[str], max_workers: int) -> list[BatchRow]:
    """Run ``campaigns`` concurrently with at most ``max_workers`` at a time."""
    rows: list[BatchRow] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(_run_one_campaign_safe, campaign_id): campaign_id
            for campaign_id in campaigns
        }
        for future in concurrent.futures.as_completed(futures):
            row = future.result()
            print(
                f"[concurrent] {row.campaign_id:35s} | "
                f"{row.status:20s} | "
                f"{row.techniques_success}/{row.techniques_total} | "
                f"{row.duration_seconds:6.1f}s"
            )
            rows.append(row)
    return rows


def _write_summary(rows: list[BatchRow], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, delimiter="\t", lineterminator="\n")
        writer.writerow(["campaign_id", "status", "total", "success",
                          "duration_seconds", "manifest_path"])
        for row in rows:
            writer.writerow([
                row.campaign_id, row.status,
                row.techniques_total, row.techniques_success,
                row.duration_seconds, row.manifest_path,
            ])
    print(f"[concurrent] summary: {output_path}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run AutoSUT campaigns concurrently (demonstration of "
                    "architectural advantage over the frozen sequential runner)."
    )
    parser.add_argument("--campaigns", nargs="+", required=True,
                        help="Campaign IDs to run.")
    parser.add_argument("--max-workers", type=int, default=3,
                        help="Maximum number of campaigns running at once.")
    parser.add_argument("--output", type=Path, default=None,
                        help="TSV summary path; defaults to "
                              "release/concurrent_batch_<ts>.tsv.")
    args = parser.parse_args()

    started_at = time.monotonic()
    rows = run(args.campaigns, max_workers=args.max_workers)
    total_duration = time.monotonic() - started_at
    sequential_estimate = sum(row.duration_seconds for row in rows)
    speedup = (sequential_estimate / total_duration) if total_duration else 0.0
    print(
        f"[concurrent] wall_clock={total_duration:.1f}s "
        f"sum_individual={sequential_estimate:.1f}s "
        f"speedup={speedup:.2f}x"
    )

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    output_path = args.output or (RELEASE_DIR / f"concurrent_batch_{timestamp}.tsv")
    _write_summary(rows, output_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
