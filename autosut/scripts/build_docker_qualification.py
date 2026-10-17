#!/usr/bin/env python3
"""Derive the Docker backend's qualification from its real run bundles.

Reads the sealed lifecycle bundles a set of runs produced, aggregates their outcomes and timings,
and writes the qualification summary the capability ledger consumes. The summary records each
bundle's manifest hash, so it is verifiable against the sealed evidence and cannot claim a level
the bundles do not support.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from infrastructure.qualification import (  # noqa: E402
    historical_audit_policy,
    summarize,
    supervised_final_policy,
)
from infrastructure.revision import current_revision  # noqa: E402

EVIDENCE_ROOT = PROJECT_ROOT / "release" / "evidence"
DEFAULT_OUTPUT = (
    PROJECT_ROOT / "release" / "experiments" / "docker_qualification" / "qualification.json"
)


def _bundles(campaign: str, glob: str) -> list[Path]:
    bundles = [
        path
        for path in EVIDENCE_ROOT.glob(glob)
        if path.is_dir() and (path / "lifecycle-result.json").is_file()
    ]
    if not bundles:
        raise FileNotFoundError(f"no lifecycle bundles under {EVIDENCE_ROOT} matching {glob!r}")
    return bundles


def _policy(args: argparse.Namespace, revision: str):
    """Select an explicit policy instead of treating direct history as universal qualification."""

    if args.evidence_policy == "historical-audit":
        return historical_audit_policy(name="docker-lifecycle-historical-audit/v1")
    return supervised_final_policy(
        name="docker-lifecycle-supervised-final/v1",
        expected_experiment="lifecycle",
        required_revision=args.required_revision or revision,
        protocol_version=args.protocol_version,
        required_evidence_files=["lifecycle-result.json", "verify-clean.json"],
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign", default="0.c0010")
    parser.add_argument("--glob", default="0.c0010_*")
    parser.add_argument(
        "--evidence-policy",
        choices=("supervised-final", "historical-audit"),
        default="supervised-final",
        help="eligibility policy; historical audit preserves observations but cannot promote a release",
    )
    parser.add_argument(
        "--protocol-version",
        default="autosut-qualification/v1",
        help="version required by the supervised-final policy",
    )
    parser.add_argument(
        "--required-revision",
        help="immutable source revision required by the supervised-final policy; defaults to current",
    )
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    revision = current_revision(PROJECT_ROOT)
    policy = _policy(args, revision)
    summary = summarize(
        "docker",
        args.campaign,
        _bundles(args.campaign, args.glob),
        revision,
        policy=policy,
        project_root=PROJECT_ROOT,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(summary.model_dump_json(indent=2) + "\n", encoding="utf-8")

    print(
        f"[docker-qualification] policy={policy.name}; "
        f"{summary.clean_runs} eligible clean / {summary.eligible_runs} eligible / "
        f"{summary.total_runs} observed runs ({summary.excluded_runs} excluded); "
        f"failure recovery reached clean: {summary.failure_recovery_reached_clean}; "
        f"median {summary.total_seconds_median}s "
        f"(min {summary.total_seconds_min}s, max {summary.total_seconds_max}s); "
        f"derived level: {summary.capability_level.value}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
