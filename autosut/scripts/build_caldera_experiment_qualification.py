#!/usr/bin/env python3
"""Derive the full-experiment qualification from its run bundles.

Reads the isolated-Caldera experiment bundles, records each run's stages, realization, operation
state, and independently-confirmed effect, and writes the scoped qualification the capability
ledger consumes. The level follows from the bundles; it is not asserted.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from infrastructure.experiment_qualification import summarize  # noqa: E402
from infrastructure.qualification import (  # noqa: E402
    historical_audit_policy,
    supervised_final_policy,
)
from infrastructure.revision import current_revision  # noqa: E402

EVIDENCE_ROOT = PROJECT_ROOT / "release" / "evidence"
DEFAULT_OUTPUT = (
    PROJECT_ROOT / "release" / "experiments" / "caldera_experiment" / "qualification.json"
)
CAPABILITY = "experiment.docker_isolated_caldera_integration"


def _bundles(glob: str) -> list[Path]:
    bundles = [
        path
        for path in EVIDENCE_ROOT.glob(glob)
        if path.is_dir()
        and (path / "lifecycle-result.json").is_file()
        and (path / "experiment.json").is_file()
    ]
    if not bundles:
        raise FileNotFoundError(f"no experiment bundles under {EVIDENCE_ROOT} matching {glob!r}")
    return bundles


def _policy(args: argparse.Namespace, revision: str):
    """Make the supervised final protocol explicit while retaining an audit-only mode."""

    if args.evidence_policy == "historical-audit":
        return historical_audit_policy(name="caldera-experiment-historical-audit/v1")
    return supervised_final_policy(
        name="caldera-experiment-supervised-final/v1",
        expected_experiment="caldera",
        required_revision=args.required_revision or revision,
        required_topology="single_host",
        accepted_realizations=args.accepted_realization,
        required_evidence_files=[
            "lifecycle-result.json",
            "experiment.json",
            "verify-clean.json",
        ],
        protocol_version=args.protocol_version,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--glob", default="shadowray_caldera_c*")
    parser.add_argument(
        "--evidence-policy",
        choices=("supervised-final", "historical-audit"),
        default="supervised-final",
        help="eligibility policy; historical audit retains observations but cannot promote a release",
    )
    parser.add_argument("--protocol-version", default="autosut-qualification/v1")
    parser.add_argument(
        "--required-revision",
        help="immutable source revision required by the supervised-final policy; defaults to current",
    )
    parser.add_argument(
        "--accepted-realization",
        action="append",
        default=["surrogate"],
        help="accepted realization for this scoped protocol; repeat to allow more than one",
    )
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    revision = current_revision(PROJECT_ROOT)
    policy = _policy(args, revision)
    qualification = summarize(
        CAPABILITY,
        _bundles(args.glob),
        revision,
        policy=policy,
        project_root=PROJECT_ROOT,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(qualification.model_dump_json(indent=2) + "\n", encoding="utf-8")

    print(f"[caldera-experiment] capability: {qualification.capability}")
    print(f"[caldera-experiment] result_level: {qualification.result_level.value}")
    print(
        f"[caldera-experiment] policy={policy.name}; "
        f"{qualification.clean_runs} eligible clean / {qualification.eligible_runs} eligible / "
        f"{qualification.total_runs} observed ({qualification.excluded_runs} excluded); "
        f"{qualification.effect_confirmed_runs} eligible confirmed effect; "
        f"realizations {qualification.realizations_observed}; "
        f"median {qualification.total_seconds_median}s"
    )
    for record in qualification.runs:
        print(
            f"[caldera-experiment]   {record.label}: {record.final_state}; "
            f"operation={record.operation_state}; effect={record.effect_confirmed}; "
            f"realization={record.realization}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
