#!/usr/bin/env python3
"""Derive the Docker multi-host infrastructure qualification from its positive run bundles.

Reads the multi-host positive-run bundles, records each run's stages, fact propagation, and the
independently-confirmed effect on host B, and writes the scoped qualification the capability ledger
consumes. This qualifies the multi-host infrastructure (two hosts, per-run network, fact produced
on host A and consumed on host B, per-host probe, verified teardown); it is an
infrastructure_qualification_scenario, not a campaign reconstruction.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from infrastructure.experiment_qualification import QualificationScope, summarize  # noqa: E402
from infrastructure.qualification import (  # noqa: E402
    historical_audit_policy,
    supervised_final_policy,
)
from infrastructure.revision import current_revision  # noqa: E402

EVIDENCE_ROOT = PROJECT_ROOT / "release" / "evidence"
DEFAULT_OUTPUT = (
    PROJECT_ROOT / "release" / "experiments" / "multihost_qualification" / "qualification.json"
)
CAPABILITY = "experiment.docker_multihost_fact_chain_infrastructure"

_MULTIHOST_SCOPE = QualificationScope(
    validated=[
        "per-run private docker network",
        "two distinct host identities, each running its own real Sandcat",
        "per-run isolated Caldera (destroyed by the run)",
        "a fact produced by host A's agent and consumed by host B's agent",
        "effect confirmed on host B by a probe independent of Caldera's status",
        "a negative control: without the producing ability the fact does not propagate",
        "verified teardown and temporal verify-clean over containers and networks",
    ],
    excluded=[
        "a CTI-grounded credential-to-lateral-movement chain (grounding is Windows-only, C0029); "
        "this fact chain is synthetic (infrastructure_qualification_scenario)",
        "real-CVE realization",
        "the QEMU/Vagrant backend",
    ],
)


def _bundles(glob: str) -> list[Path]:
    bundles = [
        path
        for path in EVIDENCE_ROOT.glob(glob)
        if path.is_dir()
        and (path / "lifecycle-result.json").is_file()
        and (path / "experiment.json").is_file()
    ]
    if not bundles:
        raise FileNotFoundError(f"no multi-host bundles under {EVIDENCE_ROOT} matching {glob!r}")
    return bundles


def _policy(args: argparse.Namespace, revision: str):
    """Select a policy matching the property this infrastructure scenario is meant to qualify."""

    if args.evidence_policy == "historical-audit":
        return historical_audit_policy(name="multihost-historical-audit/v1")
    return supervised_final_policy(
        name="multihost-supervised-final/v1",
        expected_experiment="multihost",
        required_revision=args.required_revision or revision,
        required_topology="multi_host",
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
    parser.add_argument("--glob", default="multihost_caldera_f[0-9]*")
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
        default=["multi_host_infrastructure_scenario"],
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
        scope=_MULTIHOST_SCOPE,
        policy=policy,
        project_root=PROJECT_ROOT,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(qualification.model_dump_json(indent=2) + "\n", encoding="utf-8")

    print(f"[multihost-qualification] capability: {qualification.capability}")
    print(f"[multihost-qualification] result_level: {qualification.result_level.value}")
    print(
        f"[multihost-qualification] policy={policy.name}; "
        f"{qualification.clean_runs} eligible clean / {qualification.eligible_runs} eligible / "
        f"{qualification.total_runs} observed ({qualification.excluded_runs} excluded); "
        f"{qualification.effect_confirmed_runs} eligible confirmed effect; "
        f"median {qualification.total_seconds_median}s"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
