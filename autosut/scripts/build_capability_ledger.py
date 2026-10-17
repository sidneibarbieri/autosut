#!/usr/bin/env python3
"""Emit the honest capability ledger for the experiment substrate.

Each record states the level a capability has actually reached, bounded by the self-checking
CapabilityRecord: a level asserting real execution must cite clean runs, and only
end_to_end_validated / reproducible may back a manuscript claim. Authoring a level above its
evidence fails validation here, so the ledger cannot be inflated by declaration.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from infrastructure.capability import (  # noqa: E402
    CapabilityLedger,
    CapabilityLevel,
    CapabilityRecord,
)
from evaluation.canonical_operational_witness import (  # noqa: E402
    assess_caldera_dispatch_witness,
)
from infrastructure.experiment_qualification import (  # noqa: E402
    ExperimentQualification,
    capability_record as experiment_capability_record,
)
from infrastructure.qualification import QualificationSummary, capability_record  # noqa: E402
from infrastructure.revision import current_revision  # noqa: E402

DEFAULT_OUTPUT = (
    PROJECT_ROOT / "release" / "experiments" / "capability_ledger" / "capabilities.json"
)
DOCKER_QUALIFICATION = (
    PROJECT_ROOT / "release" / "experiments" / "docker_qualification" / "qualification.json"
)
CALDERA_EXPERIMENT_QUALIFICATION = (
    PROJECT_ROOT / "release" / "experiments" / "caldera_experiment" / "qualification.json"
)
MULTIHOST_QUALIFICATION = (
    PROJECT_ROOT / "release" / "experiments" / "multihost_qualification" / "qualification.json"
)


def _multihost_experiment_record() -> CapabilityRecord:
    """Derive the multi-host infrastructure record from its qualification, when it exists."""
    if not MULTIHOST_QUALIFICATION.is_file():
        return CapabilityRecord(
            capability="experiment.docker_multihost_fact_chain_infrastructure",
            level=CapabilityLevel.IMPLEMENTED,
            note="Multi-host lifecycle exists but no qualification is present; run "
            "scripts/run_caldera_experiment_multihost.py then build_multihost_qualification.py.",
        )
    qualification = ExperimentQualification.model_validate_json(
        MULTIHOST_QUALIFICATION.read_text(encoding="utf-8")
    )
    return experiment_capability_record(
        qualification,
        "release/experiments/multihost_qualification/qualification.json",
    )


def _caldera_experiment_record() -> CapabilityRecord:
    """Derive the isolated-Caldera experiment record from its qualification, when it exists.

    With no qualification present the honest level is implemented: the lifecycle integration exists
    but no full run has been recorded. The level is read from the bundles, never asserted.
    """
    if not CALDERA_EXPERIMENT_QUALIFICATION.is_file():
        return CapabilityRecord(
            capability="experiment.docker_isolated_caldera_integration",
            level=CapabilityLevel.IMPLEMENTED,
            note="Lifecycle integration exists but no full-experiment qualification is present; run "
            "scripts/run_caldera_experiment.py then scripts/build_caldera_experiment_qualification.py.",
        )
    qualification = ExperimentQualification.model_validate_json(
        CALDERA_EXPERIMENT_QUALIFICATION.read_text(encoding="utf-8")
    )
    return experiment_capability_record(qualification)


_DOCKER_SUT_LIFECYCLE = "lifecycle.docker_sut_materialize_execute_teardown"


def _docker_sut_lifecycle_record() -> CapabilityRecord:
    """Derive the Docker SUT-lifecycle record from the published, verifiable qualification summary.

    Scope is deliberately narrow: materialize, execute, verified teardown, verify-clean for one
    campaign. It is NOT the full experiment, which additionally requires a Caldera instance created
    and destroyed inside the run. The summary is committed and records each run bundle's manifest
    hash, so a reviewer regenerates the bundles and re-derives the same level.
    """
    if not DOCKER_QUALIFICATION.is_file():
        return CapabilityRecord(
            capability=_DOCKER_SUT_LIFECYCLE,
            level=CapabilityLevel.IMPLEMENTED,
            note="Lifecycle exists but no qualification summary is present; run "
            "scripts/run_lifecycle.py five times then scripts/build_docker_qualification.py.",
        )
    summary = QualificationSummary.model_validate_json(
        DOCKER_QUALIFICATION.read_text(encoding="utf-8")
    )
    return capability_record(summary, _DOCKER_SUT_LIFECYCLE)


def _caldera_dispatch_record() -> CapabilityRecord:
    """Derive the dispatch capability from the canonical public witness."""
    assessment = assess_caldera_dispatch_witness(PROJECT_ROOT)
    if assessment.witness is None:
        return CapabilityRecord(
            capability="caldera.operation_dispatch",
            level=CapabilityLevel.IMPLEMENTED,
            evidence_paths=list(assessment.evidence_artifacts),
            note=(
                "The dispatch integration exists, but the canonical released witness does not "
                f"pass its static evidence gate: {assessment.failure_reason}"
            ),
        )
    return CapabilityRecord(
        capability="caldera.operation_dispatch",
        level=CapabilityLevel.END_TO_END_VALIDATED,
        clean_runs_observed=1,
        implementation_revision=assessment.witness.implementation_revision,
        evidence_paths=list(assessment.evidence_artifacts),
        note=(
            "One sealed, serial, isolated C0045-derived surrogate slice reached a finished "
            "Caldera operation, an independently confirmed effect, and clean teardown. This is "
            "a one-cell author-environment witness, not a reliability estimate, a complete "
            "campaign emulation, or a claim-ready reproduction."
        ),
    )


def _shadowray_surrogate_record() -> CapabilityRecord:
    """Keep the SUT realization label attached to the same public witness."""
    assessment = assess_caldera_dispatch_witness(PROJECT_ROOT)
    implementation_revision = (
        assessment.witness.implementation_revision if assessment.witness is not None else None
    )
    return CapabilityRecord(
        capability="sut.shadowray_ray_injection",
        level=CapabilityLevel.SURROGATE,
        implementation_revision=implementation_revision,
        evidence_paths=list(assessment.evidence_artifacts),
        note=(
            "The public bounded witness uses a declared surrogate rather than a deployed "
            "historical CVE-2023-48022 target. It cannot support a real-victim or historical "
            "equivalence claim."
        ),
    )


def _mark_release_applicability(records: list[CapabilityRecord]) -> list[CapabilityRecord]:
    """A capability is claim-ready only when its qualifying set ran on the revision now present.

    e1-e5 and f1-f5 ran on different, now-superseded revisions, so they are preserved evidence of
    those revisions but do not qualify the current code: no committed release commit has been
    re-run across all backends yet, so no capability applies to the current release.
    """
    revision = current_revision(PROJECT_ROOT)
    for record in records:
        if record.implementation_revision is not None:
            record.applies_to_current_revision = record.implementation_revision == revision
    return records


def _current_ledger() -> CapabilityLedger:
    return CapabilityLedger(
        records=_mark_release_applicability(
            [
                _docker_sut_lifecycle_record(),
                _caldera_experiment_record(),
                _multihost_experiment_record(),
                _caldera_dispatch_record(),
                _shadowray_surrogate_record(),
                CapabilityRecord(
                    capability="infrastructure.preflight",
                    level=CapabilityLevel.COMPONENT_TESTED,
                    note="Host qualification matrix; 5 unit tests. No materialization performed.",
                ),
                CapabilityRecord(
                    capability="infrastructure.run_context",
                    level=CapabilityLevel.COMPONENT_TESTED,
                    note="run_id namespacing, execution lock, sealed manifest; 6 unit tests in "
                    "isolation. Not yet exercised by a real lifecycle run.",
                ),
                CapabilityRecord(
                    capability="infrastructure.capability_ledger",
                    level=CapabilityLevel.COMPONENT_TESTED,
                    note="This taxonomy; 7 unit tests enforcing that a level cannot exceed its "
                    "evidence.",
                ),
                CapabilityRecord(
                    capability="infrastructure.process_supervision_termination",
                    level=CapabilityLevel.INTEGRATION_TESTED,
                    evidence_paths=[
                        "tests/test_process_supervisor.py",
                        "tests/test_supervised_docker_sweep.py",
                    ],
                    note="OS-level termination primitive + real Docker namespace sweep, wrapped as the "
                    "supervised entrypoint scripts/run_supervised.py. 6 unit tests prove termination "
                    "(a SIGTERM-trapping child is still killed by SIGKILL; a group kill reaches a "
                    "grandchild). 2 Docker-gated integration tests prove the sweep against REAL "
                    "containers: the sweep removes an autosut container, and a hung run that created a "
                    "container is terminated by its process group and its container swept (residual "
                    "empty). This is genuine termination, unlike the in-process watchdog whose "
                    "thread.join is race-mitigation only. This level is bounded: integration_tested "
                    "reflects the PRIMITIVE + sweep proven against a real Docker dependency, NOT the "
                    "canonical experiment path. Promotion is evidence-gated, never automatic. One "
                    "happy-path supervised full caldera run IS now recorded under run_supervised.py "
                    "(9/9 stages ok, effect confirmed, final_state clean, residual none, supervisor "
                    "exit 0 with escalation=[], sweep empty) -- but escalation=[] means no signal "
                    "fired, so that run validates the WRAPPER, not termination. Termination on REAL "
                    "experiment stages, and R4 resolution, require the structured cross-stage "
                    "interruption matrix (materialize/readiness/provision/sandcat/enroll/operation/"
                    "persist/teardown x SIGINT,SIGTERM,deadline) with clean residual inventory. That "
                    "matrix is not yet run, and the qualifying batches do not yet route exclusively "
                    "through run_supervised.py, so R4 is integration-proven-on-Docker, NOT resolved.",
                ),
                CapabilityRecord(
                    capability="backend.qemu_linux_arm64",
                    level=CapabilityLevel.IMPLEMENTED,
                    note="QEMUEnvironment code exists; preflight reports requires_boot_qualification "
                    "(toolchain + HVF present, boot never proven on this host). Not self-materializing "
                    "yet (base image/firmware not pinned by hash; no overlay/cloud-init/run_id).",
                ),
                CapabilityRecord(
                    capability="backend.windows_x86_64",
                    level=CapabilityLevel.DEVELOPMENT_IN_PROGRESS,
                    note="Native Windows is an active but unqualified development track. The current "
                    "source includes a credential-free unattended template, a per-run renderer, and "
                    "host preflight checks; no native Windows guest boot, procedure execution, teardown, "
                    "or independent reproduction has passed. The corpus question is controlled by the "
                    "hash-bound human-adjudication protocol in docs/NATIVE_WINDOWS_CORPUS_ADJUDICATION.md: "
                    "ATT&CK platform labels only triage review packets and cannot determine semantics. "
                    "Until a frozen vendored corpus, complete protocol-defined adjudication, and separate "
                    "execution qualification exist, this capability is not qualified and cannot support a claim.",
                ),
                CapabilityRecord(
                    capability="caldera.isolated_instance_per_run",
                    level=CapabilityLevel.INTEGRATION_TESTED,
                    evidence_paths=["release/experiments/caldera_isolation/qualification.json"],
                    note="A fresh Caldera is materialized on its own port, answers its API (ready in "
                    "~12s), yields its randomized red key, and is force-removed with confirmed absence "
                    "-- all timed. Isolation primitive only; it does not yet enroll a Sandcat or run "
                    "an operation, so it does not qualify the full experiment on its own.",
                ),
            ]
        )
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    ledger = _current_ledger()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(ledger.model_dump_json(indent=2) + "\n", encoding="utf-8")

    supporting = {record.capability for record in ledger.claim_supporting()}
    print(f"[capability-ledger] {len(ledger.records)} capabilities recorded")
    for record in ledger.records:
        marker = "claim-ready" if record.may_support_a_claim else "not-claim-ready"
        print(f"[capability-ledger]   {record.capability}: {record.level.value} ({marker})")
    print(
        f"[capability-ledger] {len(supporting)} capability(ies) mature enough to back a claim: "
        f"{sorted(supporting) or 'none'}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
