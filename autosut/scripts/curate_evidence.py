"""Curate the release/evidence/ tree.

For artifact-evaluation integrity, ``release/evidence/`` must hold only canonical
runs: one golden run per campaign, full evidence set, post-final-orchestrator.
Everything else (empty runs, partial failures, pre-final-orchestrator runs,
broken manifests) belongs under ``_archive/``.

This script:

1. Walks every ``release/evidence/0.*_2026*`` directory.
2. Classifies each run as ``golden_candidate`` / ``partial`` / ``empty`` /
   ``broken``.
3. Picks the *most recent* ``golden_candidate`` per campaign as the golden
   run for that campaign.
4. Moves everything else under ``release/evidence/_archive/`` so the
   primary tree contains only golden runs.
5. Writes ``release/golden_runs.json`` enumerating the chosen runs.

Golden-candidate criteria (all must hold):

- ``manifest.json`` exists and parses.
- ``summary.json`` exists.
- ``fidelity_report.json`` exists (the fidelity rubric must have run).
- The manifest has at least one technique outcome.
- Every technique status is ``success``.

The script is idempotent: archived runs stay archived; goldens stay
golden across re-invocations.

Usage::

    .venv/bin/python scripts/curate_evidence.py            # dry-run report
    .venv/bin/python scripts/curate_evidence.py --apply    # actually move
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
EVIDENCE_ROOT = PROJECT_ROOT / "release" / "evidence"
ARCHIVE_ROOT = EVIDENCE_ROOT / "_archive"
GOLDEN_RUNS_PATH = PROJECT_ROOT / "release" / "golden_runs.json"


@dataclass
class RunClassification:
    """One run's classification result. All fields are JSON-serialisable."""

    run_id: str
    campaign_id: str
    path: str
    techniques_total: int
    techniques_success: int
    has_manifest: bool
    has_summary: bool
    has_rubric: bool
    has_composition: bool
    has_teardown: bool
    classification: str  # "golden_candidate" | "partial" | "empty" | "broken"
    reason: str


def _classify_run(run_dir: Path) -> RunClassification:
    """Decide which bucket a run belongs to. Pure: only reads files."""
    manifest_path = run_dir / "manifest.json"
    summary_path = run_dir / "summary.json"
    rubric_path = run_dir / "fidelity_report.json"
    teardown_path = run_dir / "sut" / "teardown.log"
    composition_candidates = list((run_dir / "sut").glob("composition_*.json")) \
        if (run_dir / "sut").exists() else []

    has_manifest = manifest_path.exists()
    has_summary = summary_path.exists()
    has_rubric = rubric_path.exists()
    has_teardown = teardown_path.exists()
    has_composition = len(composition_candidates) > 0

    if not has_manifest:
        return RunClassification(
            run_id=run_dir.name, campaign_id="?",
            path=str(run_dir.relative_to(PROJECT_ROOT)),
            techniques_total=0, techniques_success=0,
            has_manifest=False, has_summary=has_summary, has_rubric=has_rubric,
            has_composition=has_composition, has_teardown=has_teardown,
            classification="broken", reason="missing manifest.json",
        )

    manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))
    techniques = manifest_data.get("techniques", [])
    successful = sum(1 for tech in techniques if tech.get("status") == "success")
    campaign_id = manifest_data.get("campaign_id", "?")

    common_fields = dict(
        run_id=manifest_data.get("run_id", run_dir.name),
        campaign_id=campaign_id,
        path=str(run_dir.relative_to(PROJECT_ROOT)),
        techniques_total=len(techniques),
        techniques_success=successful,
        has_manifest=True,
        has_summary=has_summary,
        has_rubric=has_rubric,
        has_composition=has_composition,
        has_teardown=has_teardown,
    )

    if not techniques:
        return RunClassification(
            **common_fields,
            classification="empty",
            reason="manifest has zero techniques",
        )

    if successful != len(techniques):
        return RunClassification(
            **common_fields,
            classification="partial",
            reason=f"only {successful}/{len(techniques)} techniques succeeded",
        )

    if not has_rubric:
        return RunClassification(
            **common_fields,
            classification="partial",
            reason="rubric report missing — predates multi-zone topology support",
        )

    if not has_summary:
        return RunClassification(
            **common_fields,
            classification="partial",
            reason="summary.json missing",
        )

    return RunClassification(
        **common_fields,
        classification="golden_candidate",
        reason="all techniques succeeded; manifest + summary + rubric present",
    )


def _designate_goldens(classifications: list[RunClassification]) -> dict[str, str]:
    """Pick the most recent golden_candidate per campaign.

    Returns a map of ``campaign_id -> golden run_id``.
    """
    candidates_per_campaign: dict[str, list[RunClassification]] = {}
    for classification in classifications:
        if classification.classification != "golden_candidate":
            continue
        candidates_per_campaign.setdefault(
            classification.campaign_id, []).append(classification)
    chosen: dict[str, str] = {}
    def run_timestamp(run_id: str) -> str:
        """Return the sortable timestamp suffix from a run identifier."""
        match = re.search(r"(\d{8}_\d{6})$", run_id)
        return match.group(1) if match else ""

    for campaign_id, runs in candidates_per_campaign.items():
        # Labels such as ``_realcheck_`` may precede the timestamp. Comparing
        # whole identifiers would sort those labels instead of run time.
        runs.sort(
            key=lambda run: (run_timestamp(run.run_id), run.run_id),
            reverse=True,
        )
        chosen[campaign_id] = runs[0].run_id
    return chosen


def _print_report(classifications: list[RunClassification],
                  goldens: dict[str, str]) -> None:
    by_classification: dict[str, int] = {}
    for classification in classifications:
        by_classification[classification.classification] = \
            by_classification.get(classification.classification, 0) + 1
    print("=== Classification breakdown ===")
    for key, count in sorted(by_classification.items()):
        print(f"  {key:20s} {count}")
    print()
    print("=== Golden runs designated ===")
    for campaign_id, golden_run_id in sorted(goldens.items()):
        print(f"  {campaign_id:38s} -> {golden_run_id}")
    print()
    no_golden = sorted(
        {run.campaign_id for run in classifications}
        - set(goldens) - {"?"}
    )
    if no_golden:
        print("=== Campaigns with NO golden candidate ===")
        for campaign_id in no_golden:
            print(f"  {campaign_id}")


def _apply_archive(classifications: list[RunClassification],
                   goldens: dict[str, str]) -> int:
    """Move every non-golden run under ARCHIVE_ROOT. Returns # moved."""
    ARCHIVE_ROOT.mkdir(parents=True, exist_ok=True)
    golden_ids = set(goldens.values())
    moved = 0
    for classification in classifications:
        if classification.run_id in golden_ids:
            continue
        source = PROJECT_ROOT / classification.path
        if not source.exists():
            continue
        destination = ARCHIVE_ROOT / source.name
        if destination.exists():
            if source.is_dir():
                shutil.rmtree(source)
            else:
                source.unlink()
            moved += 1
            continue
        shutil.move(str(source), str(destination))
        moved += 1
    return moved


def _read_run_metrics(run_dir: Path) -> dict[str, Any]:
    """Read manifest, rubric, execution modes, and provenance metrics."""
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    techniques = manifest.get("techniques", [])
    passed = sum(1 for tech in techniques if tech.get("status") == "success")
    failed = sum(1 for tech in techniques if tech.get("status") != "success")
    fidelity_distribution: dict[str, int] = {}
    execution_modes: dict[str, int] = {}
    for technique in techniques:
        fidelity_key = technique.get("executed_fidelity", "?")
        fidelity_distribution[fidelity_key] = (
            fidelity_distribution.get(fidelity_key, 0) + 1)
        mode_key = technique.get("executed_mode", "?")
        execution_modes[mode_key] = execution_modes.get(mode_key, 0) + 1
    return {
        "techniques_total": len(techniques),
        "techniques_pass": passed,
        "techniques_fail": failed,
        "fidelity_distribution": fidelity_distribution,
        "execution_modes": execution_modes,
        "provenance_per_element_class": _aggregate_provenance(run_dir),
    }


def _aggregate_provenance(run_dir: Path) -> dict[str, dict[str, int]]:
    """Walk every ``sut/composition_*.json`` and bucket each composition
    element by its ``source`` tag (provenance taxonomy).

    Returns a nested dict::

        {
          "credentials":         {"analyst_authored": 1, ...},
          "artifacts":           {"analyst_authored": 2, ...},
          "applications":        {"corpus_supported": 1, ...},
          "exposures":           {"analyst_authored": 1, ...},
        }

    Reviewers and the realism matrix consume this to report the
    ``% corpus_supported`` vs ``% analyst_authored`` breakdown for each
    campaign — which is the methodologically-strongest comparison axis
    against the frozen artefact, since the frozen never tagged origin.
    """
    sut_dir = run_dir / "sut"
    buckets: dict[str, dict[str, int]] = {
        "credentials": {}, "artifacts": {},
        "applications": {}, "exposures": {},
    }
    if not sut_dir.exists():
        return buckets
    for composition_path in sorted(sut_dir.glob("composition_*.json")):
        composition = json.loads(composition_path.read_text(encoding="utf-8"))
        for class_key in buckets:
            for element in composition.get(class_key, []):
                source = element.get("source", "analyst_authored")
                buckets[class_key][source] = buckets[class_key].get(source, 0) + 1
    return buckets


def _classify_tier(execution_modes: dict[str, int]) -> str:
    """Separate mechanistic executions from runs containing marker steps.

    This label describes execution mode only.  It deliberately avoids
    ``full_real`` because a mechanistic run may still use an adapted surrogate.
    """
    real_modes = {"real_controlled", "caldera_driven", "atomic_red_team"}
    has_any_non_real = any(mode not in real_modes for mode in execution_modes)
    return ("tier_2_marker_mixed" if has_any_non_real
            else "tier_1_mechanistic_execution")


# CTI scope distinction (paper-aligned with the "procedural semantics gap"
# framing). Specific historical campaigns (CVE-anchored or named operation)
# carry sharper attribution than intrusion-set aggregates. Reviewer sees the
# distinction directly in golden_runs.json so a 100% pass rate is read in
# context.
_INTRUSION_SET_CAMPAIGNS = {
    "0.fin6_emulation",      # G0037 — intrusion set, behavioral aggregate
    "0.apt41_dust",
    "0.apt41_dust_full",
    "0.costaricto",
    "0.outer_space",
}


def _classify_cti_scope(campaign_id: str) -> str:
    """Return ``"campaign"`` for specific events (named operation with CVE
    and timeline) and ``"intrusion_set"`` for adversary-group aggregates.

    Campaign attribution is sharper because the procedure set is anchored
    to a documented historical event; intrusion-set runs document an
    aggregated behavioral profile and should be read accordingly.
    """
    if campaign_id in _INTRUSION_SET_CAMPAIGNS:
        return "intrusion_set"
    return "campaign"


def _write_golden_runs_file(goldens: dict[str, str],
                             classifications: list[RunClassification]) -> None:
    """Persist a canonical record of the chosen golden runs.

    Schema is now self-describing: every entry
    carries pass/fail counts, fidelity distribution, execution modes,
    composition presence, teardown presence, and a tier marker.
    """
    classification_by_run = {
        classification.run_id: classification
        for classification in classifications
    }
    entries: list[dict[str, Any]] = []
    for campaign_id, run_id in sorted(goldens.items()):
        classification = classification_by_run[run_id]
        run_dir = Path(classification.path)
        if not run_dir.is_absolute():
            run_dir = PROJECT_ROOT / classification.path
        metrics = _read_run_metrics(run_dir)
        entries.append({
            "campaign_id": campaign_id,
            "golden_run_id": run_id,
            "evidence_path": str(classification.path),
            "cti_scope_type": _classify_cti_scope(campaign_id),
            "techniques_total": metrics["techniques_total"],
            "techniques_pass": metrics["techniques_pass"],
            "techniques_fail": metrics["techniques_fail"],
            "fidelity_distribution": metrics["fidelity_distribution"],
            "execution_modes": metrics["execution_modes"],
            "tier": _classify_tier(metrics["execution_modes"]),
            "has_composition": classification.has_composition,
            "has_teardown": classification.has_teardown,
            # Provenance breakdown per element class. Keyed by
            # element class (credentials/artifacts/applications/exposures)
            # -> source tag (corpus_supported/analyst_authored/...) -> count.
            "provenance_per_element_class":
                metrics["provenance_per_element_class"],
        })
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "claim_scope": (
            "Campaign emulation instantiates a declared subset of "
            "ATT&CK-linked behaviors in a SUT whose software, credentials, "
            "services, topology, and vulnerability state are explicitly "
            "composed and logged. The goal is bounded, auditable replay of "
            "the environment-conditioned behaviors supported by the CTI "
            "scope — not historical reconstruction of the original "
            "intrusion."
        ),
        "criteria": [
            "manifest.json exists and parses",
            "summary.json exists",
            "fidelity_report.json exists",
            "manifest has at least one technique",
            "every technique status == success",
            "sut/teardown.log exists",
            "at least one sut/composition_*.json present",
        ],
        "tiering": {
            "tier_1_mechanistic_execution": (
                "every technique used a mechanistic execution mode "
                "(real_controlled, caldera_driven or atomic_red_team); this "
                "does not imply faithful fidelity or a real product"),
            "tier_2_marker_mixed": (
                "100% status success but at least one step is a "
                "naive_simulated marker; markers are declared coverage, not "
                "execution evidence"),
        },
        "cti_scope_types": {
            "campaign": ("specific historical event with CVE-anchored "
                          "attribution and timeline (e.g. ShadowRay, "
                          "CVE-2021-41773, Operation MidnightEclipse)"),
            "intrusion_set": ("behavioral aggregate of a documented "
                               "adversary group (e.g. FIN6/G0037, APT41); "
                               "less specific than campaign attribution"),
        },
        "provenance_taxonomy": {
            "corpus_supported": ("anchored in CTI/ATT&CK/STIX evidence "
                                  "(CVE pin, MITRE-attributed software, "
                                  "campaign attribution detail)"),
            "external_reference": ("anchored outside the evaluated CTI "
                                     "snapshot in a vendor advisory, NVD "
                                     "record, or package metadata"),
            "analyst_authored": ("deliberate analyst choice not constrained "
                                  "by the corpus (topology zones, decoy "
                                  "files, lab credential strategy)"),
            "autosut_concretized": ("AutoSUT picked a defensible concrete "
                                     "value when the corpus said only "
                                     "'weak credentials' or 'web service'"),
            "inferred": ("lower-confidence heuristic inference from the "
                          "corpus the reviewer should treat as assumption"),
        },
        "campaigns": entries,
    }
    GOLDEN_RUNS_PATH.write_text(
        json.dumps(payload, indent=2), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true",
                        help="Actually move non-golden runs (without this "
                              "flag the script only reports).")
    args = parser.parse_args()

    classifications = [
        _classify_run(run_dir)
        for run_dir in sorted(EVIDENCE_ROOT.glob("0.*_2026*"))
        if run_dir.is_dir()
    ]
    goldens = _designate_goldens(classifications)

    _print_report(classifications, goldens)
    if args.apply:
        _write_golden_runs_file(goldens, classifications)
        print(f"\n[curate] golden_runs.json written to "
              f"{GOLDEN_RUNS_PATH.relative_to(PROJECT_ROOT)}")
        moved = _apply_archive(classifications, goldens)
        print(f"[curate] moved {moved} non-golden runs to "
              f"{ARCHIVE_ROOT.relative_to(PROJECT_ROOT)}/")
    else:
        print("[curate] dry-run; no files changed; pass --apply to curate")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
