#!/usr/bin/env python3
"""Draw a stratified compatibility-validation sample and emit blind annotation sheets.

The sample is stratified by the rule that fired (or fallback), with the fallback
stratum deliberately over-sampled because it carries most of the population and
is the one the routing policy is weakest on. Two annotation sheets carry no
AutoSUT label, so each annotator decides independently. The frame keeps the
AutoSUT label for adjudication but is never shown to annotators.
"""

from __future__ import annotations

import argparse
import csv
import json
import random
from pathlib import Path

import sut_measurement_pipeline as pipeline

SCRIPTS_DIR = Path(__file__).resolve().parent
AUDIT_DIR = SCRIPTS_DIR / "results" / "audit"

# Target draw per stratum. Small strata are taken whole; the fallback stratum is
# over-sampled relative to a proportional draw so it can be evaluated on its own.
STRATUM_TARGET = {
    "R7_CF_CONTAINER_COMPATIBLE": 19,
    "R1_ID_PLATFORM_KEYWORD": 25,
    "R3_ID_LATERAL_TACTIC": 14,
    "R4_VMR_KERNEL_BOOT": 17,
    "R6_VMR_NAME_PATTERN": 17,
    "fallback": 60,
}
BLIND_FIELDS = [
    "item_id", "technique_external_id", "technique_name", "tactics",
    "platforms", "permissions", "description_excerpt", "annotator_class", "annotator_notes",
]


def _external_id(technique: dict) -> str:
    for reference in technique.get("external_references", []):
        if reference.get("source_name") == "mitre-attack":
            return reference.get("external_id", "")
    return ""


def _stratum(trace: dict) -> str:
    return "fallback" if trace["is_fallback"] else trace["rule_id"]


def _tactics(technique: dict) -> list[str]:
    return sorted(
        phase.get("phase_name", "")
        for phase in technique.get("kill_chain_phases", [])
        if phase.get("kill_chain_name") == "mitre-attack"
    )


def classify_population(bundle_path: Path) -> list[dict]:
    by_type, by_id = pipeline.index_objects_by_type(pipeline.load_bundle(bundle_path))
    rel_fwd, _, _ = pipeline.build_relationship_index(by_type.get("relationship", []))
    rows = []
    for technique in by_type.get("attack-pattern", []):
        trace = pipeline.classify_technique_compatibility_trace(technique, rel_fwd, by_id)
        rows.append({
            "technique_external_id": _external_id(technique),
            "technique_name": technique.get("name", ""),
            "tactics": ";".join(_tactics(technique)),
            "platforms": ";".join(technique.get("x_mitre_platforms", [])),
            "permissions": ";".join(technique.get("x_mitre_permissions_required", []) or []),
            "description_excerpt": " ".join(technique.get("description", "").split())[:300],
            "autosut_class": trace["class"],
            "rule_id": trace["rule_id"],
            "stratum": _stratum(trace),
        })
    return rows


def draw_sample(rows: list[dict], seed: int) -> list[dict]:
    rng = random.Random(seed)
    by_stratum: dict[str, list[dict]] = {}
    for row in rows:
        by_stratum.setdefault(row["stratum"], []).append(row)
    sample = []
    for stratum, target in STRATUM_TARGET.items():
        members = sorted(by_stratum.get(stratum, []), key=lambda row: row["technique_external_id"])
        rng.shuffle(members)
        sample.extend(members[: min(target, len(members))])
    sample.sort(key=lambda row: row["technique_external_id"])
    for index, row in enumerate(sample, start=1):
        row["item_id"] = f"CMP-{index:03d}"
    return sample


def write_frame(sample: list[dict], path: Path) -> None:
    fields = ["item_id", "technique_external_id", "technique_name", "tactics", "platforms",
              "permissions", "autosut_class", "rule_id", "stratum", "description_excerpt"]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore", lineterminator="\n")
        writer.writeheader()
        writer.writerows(sample)


def write_blind_sheet(sample: list[dict], path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=BLIND_FIELDS, extrasaction="ignore", lineterminator="\n")
        writer.writeheader()
        for row in sample:
            writer.writerow({**{field: row.get(field, "") for field in BLIND_FIELDS},
                             "annotator_class": "", "annotator_notes": ""})


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, default=Path(pipeline.ENTERPRISE_FILE))
    parser.add_argument("--seed", type=int, default=20261006)
    parser.add_argument("--output-dir", type=Path, default=AUDIT_DIR)
    args = parser.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)
    rows = classify_population(args.bundle)
    sample = draw_sample(rows, args.seed)
    write_frame(sample, args.output_dir / "compatibility_validation_frame.csv")
    write_blind_sheet(sample, args.output_dir / "compatibility_annotation_sheet_A.csv")
    write_blind_sheet(sample, args.output_dir / "compatibility_annotation_sheet_B.csv")

    strata = {stratum: sum(row["stratum"] == stratum for row in sample) for stratum in STRATUM_TARGET}
    population_strata = {stratum: sum(row["stratum"] == stratum for row in rows) for stratum in STRATUM_TARGET}
    manifest = {
        "bundle": args.bundle.name,
        "seed": args.seed,
        "population_size": len(rows),
        "sample_size": len(sample),
        "stratum_sizes": strata,
        "population_stratum_sizes": population_strata,
        "blind_sheets": ["compatibility_annotation_sheet_A.csv", "compatibility_annotation_sheet_B.csv"],
    }
    (args.output_dir / "compatibility_validation_manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    print(f"population {len(rows)}, sample {len(sample)}, strata {strata}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
