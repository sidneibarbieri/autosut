#!/usr/bin/env python3
"""
Audit published campaign metadata against the local MITRE ATT&CK Enterprise bundle.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
CAMPAIGNS_DIR = PROJECT_ROOT / "campaigns"
DEFAULT_BUNDLE = PROJECT_ROOT / "data" / "stix" / "enterprise-attack.json"
OUTPUT_JSON = PROJECT_ROOT / "results" / "mitre_metadata_audit.json"
OUTPUT_MD = PROJECT_ROOT / "results" / "MITRE_METADATA_AUDIT.md"

REQUIRED_STEP_FIELDS = (
    "technique_id",
    "name",
    "tactic",
    "platform",
    "description",
)


def display_path(path: Path) -> str:
    try:
        return str(path.relative_to(PROJECT_ROOT))
    except ValueError:
        return str(path)


def normalize_tactic(value: str) -> str:
    return value.strip().lower().replace("_", "-")


def build_attack_index(bundle_path: Path) -> dict[str, dict]:
    bundle = json.loads(bundle_path.read_text())
    attack_index: dict[str, dict] = {}

    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked", False) or obj.get("x_mitre_deprecated", False):
            continue

        external_id = ""
        for reference in obj.get("external_references", []):
            if reference.get("source_name") == "mitre-attack":
                external_id = reference.get("external_id", "")
                break
        if not external_id:
            continue

        tactics = sorted(
            {
                normalize_tactic(phase.get("phase_name", ""))
                for phase in obj.get("kill_chain_phases", [])
                if phase.get("kill_chain_name") == "mitre-attack"
            }
        )
        attack_index[external_id] = {
            "name": obj.get("name", ""),
            "tactics": tactics,
            "stix_id": obj.get("id", ""),
        }

    return attack_index


def audit_campaign(path: Path, attack_index: dict[str, dict]) -> dict:
    data = json.loads(path.read_text())
    step_findings = []

    for index, step in enumerate(data.get("techniques", []), start=1):
        technique_id = step.get("technique_id", "")
        missing_fields = [field for field in REQUIRED_STEP_FIELDS if not step.get(field)]
        tactic = normalize_tactic(step.get("tactic", ""))
        tactic_is_slug = bool(tactic)
        mitre_entry = attack_index.get(technique_id)
        supported_by_mitre = mitre_entry is not None
        tactic_matches_mitre = supported_by_mitre and tactic in mitre_entry["tactics"]

        step_findings.append(
            {
                "order": index,
                "technique_id": technique_id,
                "missing_fields": missing_fields,
                "tactic": tactic,
                "tactic_is_slug": tactic_is_slug,
                "supported_by_mitre": supported_by_mitre,
                "mitre_name": mitre_entry["name"] if mitre_entry else "",
                "mitre_tactics": mitre_entry["tactics"] if mitre_entry else [],
                "tactic_matches_mitre": tactic_matches_mitre,
            }
        )

    missing_count = sum(1 for item in step_findings if item["missing_fields"])
    invalid_tactic_count = sum(1 for item in step_findings if not item["tactic_is_slug"])
    unsupported_count = sum(1 for item in step_findings if not item["supported_by_mitre"])
    mismatched_tactic_count = sum(
        1
        for item in step_findings
        if item["supported_by_mitre"] and not item["tactic_matches_mitre"]
    )

    return {
        "campaign_id": data.get("campaign_id", path.stem),
        "technique_count": len(step_findings),
        "steps_with_missing_metadata": missing_count,
        "steps_with_noncanonical_tactic": invalid_tactic_count,
        "steps_without_mitre_support": unsupported_count,
        "steps_with_tactic_mismatch": mismatched_tactic_count,
        "steps": step_findings,
    }


def build_report(bundle_path: Path) -> dict:
    attack_index = build_attack_index(bundle_path)
    campaigns = [
        audit_campaign(path, attack_index) for path in sorted(CAMPAIGNS_DIR.glob("*.json"))
    ]
    total_steps = sum(item["technique_count"] for item in campaigns)
    incomplete_steps = sum(item["steps_with_missing_metadata"] for item in campaigns)
    bad_tactics = sum(item["steps_with_noncanonical_tactic"] for item in campaigns)
    unsupported_steps = sum(item["steps_without_mitre_support"] for item in campaigns)
    mismatched_steps = sum(item["steps_with_tactic_mismatch"] for item in campaigns)

    return {
        "generated_at": datetime.now().isoformat(),
        "bundle_path": display_path(bundle_path),
        "campaign_count": len(campaigns),
        "total_steps": total_steps,
        "steps_with_missing_metadata": incomplete_steps,
        "steps_with_noncanonical_tactic": bad_tactics,
        "steps_without_mitre_support": unsupported_steps,
        "steps_with_tactic_mismatch": mismatched_steps,
        "campaigns": campaigns,
    }


def write_markdown(report: dict) -> None:
    lines = [
        "# MITRE Metadata Audit",
        "",
        f"- Generated at: `{report['generated_at']}`",
        f"- Bundle path: `{report['bundle_path']}`",
        f"- Campaigns audited: `{report['campaign_count']}`",
        f"- Total technique steps: `{report['total_steps']}`",
        f"- Steps with missing metadata: `{report['steps_with_missing_metadata']}`",
        f"- Steps with noncanonical tactic formatting: `{report['steps_with_noncanonical_tactic']}`",
        f"- Steps without MITRE technique support: `{report['steps_without_mitre_support']}`",
        f"- Steps with tactic mismatch against MITRE: `{report['steps_with_tactic_mismatch']}`",
        "",
        "This audit checks metadata presence plus technique/tactic consistency against the local ATT&CK Enterprise bundle.",
        "",
    ]

    for campaign in report["campaigns"]:
        lines.extend(
            [
                f"## {campaign['campaign_id']}",
                "",
                f"- Technique steps: `{campaign['technique_count']}`",
                f"- Missing metadata: `{campaign['steps_with_missing_metadata']}`",
                f"- Noncanonical tactic formatting: `{campaign['steps_with_noncanonical_tactic']}`",
                f"- Unsupported by MITRE bundle: `{campaign['steps_without_mitre_support']}`",
                f"- Tactic mismatches: `{campaign['steps_with_tactic_mismatch']}`",
                "",
            ]
        )
        for step in campaign["steps"]:
            if (
                not step["missing_fields"]
                and step["tactic_is_slug"]
                and step["supported_by_mitre"]
                and step["tactic_matches_mitre"]
            ):
                continue

            lines.append(
                f"- Step {step['order']} `{step['technique_id']}`: "
                f"missing=`{', '.join(step['missing_fields']) or 'none'}`, "
                f"tactic=`{step['tactic'] or 'missing'}`, "
                f"mitre_supported=`{step['supported_by_mitre']}`, "
                f"mitre_tactics=`{', '.join(step['mitre_tactics']) or 'none'}`"
            )
        lines.append("")

    OUTPUT_MD.write_text("\n".join(lines))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Audit published campaign metadata against ATT&CK Enterprise",
    )
    parser.add_argument(
        "--bundle",
        default=str(DEFAULT_BUNDLE),
        help="Path to enterprise-attack.json bundle",
    )
    args = parser.parse_args()

    bundle_path = Path(args.bundle)
    if not bundle_path.exists():
        raise FileNotFoundError(f"ATT&CK bundle not found: {bundle_path}")

    report = build_report(bundle_path)
    OUTPUT_JSON.write_text(json.dumps(report, indent=2))
    write_markdown(report)
    print(f"Wrote {OUTPUT_JSON}")
    print(f"Wrote {OUTPUT_MD}")


if __name__ == "__main__":
    main()
