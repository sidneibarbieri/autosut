#!/usr/bin/env python3
"""
Audit latest campaign evidence for signs that execution occurred on the host
instead of the intended SUT substrate.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
CAMPAIGNS_DIR = PROJECT_ROOT / "campaigns"
EVIDENCE_DIR = PROJECT_ROOT / "release" / "evidence"
OUTPUT_JSON = PROJECT_ROOT / "results" / "host_leakage_audit.json"
OUTPUT_MD = PROJECT_ROOT / "results" / "HOST_LEAKAGE_AUDIT.md"

HOST_LEAK_PATTERNS = {
    "darwin_kernel": "Darwin Kernel Version",
    "darwin_uname": "Darwin ",
    "macos_windowserver": "/WindowServer",
    "apple_group": "com.apple.access_ssh",
    "xnu_kernel": "xnu-",
    "user_uid_501": "uid=501(",
}


def display_path(path: Path) -> str:
    try:
        return str(path.relative_to(PROJECT_ROOT))
    except ValueError:
        return str(path)


def latest_summary_path(campaign_id: str) -> Path | None:
    candidates = sorted(EVIDENCE_DIR.glob(f"{campaign_id}_*/summary.json"))
    if not candidates:
        return None
    return max(candidates, key=lambda path: path.parent.name)


def detect_patterns(text: str) -> list[str]:
    matches = []
    for label, pattern in HOST_LEAK_PATTERNS.items():
        if pattern in text:
            matches.append(label)
    return matches


def audit_campaign(campaign_id: str) -> dict:
    summary_path = latest_summary_path(campaign_id)
    if summary_path is None:
        return {
            "campaign_id": campaign_id,
            "has_evidence": False,
            "latest_summary": None,
            "leaked_steps": [],
            "host_leakage_detected": False,
        }

    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    leaked_steps = []
    for step in summary.get("technique_results", []):
        combined = "\n".join([step.get("stdout", ""), step.get("stderr", "")])
        pattern_hits = detect_patterns(combined)
        if pattern_hits:
            leaked_steps.append(
                {
                    "technique_id": step.get("technique_id", ""),
                    "status": step.get("status", ""),
                    "patterns": pattern_hits,
                }
            )

    return {
        "campaign_id": campaign_id,
        "has_evidence": True,
        "latest_summary": display_path(summary_path),
        "leaked_steps": leaked_steps,
        "host_leakage_detected": bool(leaked_steps),
    }


def build_report() -> dict:
    campaigns = sorted(path.stem for path in CAMPAIGNS_DIR.glob("*.json"))
    rows = [audit_campaign(campaign_id) for campaign_id in campaigns]
    with_evidence = [row for row in rows if row["has_evidence"]]
    leaked = [row for row in with_evidence if row["host_leakage_detected"]]
    leaked_steps = sum(len(row["leaked_steps"]) for row in leaked)
    return {
        "generated_at": datetime.now().isoformat(),
        "campaigns_audited": len(rows),
        "campaigns_with_evidence": len(with_evidence),
        "campaigns_with_host_leakage": len(leaked),
        "leaked_steps_in_latest_evidence": leaked_steps,
        "campaigns": rows,
    }


def write_markdown(report: dict) -> None:
    lines = [
        "# Host Leakage Audit",
        "",
        f"- Generated at: `{report['generated_at']}`",
        f"- Campaigns audited: `{report['campaigns_audited']}`",
        f"- Campaigns with evidence: `{report['campaigns_with_evidence']}`",
        f"- Campaigns with host leakage in latest evidence: `{report['campaigns_with_host_leakage']}`",
        f"- Leaked steps in latest evidence: `{report['leaked_steps_in_latest_evidence']}`",
        "",
        "Host leakage means evidence contains strong signs of execution on the macOS host",
        "rather than on the intended experimental substrate.",
        "",
        "## Campaign Status",
        "",
        "| Campaign | Evidence | Host Leakage | Leaked Steps |",
        "|---|---:|---:|---:|",
    ]

    for row in report["campaigns"]:
        lines.append(
            f"| {row['campaign_id']} | "
            f"{'yes' if row['has_evidence'] else 'no'} | "
            f"{'yes' if row['host_leakage_detected'] else 'no'} | "
            f"{len(row['leaked_steps'])} |"
        )

    lines.extend(["", "## Detailed Findings", ""])
    for row in report["campaigns"]:
        if not row["host_leakage_detected"]:
            continue
        lines.append(f"### {row['campaign_id']}")
        lines.append("")
        lines.append(f"- Latest summary: `{row['latest_summary']}`")
        for step in row["leaked_steps"]:
            lines.append(
                f"- `{step['technique_id']}` ({step['status']}): "
                f"{', '.join(step['patterns'])}"
            )
        lines.append("")

    OUTPUT_MD.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    report = build_report()
    OUTPUT_JSON.write_text(json.dumps(report, indent=2), encoding="utf-8")
    write_markdown(report)
    print(f"Wrote {OUTPUT_JSON}")
    print(f"Wrote {OUTPUT_MD}")


if __name__ == "__main__":
    main()
