#!/usr/bin/env python3
"""Inspect existing replay records; no infrastructure or API calls are made."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from evaluation.replay_audit import audit_replay_report  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--artifact-root", type=Path, default=PROJECT_ROOT)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    audit = audit_replay_report(args.report, args.artifact_root)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(audit.model_dump_json(indent=2) + "\n", encoding="utf-8")
    issue_count = sum(bool(record.issues) for record in audit.records)
    print(f"Audited {len(audit.records)} rows; {issue_count} contain limitations or inconsistencies.")
    print(f"Audit: {args.output}")
    return 2 if issue_count else 0


if __name__ == "__main__":
    raise SystemExit(main())
