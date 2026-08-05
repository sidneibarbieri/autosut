#!/usr/bin/env python3
"""Execute only verifier-admitted procedures and retain hashed evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
for import_root in (PROJECT_ROOT, SRC_ROOT):
    if str(import_root) not in sys.path:
        sys.path.insert(0, str(import_root))

from executors.executor_registry import execute_technique, registry  # noqa: E402
from executors.campaign_bootstrap import bootstrap_campaign_executors  # noqa: E402
from executors.registry_initializer import initialize_registry  # noqa: E402
from planning.concretized_plan import load_concretized_plan  # noqa: E402
from runners.campaign_runner import BASE_CAPABILITIES  # noqa: E402


def _artifact_record(path_text: str) -> dict:
    path = Path(path_text)
    if not path.is_absolute():
        path = PROJECT_ROOT / path
    if not path.exists():
        return {"path": path_text, "present": False}
    if path.is_dir():
        directory_payload = [
            (
                str(item.relative_to(path)),
                hashlib.sha256(item.read_bytes()).hexdigest(),
            )
            for item in sorted(path.rglob("*"))
            if item.is_file()
        ]
        digest = hashlib.sha256(
            json.dumps(directory_payload, separators=(",", ":")).encode()
        ).hexdigest()
        artifact_kind = "directory"
    else:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        artifact_kind = "file"
    try:
        relative = str(path.resolve().relative_to(PROJECT_ROOT))
    except ValueError:
        relative = path.name
    if path.resolve().is_relative_to((PROJECT_ROOT / "data" / "artifacts").resolve()):
        if path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink()
        cleaned = True
    else:
        cleaned = False
    return {
        "path": relative,
        "present": True,
        "kind": artifact_kind,
        "sha256": digest,
        "cleaned": cleaned,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--campaign-id", required=True)
    parser.add_argument("--sut-profile-id", required=True)
    parser.add_argument(
        "--allowed-domain",
        action="append",
        dest="allowed_domains",
        default=[],
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    allowed_domains = set(args.allowed_domains or ["attacker"])
    plan = load_concretized_plan(args.plan, require_complete=False)
    initialize_registry()
    bootstrap_campaign_executors(args.campaign_id)
    capabilities = set(BASE_CAPABILITIES)
    capabilities.update(plan.planning_certificate.initial_facts)
    rows = []
    evidence_dir = args.output.parent / f"{args.output.stem}.evidence"
    for step in plan.steps:
        template_domain = (
            "attacker"
            if step.template_id == "stage-benign-toolkit"
            else "target_or_boundary"
        )
        if template_domain not in allowed_domains:
            continue
        metadata = registry.get_metadata(step.technique_id)
        if metadata is None:
            raise RuntimeError(f"no executor for admitted step {step.technique_id}")
        if not metadata.safe_simulation:
            raise RuntimeError(
                f"executor is not declared safe: {step.technique_id}"
            )
        evidence = execute_technique(
            technique_id=step.technique_id,
            available_capabilities=sorted(capabilities),
            campaign_id=args.campaign_id,
            sut_profile_id=args.sut_profile_id,
            evidence_dir=evidence_dir,
        )
        artifacts = [
            _artifact_record(path_text)
            for path_text in evidence.artifacts_created
        ]
        if evidence.status == "success":
            capabilities.update(evidence.capabilities_produced)
            capabilities.update(step.produces)
        rows.append(
            {
                "technique_id": step.technique_id,
                "template_id": step.template_id,
                "status": evidence.status,
                "execution_mode": evidence.execution_mode,
                "execution_fidelity": evidence.execution_fidelity,
                "evidence_predicates": step.evidence_predicates,
                "artifact_records": artifacts,
            }
        )
    report = {
        "schema_version": "1",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "campaign_id": plan.campaign_id,
        "source_plan_sha256": plan.content_sha256,
        "allowed_domains": sorted(allowed_domains),
        "admitted_step_count": len(plan.steps),
        "attempted_step_count": len(rows),
        "successful_with_evidence": sum(
            row["status"] == "success"
            and bool(row["evidence_predicates"])
            and all(
                record.get("present", False)
                for record in row["artifact_records"]
            )
            for row in rows
        ),
        "rows": rows,
    }
    hash_payload = json.dumps(
        report, sort_keys=True, separators=(",", ":")
    ).encode()
    report["content_sha256"] = hashlib.sha256(hash_payload).hexdigest()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"[admitted-arm] attempted: {report['attempted_step_count']}")
    print(
        "[admitted-arm] successful with evidence: "
        f"{report['successful_with_evidence']}"
    )
    print(f"[admitted-arm] output: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
