#!/usr/bin/env python3
"""Prepare campaign/SUT pairs and account for every CTI corpus plan."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from pydantic import BaseModel, ConfigDict

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from infrastructure.revision import current_revision  # noqa: E402
from planning.campaign_pair import PairPreparation, prepare_campaign_pair  # noqa: E402
from planning.procedural_plan import load_procedural_plan  # noqa: E402


class TrustedCatalogCoverage(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    source_campaign_id: str
    source_steps: int
    covered_steps: int
    uncovered_technique_ids: tuple[str, ...]


def trusted_catalog_coverage(
    corpus_plans: dict[str, Path], catalog_path: Path
) -> tuple[str, list[TrustedCatalogCoverage]]:
    """Count exact technique matches in the trusted STICKS template catalog."""
    catalog_bytes = catalog_path.read_bytes()
    catalog = json.loads(catalog_bytes)
    supported_ids = {
        technique_id
        for template in catalog["templates"]
        for technique_id in template["technique_ids"]
    }
    coverage = []
    for source_id, plan_path in sorted(corpus_plans.items()):
        plan = load_procedural_plan(plan_path)
        technique_ids = [step.technique_id for step in plan.steps]
        coverage.append(
            TrustedCatalogCoverage(
                source_campaign_id=source_id,
                source_steps=len(technique_ids),
                covered_steps=sum(technique_id in supported_ids for technique_id in technique_ids),
                uncovered_technique_ids=tuple(sorted(set(technique_ids) - supported_ids)),
            )
        )
    return hashlib.sha256(catalog_bytes).hexdigest(), coverage


def resolve_python_executable(value: str, invocation_root: Path) -> str:
    """Make an explicit interpreter path absolute without following venv symlinks."""
    candidate = Path(value).expanduser()
    if candidate.is_absolute():
        return str(candidate)
    if len(candidate.parts) > 1 or candidate.exists():
        return str((invocation_root / candidate).absolute())
    return value


def discover_corpus_plans(plan_root: Path) -> dict[str, Path]:
    """Index a plan corpus, preferring curated top-level plan copies."""
    sources = sorted((plan_root / "enterprise").glob("*.procedural-plan.json"))
    sources.extend(sorted(plan_root.glob("*.procedural-plan.json")))
    plans: dict[str, Path] = {}
    suffix = ".procedural-plan.json"
    for source in sources:
        plans[source.name.removesuffix(suffix)] = source
    if not plans:
        raise ValueError("STICKS corpus contains no procedural plans")
    return plans


def discover_campaign_specs(specs_root: Path, legacy_ids: set[str]) -> dict[str, Path]:
    """Accept external campaign specifications with stable file identities."""
    if not specs_root.is_dir():
        raise ValueError(f"campaign specification directory does not exist: {specs_root}")
    specs: dict[str, Path] = {}
    for path in sorted(specs_root.glob("*.json")):
        spec = json.loads(path.read_text(encoding="utf-8"))
        if spec.get("campaign_id") != path.stem:
            raise ValueError(f"campaign ID differs from specification filename: {path.name}")
        if spec.get("source_campaign_id") or path.stem in legacy_ids:
            specs[path.stem] = path
    return specs


def derive_missing_specification(plan_path: Path, specs_root: Path) -> Path:
    """Derive source identity without inventing an execution contract."""
    plan = load_procedural_plan(plan_path)
    source_digest = hashlib.sha256(plan_path.read_bytes()).hexdigest()
    spec = {
        "campaign_id": plan.campaign_id,
        "source_campaign_id": plan.campaign_id,
        "derivation": {
            "schema_version": "autosut-source-specification/v1",
            "source_file_sha256": source_digest,
            "source_plan_sha256": plan.content_sha256,
            "execution_contract_inferred": False,
        },
    }
    specs_root.mkdir(parents=True, exist_ok=True)
    path = specs_root / f"{source_digest}.json"
    path.write_text(json.dumps(spec, indent=2) + "\n", encoding="utf-8")
    return path


def load_legacy_inventory(path: Path | None) -> tuple[dict[str, str], str | None]:
    """Load historical aliases only when the caller includes that inventory."""
    if path is None:
        return {}, None
    payload = json.loads(path.read_text(encoding="utf-8"))
    mappings = {row["campaign_id"]: row["source_campaign_id"] for row in payload["campaigns"]}
    return mappings, hashlib.sha256(path.read_bytes()).hexdigest()


def audit_corpus_coverage(results: list[PairPreparation], corpus_plans: dict[str, Path]) -> None:
    """Reject a matrix that omits a plan or loses its source identity."""
    by_source: dict[str, list[PairPreparation]] = {}
    for result in results:
        if result.source_campaign_id:
            by_source.setdefault(result.source_campaign_id, []).append(result)
    for source_id, plan_path in corpus_plans.items():
        plan = load_procedural_plan(plan_path)
        if plan.campaign_id != source_id:
            raise ValueError(f"plan filename and campaign ID disagree: {plan_path.name}")
        matching = by_source.get(source_id, [])
        if not matching:
            raise ValueError(f"pair matrix omits corpus plan {source_id}")
        if any(
            result.source_plan_sha256 != plan.content_sha256
            or result.source_steps != len(plan.steps)
            for result in matching
        ):
            raise ValueError(f"pair matrix lost source provenance for {source_id}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sticks-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--campaign-specs", type=Path, default=PROJECT_ROOT / "campaigns")
    parser.add_argument(
        "--derive-missing-specs", action="store_true",
        help="derive missing source identities from CTI plans and audit environment requirements",
    )
    parser.add_argument(
        "--plans-root", type=Path, help="STICKS plan directory; defaults to its release corpus"
    )
    inventory_options = parser.add_mutually_exclusive_group()
    inventory_options.add_argument(
        "--legacy-inventory",
        type=Path,
        default=PROJECT_ROOT / "release/plans/legacy-campaign-inventory.json",
    )
    inventory_options.add_argument(
        "--no-legacy-inventory",
        action="store_true",
        help="prepare an external plan corpus without the frozen historical aliases",
    )
    args = parser.parse_args()
    python_executable = resolve_python_executable(args.python, Path.cwd())
    sticks_root = args.sticks_root.resolve()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    inventory_path = None if args.no_legacy_inventory else args.legacy_inventory.resolve()
    source_by_campaign, inventory_sha256 = load_legacy_inventory(inventory_path)
    plan_root = args.plans_root.resolve() if args.plans_root else sticks_root / "release/plans"
    corpus_plans = discover_corpus_plans(plan_root)
    legacy_ids = set(source_by_campaign)
    specs = discover_campaign_specs(args.campaign_specs.resolve(), legacy_ids)
    specified_sources = {
        json.loads(path.read_text(encoding="utf-8")).get("source_campaign_id")
        or source_by_campaign.get(campaign_id)
        for campaign_id, path in specs.items()
    }
    missing_spec_sources = set(corpus_plans) - specified_sources - set(source_by_campaign.values())
    results = []
    for campaign_id in sorted(set(specs) | legacy_ids | missing_spec_sources):
        if args.derive_missing_specs and campaign_id in missing_spec_sources:
            specs[campaign_id] = derive_missing_specification(
                corpus_plans[campaign_id], output / "derived-specifications"
            )
        if campaign_id not in specs:
            source_id = (
                campaign_id if campaign_id in corpus_plans else source_by_campaign[campaign_id]
            )
            plan_path = corpus_plans.get(source_id)
            plan = load_procedural_plan(plan_path) if plan_path else None
            result = PairPreparation(
                campaign_id=campaign_id,
                source_campaign_id=source_id,
                source_plan_sha256=plan.content_sha256 if plan else None,
                source_steps=len(plan.steps) if plan else 0,
                reasons=("missing_campaign_spec",),
            )
        else:
            campaign_path = specs[campaign_id]
            spec = json.loads(campaign_path.read_text(encoding="utf-8"))
            source_id = spec.get("source_campaign_id") or source_by_campaign.get(campaign_id)
            plan_path = corpus_plans.get(source_id)
            if plan_path is None:
                result = PairPreparation(
                    campaign_id=campaign_id,
                    source_campaign_id=source_id,
                    reasons=("missing_cti_plan_mapping",),
                )
            else:
                result = prepare_campaign_pair(
                    campaign_path=campaign_path,
                    plan_path=plan_path,
                    sticks_root=sticks_root,
                    output_dir=output / campaign_id,
                    python_executable=python_executable,
                    source_campaign_id=source_id,
                )
        results.append(result)
        print(f"{campaign_id}: {result.status}; {', '.join(result.reasons) or 'execution not run'}")
    audit_corpus_coverage(results, corpus_plans)
    catalog_sha256, catalog_coverage = trusted_catalog_coverage(
        corpus_plans, sticks_root / "data/concretization/action_templates.json"
    )
    payload = {
        "schema_version": "autosut-pair-preparation/v1",
        "implementation_revision": current_revision(PROJECT_ROOT),
        "legacy_inventory_sha256": inventory_sha256,
        "legacy_campaign_ids": sorted(legacy_ids),
        "corpus_campaign_ids": sorted(corpus_plans),
        "scope": "Every input CTI corpus plan, plus campaign specifications and legacy inventory entries.",
        "prepared": sum(result.status == "prepared" for result in results),
        "blocked": sum(result.status == "blocked" for result in results),
        "executed": 0,
        "trusted_catalog_coverage": {
            "matching_policy": "exact_technique_id",
            "catalog_sha256": catalog_sha256,
            "covered_steps": sum(row.covered_steps for row in catalog_coverage),
            "source_steps": sum(row.source_steps for row in catalog_coverage),
            "by_source": [row.model_dump(mode="json") for row in catalog_coverage],
        },
        "pairs": [result.model_dump(mode="json") for result in results],
    }
    (output / "matrix.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
