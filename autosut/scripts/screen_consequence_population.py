"""Inventory frozen campaign inputs before selecting consequence-study pairs.

The finite join is deterministic and linear in the two input record counts.
It does not decide whether a campaign is eligible for the prospective study.
"""

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field


ARTIFACT_ROOT = Path(__file__).resolve().parents[1]
CORPUS_MANIFEST = ARTIFACT_ROOT / "release/corpus-suts-20261001-enterprise-r3/manifest.json"
PAIR_MATRIX = ARTIFACT_ROOT / "release/prepared-pairs/matrix.json"
REPORT = ARTIFACT_ROOT / "release/experiments/consequence_study/screening_report.json"
SHA256_PATTERN = r"^[0-9a-f]{64}$"


class CampaignRecord(BaseModel):
    campaign_id: str = Field(pattern=r"^C[0-9]{4}$")
    source_plan_sha256: str = Field(pattern=SHA256_PATTERN)
    status: Literal["blueprint_generated", "partial_plan_only"]
    materialized: bool
    executed: bool


class CorpusManifest(BaseModel):
    schema_version: Literal["autosut-corpus-suts/v1"]
    campaigns: int = Field(ge=0)
    blueprints_generated: int = Field(ge=0)
    partial_plans_generated: int = Field(ge=0)
    records: list[CampaignRecord]


class PreparedPair(BaseModel):
    campaign_id: str
    source_campaign_id: str = Field(pattern=r"^C[0-9]{4}$")
    status: Literal["prepared", "blocked"]
    reasons: list[str]
    contract_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    files: dict[str, str] = Field(default_factory=dict)
    execution_status: str


class PairMatrix(BaseModel):
    schema_version: Literal["autosut-pair-preparation/v1"]
    prepared: int = Field(ge=0)
    blocked: int = Field(ge=0)
    executed: int = Field(ge=0)
    pairs: list[PreparedPair]


def _unique_by_id(records: list, attribute: str, label: str) -> dict:
    indexed = {getattr(record, attribute): record for record in records}
    if len(indexed) != len(records):
        raise ValueError(f"duplicate {label}")
    return indexed


def _validate_counts(corpus: CorpusManifest, matrix: PairMatrix) -> None:
    status_counts = Counter(record.status for record in corpus.records)
    pair_counts = Counter(pair.status for pair in matrix.pairs)
    if corpus.campaigns != len(corpus.records):
        raise ValueError("campaign count differs from records")
    if corpus.blueprints_generated != status_counts["blueprint_generated"]:
        raise ValueError("blueprint count differs from records")
    if corpus.partial_plans_generated != status_counts["partial_plan_only"]:
        raise ValueError("partial-plan count differs from records")
    if matrix.prepared != pair_counts["prepared"] or matrix.blocked != pair_counts["blocked"]:
        raise ValueError("pair status counts differ from records")
    if matrix.executed != sum(pair.execution_status != "not_run" for pair in matrix.pairs):
        raise ValueError("pair execution count differs from records")


def _screening_status(campaign: CampaignRecord, pair: PreparedPair | None) -> str:
    if pair is not None and pair.status == "prepared":
        return "contract_available_unassessed"
    if campaign.status == "blueprint_generated":
        return "blueprint_only"
    return "partial_plan"


def build_report(
    corpus_data: dict, matrix_data: dict, corpus_sha256: str, matrix_sha256: str
) -> dict:
    """Join the frozen records without interpreting readiness as an outcome."""
    corpus = CorpusManifest.model_validate(corpus_data)
    matrix = PairMatrix.model_validate(matrix_data)
    _validate_counts(corpus, matrix)
    campaigns = _unique_by_id(corpus.records, "campaign_id", "source campaign ID")
    pairs = _unique_by_id(matrix.pairs, "source_campaign_id", "pair source campaign ID")
    for source_id, pair in pairs.items():
        if source_id not in campaigns:
            raise ValueError(f"pair references unknown source campaign {source_id}")
        if pair.status == "prepared" and (pair.contract_sha256 is None or pair.reasons):
            raise ValueError(f"prepared pair has no clean contract: {source_id}")
        constraints_sha256 = pair.files.get("sut-constraints.json")
        if constraints_sha256 is not None and (
            len(constraints_sha256) != 64
            or any(digit not in "0123456789abcdef" for digit in constraints_sha256)
        ):
            raise ValueError(f"invalid CTI-constraint digest: {source_id}")
    records = []
    for source_id, campaign in sorted(campaigns.items()):
        pair = pairs.get(source_id)
        records.append({
            "campaign_id": source_id,
            "source_plan_sha256": campaign.source_plan_sha256,
            "cti_constraints_sha256": (
                pair.files.get("sut-constraints.json") if pair else None
            ),
            "plan_status": campaign.status,
            "materialized": campaign.materialized,
            "executed_in_corpus": campaign.executed,
            "pair_id": pair.campaign_id if pair else None,
            "pair_status": pair.status if pair else None,
            "pair_reasons": pair.reasons if pair else [],
            "contract_sha256": pair.contract_sha256 if pair else None,
            "pair_execution_status": pair.execution_status if pair else None,
            "screening_status": _screening_status(campaign, pair),
            "prospective_eligible": None,
            "prospective_exclusion_reason": None,
            "pilot_excluded": source_id == "C0045",
        })
    return {
        "schema_version": "autosut-consequence-screening/v1",
        "source": {"corpus_manifest_sha256": corpus_sha256, "pair_matrix_sha256": matrix_sha256},
        "scope": "Inventory only; CTI-consistent two-arm eligibility has not been assessed.",
        "counts": {
            "campaigns": corpus.campaigns,
            "blueprints_generated": corpus.blueprints_generated,
            "partial_plans_generated": corpus.partial_plans_generated,
            "contract_available_campaigns": matrix.prepared,
            "executed_campaigns": sum(campaign.executed for campaign in corpus.records),
        },
        "records": records,
    }


def _render(report: dict) -> str:
    return json.dumps(report, indent=2, sort_keys=True) + "\n"


def write_report(destination: Path, report: dict) -> None:
    destination.write_text(_render(report), encoding="utf-8")


def check_report(destination: Path, report: dict) -> None:
    if destination.read_text(encoding="utf-8") != _render(report):
        raise ValueError(f"screening report differs from frozen inputs: {destination}")


def _read_with_digest(path: Path) -> tuple[dict, str]:
    contents = path.read_bytes()
    return json.loads(contents), hashlib.sha256(contents).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="write the fixed screening report")
    arguments = parser.parse_args()
    corpus_data, corpus_sha256 = _read_with_digest(CORPUS_MANIFEST)
    matrix_data, matrix_sha256 = _read_with_digest(PAIR_MATRIX)
    report = build_report(corpus_data, matrix_data, corpus_sha256, matrix_sha256)
    if arguments.write:
        write_report(REPORT, report)
    else:
        check_report(REPORT, report)
    print(json.dumps(report["counts"], sort_keys=True))


if __name__ == "__main__":
    main()
