#!/usr/bin/env python3
"""Compare what structured CTI and CTI plus NVD each resolve about a CVE's environment.

For every CVE the measurement associates with Enterprise CTI, the analysis asks which
environment dimensions are fixed by the STIX objects that carry the CVE, and which become
fixed once the pinned NVD record is joined. The dimensions are the ones a SUT builder must
commit: the vulnerable product, whether that product is unique, its version, the network
exposure and privilege the exploit assumes, and the topology around the host.

Reads the pinned Enterprise bundle and the pinned NVD snapshot only; it never calls NVD.
"""

from __future__ import annotations

import argparse
import csv
import json
import statistics
from collections.abc import Iterable
from pathlib import Path

from pydantic import BaseModel, ConfigDict

import sut_measurement_pipeline as pipeline

SCRIPTS_DIR = Path(__file__).resolve().parent
BUNDLE = SCRIPTS_DIR / 'data' / 'enterprise-attack.json'
SNAPSHOT_DIR = SCRIPTS_DIR / 'data' / 'nvd-snapshot'
CVE_TABLE = SCRIPTS_DIR / 'results' / 'audit' / 'all_cves.csv'
DEFAULT_OUTPUT = SCRIPTS_DIR / 'results' / 'nvd_enrichment.json'

PRODUCT_KEYS = ('x_cpe', 'cpe', 'x_mitre_cpe', 'x_opencti_cpe')
VERSION_FIELDS = ('versionStartIncluding', 'versionStartExcluding', 'versionEndIncluding', 'versionEndExcluding')
UNSPECIFIED = {'*', '-'}
EXPOSED_SERVICE_TECHNIQUES = {'T1190', 'T1133', 'T1210'}


class StrictModel(BaseModel):
    model_config = ConfigDict(extra='forbid', frozen=True)


class CveEnrichment(StrictModel):
    cve_id: str
    cti_source: str
    cti_objects: int
    cti_names_product: bool
    cti_implies_exposure: bool
    nvd_products: list[str]
    nvd_vulnerable_matches: int
    nvd_version_bounded: bool
    nvd_single_version: bool
    nvd_requires_platform: bool
    attack_vector: str | None
    privileges_required: str | None
    user_interaction: str | None


class DimensionCount(StrictModel):
    dimension: str
    structured_cti: int
    cti_plus_nvd: int


class EnrichmentReport(StrictModel):
    question: str
    cves: int
    dimensions: list[DimensionCount]
    unique_deployment_after_nvd: int
    median_vulnerable_matches: float
    note: str
    rows: list[CveEnrichment]


def objects_referencing(objects: Iterable[dict]) -> dict[str, list[dict]]:
    """Active STIX objects, relationships included, that carry each CVE.

    Uses the pipeline's own extraction so the carriers match the measured CVE population.
    """
    carriers: dict[str, list[dict]] = {}
    for item in objects:
        if item.get('revoked') or item.get('x_mitre_deprecated'):
            continue
        structured, freetext = pipeline.extract_cves_from_object(item)
        for cve_id in structured | freetext:
            carriers.setdefault(cve_id, []).append(item)
    return carriers


def names_product(carriers: list[dict]) -> bool:
    return any(key in item for item in carriers for key in PRODUCT_KEYS)


def exposed_service_users(objects: list[dict]) -> set[str]:
    """Objects that use, or are, a technique against an exposed network service."""
    exposed = {
        item['id']
        for item in objects
        if item.get('type') == 'attack-pattern'
        and any(reference.get('external_id') in EXPOSED_SERVICE_TECHNIQUES for reference in item.get('external_references', []))
    }
    users = {
        item['source_ref']
        for item in objects
        if item.get('type') == 'relationship' and item.get('relationship_type') == 'uses'
        and not item.get('revoked') and item.get('target_ref') in exposed
    }
    return exposed | users


def vulnerable_matches(record: dict) -> list[dict]:
    return [
        match
        for configuration in record.get('configurations', [])
        for node in configuration['nodes']
        for match in node['cpeMatch']
        if match.get('vulnerable')
    ]


def _cpe_fields(criteria: str) -> list[str]:
    return criteria.split(':')


def is_version_bounded(match: dict) -> bool:
    return any(field in match for field in VERSION_FIELDS) or _cpe_fields(match['criteria'])[5] not in UNSPECIFIED


def is_single_version(match: dict) -> bool:
    return not any(field in match for field in VERSION_FIELDS) and _cpe_fields(match['criteria'])[5] not in UNSPECIFIED


def requires_platform(record: dict) -> bool:
    """An AND node pairs the vulnerable product with a platform it must run on."""
    return any(
        node.get('operator') == 'AND' or configuration.get('operator') == 'AND'
        for configuration in record.get('configurations', [])
        for node in configuration['nodes']
    )


def cvss(record: dict) -> dict:
    metrics = record.get('metrics', {})
    for key in ('cvssMetricV31', 'cvssMetricV30'):
        if metrics.get(key):
            return metrics[key][0]['cvssData']
    return {}


def enrich(cve_id: str, cti_source: str, carriers: list[dict], record: dict, exposed: set[str]) -> CveEnrichment:
    matches = vulnerable_matches(record)
    vector = cvss(record)
    return CveEnrichment(
        cve_id=cve_id,
        cti_source=cti_source,
        cti_objects=len(carriers),
        cti_names_product=names_product(carriers),
        cti_implies_exposure=any(
            exposed & {item['id'], item.get('source_ref'), item.get('target_ref')} for item in carriers
        ),
        nvd_products=sorted({':'.join(_cpe_fields(match['criteria'])[3:5]) for match in matches}),
        nvd_vulnerable_matches=len(matches),
        nvd_version_bounded=bool(matches) and all(is_version_bounded(match) for match in matches),
        nvd_single_version=len(matches) == 1 and is_single_version(matches[0]),
        nvd_requires_platform=requires_platform(record),
        attack_vector=vector.get('attackVector'),
        privileges_required=vector.get('privilegesRequired'),
        user_interaction=vector.get('userInteraction'),
    )


def dimension_counts(rows: list[CveEnrichment]) -> list[DimensionCount]:
    def count(predicate) -> int:
        return sum(1 for row in rows if predicate(row))

    return [
        DimensionCount(dimension='vulnerable product named', structured_cti=count(lambda row: row.cti_names_product),
                       cti_plus_nvd=count(lambda row: row.cti_names_product or bool(row.nvd_products))),
        DimensionCount(dimension='single vulnerable product', structured_cti=count(lambda row: row.cti_names_product),
                       cti_plus_nvd=count(lambda row: len(row.nvd_products) == 1)),
        DimensionCount(dimension='version bounded', structured_cti=count(lambda row: row.cti_names_product),
                       cti_plus_nvd=count(lambda row: row.nvd_version_bounded)),
        DimensionCount(dimension='network exposure', structured_cti=count(lambda row: row.cti_implies_exposure),
                       cti_plus_nvd=count(lambda row: row.cti_implies_exposure or row.attack_vector is not None)),
        DimensionCount(dimension='privilege the exploit assumes', structured_cti=0,
                       cti_plus_nvd=count(lambda row: row.privileges_required is not None)),
        DimensionCount(dimension='topology and trust boundaries', structured_cti=0, cti_plus_nvd=0),
    ]


def build_report(bundle: dict, sources: dict[str, str], records: dict[str, dict]) -> EnrichmentReport:
    if not sources:
        raise ValueError('no CVEs to enrich')
    carriers = objects_referencing(bundle['objects'])
    exposed = exposed_service_users(bundle['objects'])
    rows = [enrich(cve_id, sources[cve_id], carriers.get(cve_id, []), records[cve_id], exposed) for cve_id in sorted(sources)]
    return EnrichmentReport(
        question=(
            'Which environment dimensions of a CVE does structured CTI fix, and which does '
            'joining the NVD record add?'
        ),
        cves=len(rows),
        dimensions=dimension_counts(rows),
        unique_deployment_after_nvd=sum(row.nvd_single_version and not row.nvd_requires_platform for row in rows),
        median_vulnerable_matches=float(statistics.median(row.nvd_vulnerable_matches for row in rows)),
        note=(
            'NVD describes the vulnerable configuration, not the deployment: a version range '
            'or several matching products still leave a choice, and no source describes '
            'topology or trust boundaries. Topology is counted as unresolved by construction '
            'because neither source has a field for it. STIX has no field for the privilege '
            'an exploit assumes, so its structured count is zero by schema. Product, '
            'uniqueness, and version can be fixed by CTI only where it names a product.'
        ),
        rows=rows,
    )


def load_sources(table: Path = CVE_TABLE) -> dict[str, str]:
    with table.open(encoding='utf-8') as handle:
        return {row['cve_id']: row['source'] for row in csv.DictReader(handle)}


def load_records(cve_ids: Iterable[str], snapshot: Path = SNAPSHOT_DIR) -> dict[str, dict]:
    return {
        cve_id: json.loads((snapshot / f'{cve_id}.json').read_text(encoding='utf-8'))['vulnerabilities'][0]['cve']
        for cve_id in cve_ids
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    sources = load_sources()
    report = build_report(json.loads(BUNDLE.read_text(encoding='utf-8')), sources, load_records(sources))
    args.output.write_text(report.model_dump_json(indent=2) + '\n', encoding='utf-8')
    for dimension in report.dimensions:
        print(f'[nvd-enrichment] {dimension.dimension}: CTI {dimension.structured_cti}/{report.cves}, '
              f'CTI+NVD {dimension.cti_plus_nvd}/{report.cves}')
    print(f'[nvd-enrichment] unique deployment after NVD: {report.unique_deployment_after_nvd}/{report.cves}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
