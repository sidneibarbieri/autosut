#!/usr/bin/env python3
"""Measure the environment-evidence surface across ATT&CK Enterprise releases.

Every release goes through the same functions the main pipeline uses, so a change
between rows reflects the corpus, not the method. The metric set is fixed here.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from pydantic import BaseModel, ConfigDict

import sut_measurement_pipeline as pipeline

SCRIPTS_DIR = Path(__file__).resolve().parent
DEFAULT_OUTPUT = SCRIPTS_DIR / 'results' / 'longitudinal_gap.json'


class ReleaseMeasurement(BaseModel):
    model_config = ConfigDict(frozen=True)

    release: str
    bundle_sha256: str
    active_techniques: int
    technique_platform_pct: float
    usable_campaigns: int
    campaigns_with_platform_signal_pct: float
    software_objects: int
    software_with_version_pct: float
    software_with_cpe_pct: float
    unique_cves: int
    campaigns_with_structured_cve_pct: float
    campaigns_with_any_cve_pct: float
    cf_pct: float
    vmr_pct: float
    id_pct: float
    fallback_pct: float


def bundle_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def measure_release(release: str, bundle_path: Path) -> ReleaseMeasurement:
    by_type, by_id = pipeline.index_objects_by_type(pipeline.load_bundle(bundle_path))
    rel_fwd, rel_rev, _ = pipeline.build_relationship_index(by_type.get('relationship', []))
    techniques = by_type.get('attack-pattern', [])
    campaigns = by_type.get('campaign', [])
    intrusion_sets = by_type.get('intrusion-set', [])
    software = by_type.get('malware', []) + by_type.get('tool', [])
    excluded = {
        campaign['id']
        for campaign in campaigns
        if not any(kind == 'uses' for kind, _, _ in rel_fwd.get(campaign['id'], []))
    }
    platform = pipeline.analyze_platform_coverage(techniques)
    software_refs = pipeline.analyze_software_references(
        campaigns, intrusion_sets, software, rel_fwd, rel_rev, by_id, excluded
    )
    cves = pipeline.analyze_vulnerability_references(
        campaigns, intrusion_sets, software, techniques, by_type.get('vulnerability', []),
        rel_fwd, rel_rev, by_id, excluded,
    )
    routing = pipeline.analyze_compatibility(techniques, rel_fwd, by_id)
    return ReleaseMeasurement(
        release=release,
        bundle_sha256=bundle_digest(bundle_path),
        active_techniques=platform['total_techniques'],
        technique_platform_pct=platform['platform_pct'],
        usable_campaigns=software_refs['total_usable_campaigns'],
        campaigns_with_platform_signal_pct=software_refs['campaigns_with_platform_signal_pct'],
        software_objects=software_refs['total_software'],
        software_with_version_pct=software_refs['software_with_version_pct'],
        software_with_cpe_pct=software_refs['software_with_cpe_pct'],
        unique_cves=cves['cve_unique_count'],
        campaigns_with_structured_cve_pct=cves['campaigns_with_cve_structured_pct'],
        campaigns_with_any_cve_pct=cves['campaigns_with_cve_pct'],
        cf_pct=routing['cf_pct'],
        vmr_pct=routing['vmr_pct'],
        id_pct=routing['id_pct'],
        fallback_pct=routing['fallback_pct'],
    )


def parse_release(argument: str) -> tuple[str, Path]:
    release, separator, path = argument.partition('=')
    if not separator or not release or not path:
        raise argparse.ArgumentTypeError('expected RELEASE=PATH, for example 18.1=data/v18.1.json')
    return release, Path(path)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release', type=parse_release, action='append', required=True,
                        help='RELEASE=PATH to an Enterprise STIX bundle; repeat in chronological order.')
    parser.add_argument('--output', type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    rows = [measure_release(release, path) for release, path in args.release]
    args.output.write_text(
        json.dumps({'releases': [row.model_dump() for row in rows]}, indent=2) + '\n', encoding='utf-8'
    )
    fields = [name for name in ReleaseMeasurement.model_fields if name not in {'bundle_sha256'}]
    for name in fields:
        print(f"{name:36} " + "  ".join(f"{getattr(row, name)!s:>8}" for row in rows))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
