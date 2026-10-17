#!/usr/bin/env python3
"""Fetch the NVD record of every CVE the measurement associates with Enterprise CTI.

The enrichment analysis reads only the pinned snapshot this script writes, so it stays
offline and reproducible. Re-running the fetch creates a new snapshot: NVD records change,
and the manifest records when each one was retrieved and its SHA-256.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
CVE_TABLE = SCRIPTS_DIR / 'results' / 'audit' / 'all_cves.csv'
SNAPSHOT_DIR = SCRIPTS_DIR / 'data' / 'nvd-snapshot'
MANIFEST = SCRIPTS_DIR / 'data' / 'nvd_snapshot_manifest.json'
NVD_API = 'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}'
SECONDS_BETWEEN_REQUESTS = 6.5


def measured_cve_ids(table: Path = CVE_TABLE) -> list[str]:
    with table.open(encoding='utf-8') as handle:
        return sorted({row['cve_id'] for row in csv.DictReader(handle)})


def fetch_record(cve_id: str) -> bytes:
    request = urllib.request.Request(NVD_API.format(cve_id=cve_id), headers={'User-Agent': 'autosut-measurement'})
    with urllib.request.urlopen(request, timeout=60) as response:
        payload = response.read()
    if json.loads(payload).get('totalResults') != 1:
        raise ValueError(f'NVD returned no unique record for {cve_id}')
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--delay', type=float, default=SECONDS_BETWEEN_REQUESTS)
    args = parser.parse_args()

    SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)
    entries = []
    for index, cve_id in enumerate(measured_cve_ids()):
        if index:
            time.sleep(args.delay)
        payload = fetch_record(cve_id)
        (SNAPSHOT_DIR / f'{cve_id}.json').write_bytes(payload)
        entries.append({
            'cve_id': cve_id,
            'sha256': hashlib.sha256(payload).hexdigest(),
            'retrieved_at': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
        })
        print(f'[nvd] {cve_id}')
    MANIFEST.write_text(json.dumps({'source': 'NVD CVE API 2.0', 'records': entries}, indent=2) + '\n', encoding='utf-8')
    print(f'[nvd] pinned {len(entries)} records in {SNAPSHOT_DIR.name}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
