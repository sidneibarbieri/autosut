#!/usr/bin/env python3
"""Fetch the ATT&CK Enterprise releases of the longitudinal measurement and verify them.

A file whose SHA-256 differs from data/attack_releases.json is rejected and removed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import urllib.request
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
MANIFEST = SCRIPTS_DIR / 'data' / 'attack_releases.json'
RELEASE_DIR = SCRIPTS_DIR / 'data' / 'attack-releases'


def release_path(release: str) -> Path:
    return RELEASE_DIR / f'enterprise-attack-{release}.json'


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fetch(entry: dict) -> Path:
    path = release_path(entry['release'])
    if path.exists() and sha256(path) == entry['sha256']:
        return path
    RELEASE_DIR.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(entry['url'], timeout=300) as response:
        path.write_bytes(response.read())
    if sha256(path) != entry['sha256']:
        path.unlink()
        raise ValueError(f"SHA-256 mismatch for ATT&CK {entry['release']}; file removed")
    return path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    for entry in json.loads(MANIFEST.read_text(encoding='utf-8'))['releases']:
        print(f"[attack-releases] {entry['release']}: {fetch(entry)}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
