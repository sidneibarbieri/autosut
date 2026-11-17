#!/usr/bin/env python3
"""Capture, verify or export explicit local Docker images; never build or pull."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from orchestrator.attacker import ATTACKER_IMAGE
from orchestrator.catalog import resolve
from orchestrator.docker_images import DockerImageLock, inspect_image, verify_images
from orchestrator.image_archives import export_images


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['capture', 'verify', 'export'])
    parser.add_argument('--reference', action='append', default=[])
    parser.add_argument('--campaign', action='append', default=[])
    parser.add_argument('--lock', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    references = set(args.reference)
    for campaign in args.campaign:
        _, sut, _ = resolve(campaign)
        if sut.backend not in (None, 'docker'):
            parser.error('Image locks apply only to Docker campaigns')
        if sut.is_multi_host:
            references.update(host.base_image for host in sut.hosts)
        else:
            references.add(sut.base_image)
            references.add(ATTACKER_IMAGE)
    if not references:
        parser.error('Declare at least one --reference or --campaign')
    if args.action == 'capture':
        if args.output is None:
            parser.error('capture requires --output')
        lock = DockerImageLock(images={reference: inspect_image(reference) for reference in sorted(references)})
        args.output.write_text(lock.model_dump_json(indent=2) + '\n')
        print('Recorded local identities; this does not qualify image distribution or campaign effects.')
    else:
        if args.lock is None:
            parser.error(f'{args.action} requires --lock')
        lock = DockerImageLock.model_validate_json(args.lock.read_bytes())
        if args.action == 'export':
            if args.output is None:
                parser.error('export requires --output')
            digest = export_images(lock, sorted(references), args.output)
            print(json.dumps({'status': 'exported', 'archive_sha256': digest, 'images': sorted(references)}, indent=2))
            return 0
        observations = verify_images(lock, sorted(references))
        print(json.dumps({'status': 'verified', 'images': {key: value.model_dump(mode='json') for key, value in observations.items()}}, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
