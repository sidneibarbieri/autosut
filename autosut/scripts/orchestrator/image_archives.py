"""Export verified local images without losing digest-qualified names."""

from __future__ import annotations

import copy
import hashlib
import io
import json
import os
import subprocess
import tarfile
import tempfile
from pathlib import Path

from .docker_images import DockerImageLock, verify_images


def archive_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as archive:
        while chunk := archive.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_reference(reference: str) -> str:
    name = reference.partition('@')[0]
    if '/' not in name:
        return 'docker.io/library/' + reference
    registry = name.partition('/')[0]
    if '.' not in registry and ':' not in registry and registry != 'localhost':
        return 'docker.io/' + reference
    return reference


def name_archive(source: Path, destination: Path, identities: dict[str, str]) -> None:
    """Preserve OCI blobs and bind each exported descriptor to its requested name."""
    with tarfile.open(source) as archive:
        index_member = archive.getmember('index.json')
        index = json.load(archive.extractfile(index_member))
        descriptors = {item['digest']: item for item in index['manifests']}
        named = []
        for reference, image_id in sorted(identities.items()):
            if image_id not in descriptors:
                raise ValueError(f'OCI archive does not preserve locked image identity: {reference}')
            blob_path = 'blobs/sha256/' + image_id.removeprefix('sha256:')
            blob = archive.extractfile(blob_path).read()
            if 'sha256:' + hashlib.sha256(blob).hexdigest() != image_id:
                raise ValueError(f'OCI descriptor content mismatch: {reference}')
            descriptor = copy.deepcopy(descriptors[image_id])
            descriptor.setdefault('annotations', {})['io.containerd.image.name'] = canonical_reference(reference)
            named.append(descriptor)
        index['manifests'] = named
        encoded = json.dumps(index, separators=(',', ':')).encode()
        with tarfile.open(destination, 'w') as output:
            for member in archive:
                stream = archive.extractfile(member) if member.isfile() else None
                if member.name == 'index.json':
                    member = copy.copy(member)
                    member.size = len(encoded)
                    stream = io.BytesIO(encoded)
                output.addfile(member, stream)


def export_images(lock: DockerImageLock, references: list[str], output: Path) -> str:
    """Export by verified IDs; refuse overwrites and unsupported archive identities."""
    if output.exists():
        raise FileExistsError(output)
    observations = verify_images(lock, references)
    identities = {reference: image.image_id for reference, image in observations.items()}
    for image in observations.values():
        for reference in image.repo_digests:
            if reference.partition('@')[2] != image.image_id:
                raise ValueError(f'Repository digest does not name the exported OCI root: {reference}')
            identities[reference] = image.image_id
    with tempfile.TemporaryDirectory(prefix='.autosut-images-', dir=output.parent) as temporary:
        raw = Path(temporary) / 'raw.tar'
        staged = Path(temporary) / 'named.tar'
        subprocess.run(
            ['docker', 'image', 'save', '--output', str(raw), *sorted(set(identities.values()))],
            check=True, timeout=300,
        )
        name_archive(raw, staged, identities)
        verify_images(lock, references)
        digest = archive_sha256(staged)
        os.link(staged, output)
    return digest
