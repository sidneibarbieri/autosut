"""Explicit Docker image identities for controlled replay inputs."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from contextlib import contextmanager
from contextvars import ContextVar
from collections.abc import Iterator
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

IMAGE_LOCK_ENV = 'AUTOSUT_DOCKER_IMAGE_LOCK'


class DockerImageIdentity(BaseModel):
    model_config = ConfigDict(extra='forbid', frozen=True)

    image_id: str = Field(pattern=r'^sha256:[0-9a-f]{64}$')
    operating_system: str = Field(min_length=1)
    architecture: str = Field(min_length=1)
    variant: str = ''
    repo_digests: tuple[str, ...] = ()


class DockerImageLock(BaseModel):
    model_config = ConfigDict(extra='forbid', frozen=True)

    schema_version: Literal[1] = 1
    images: dict[str, DockerImageIdentity] = Field(min_length=1)


_ACTIVE_LOCK: ContextVar[DockerImageLock | None] = ContextVar('docker_image_lock', default=None)


def configured_lock() -> DockerImageLock | None:
    active = _ACTIVE_LOCK.get()
    if active is not None:
        return active
    path = os.environ.get(IMAGE_LOCK_ENV)
    return DockerImageLock.model_validate_json(Path(path).read_bytes()) if path else None


@contextmanager
def image_lock_scope(path: Path | None) -> Iterator[None]:
    """Freeze the validated lock for this invocation, including nested launches."""
    lock = DockerImageLock.model_validate_json(path.read_bytes()) if path else configured_lock()
    token = _ACTIVE_LOCK.set(lock)
    try:
        yield
    finally:
        _ACTIVE_LOCK.reset(token)


def inspect_image(reference: str) -> DockerImageIdentity:
    if not reference.strip() or reference.startswith('-'):
        raise ValueError('Image reference must be a nonempty Docker image name or ID')
    result = subprocess.run(
        ['docker', 'image', 'inspect', reference],
        capture_output=True, text=True, check=True, timeout=30,
    )
    observations = json.loads(result.stdout)
    if not isinstance(observations, list) or len(observations) != 1:
        raise ValueError(f'Expected one Docker image for {reference}')
    image = observations[0]
    return DockerImageIdentity(
        image_id=image['Id'], operating_system=image['Os'],
        architecture=image['Architecture'], variant=image.get('Variant', ''),
        repo_digests=tuple(image.get('RepoDigests') or ()),
    )


def verify_images(lock: DockerImageLock, references: list[str]) -> dict[str, DockerImageIdentity]:
    missing = sorted(set(references) - lock.images.keys())
    if missing:
        raise ValueError(f'Images not declared in the Docker image lock: {missing}')
    observations = {}
    for reference in sorted(set(references)):
        expected = lock.images[reference]
        actual = inspect_image(reference)
        if (expected.image_id, expected.operating_system, expected.architecture, expected.variant) != (
            actual.image_id, actual.operating_system, actual.architecture, actual.variant,
        ) or not set(expected.repo_digests).issubset(actual.repo_digests):
            raise ValueError(
                f'Docker image identity mismatch for {reference}: '
                f'expected {expected.model_dump()}, observed {actual.model_dump()}'
            )
        requested = os.environ.get('AUTOSUT_DOCKER_PLATFORM') or os.environ.get('DOCKER_DEFAULT_PLATFORM')
        platform = f'{actual.operating_system}/{actual.architecture}'
        if requested and requested not in {platform, f'{platform}/{actual.variant}'}:
            raise ValueError(f'Docker platform {requested} conflicts with locked image {platform}')
        observations[reference] = actual
    return observations


def resolve_image(reference: str) -> str:
    lock = configured_lock()
    if lock is None:
        return reference
    return verify_images(lock, [reference])[reference].image_id


def verify_campaign_images(references: list[str], run_dir: Path) -> None:
    lock = configured_lock()
    if lock is None:
        return
    observations = verify_images(lock, references)
    encoded = json.dumps(lock.model_dump(mode='json'), sort_keys=True, separators=(',', ':')).encode()
    receipt = {
        'mode': 'locked_local_images',
        'lock_sha256': hashlib.sha256(encoded).hexdigest(),
        'images': {reference: identity.model_dump(mode='json') for reference, identity in observations.items()},
        'boundary': 'Image identity and platform only; does not freeze runtime package installs or establish campaign effects.',
    }
    (run_dir / 'image-contract.json').write_text(json.dumps(receipt, indent=2) + '\n')
