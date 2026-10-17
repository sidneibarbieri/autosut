"""Bind a replay receipt to its retained observations without circular hashes."""

from __future__ import annotations

import hashlib
import os
import uuid
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

MANIFEST_NAME = "replay-evidence-manifest.json"
IDENTITY_NAME = "replay-identity.json"
EXCLUDED_FILES = {MANIFEST_NAME, "joint-replay-receipt.json"}


class ReplayIdentity(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    run_label: str
    campaign_id: str


class EvidenceFile(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    path: str
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    bytes: int = Field(ge=0)


class ReplayEvidenceManifest(ReplayIdentity):
    schema_version: Literal["autosut-replay-evidence/v1"] = "autosut-replay-evidence/v1"
    files: list[EvidenceFile]


def _walk_error(error: OSError) -> None:
    raise error


def _inventory(root: Path) -> dict[str, Path]:
    files = {}
    for directory, names, filenames in os.walk(root, onerror=_walk_error):
        for name in (*names, *filenames):
            path = Path(directory) / name
            if path.is_symlink():
                raise ValueError("replay evidence contains a symlink")
            if path.is_dir():
                continue
            if not path.is_file():
                raise ValueError("replay evidence contains a nonregular file")
            relative = path.relative_to(root).as_posix()
            if relative not in EXCLUDED_FILES:
                files[relative] = path
    return files


def begin_replay(root: Path, campaign_id: str) -> ReplayIdentity:
    identity = ReplayIdentity(run_id=uuid.uuid4().hex, run_label=root.name,
                              campaign_id=campaign_id)
    with (root / IDENTITY_NAME).open("x", encoding="utf-8") as output:
        output.write(identity.model_dump_json(indent=2) + "\n")
    return identity


def seal_replay_evidence(root: Path, identity: ReplayIdentity) -> tuple[ReplayEvidenceManifest, str]:
    entries = []
    for relative, path in sorted(_inventory(root).items()):
        payload = path.read_bytes()
        entries.append(EvidenceFile(path=relative, bytes=len(payload),
                                    sha256=hashlib.sha256(payload).hexdigest()))
    manifest = ReplayEvidenceManifest(**identity.model_dump(), files=entries)
    payload = (manifest.model_dump_json(indent=2) + "\n").encode("utf-8")
    with (root / MANIFEST_NAME).open("xb") as output:
        output.write(payload)
    return manifest, hashlib.sha256(payload).hexdigest()


def verify_replay_evidence(root: Path, expected_digest: str, run_id: str) -> ReplayEvidenceManifest:
    payload = (root / MANIFEST_NAME).read_bytes()
    if hashlib.sha256(payload).hexdigest() != expected_digest:
        raise ValueError("replay evidence manifest hash differs from receipt")
    manifest = ReplayEvidenceManifest.model_validate_json(payload)
    identity = ReplayIdentity.model_validate_json((root / IDENTITY_NAME).read_bytes())
    if manifest.run_id != run_id or identity != ReplayIdentity(
        run_id=manifest.run_id, run_label=manifest.run_label, campaign_id=manifest.campaign_id,
    ):
        raise ValueError("replay run identity differs across receipt and evidence")
    actual = _inventory(root)
    expected = {entry.path: entry for entry in manifest.files}
    if len(expected) != len(manifest.files) or set(actual) != set(expected):
        raise ValueError("replay evidence file inventory differs from manifest")
    for relative, path in actual.items():
        payload = path.read_bytes()
        entry = expected[relative]
        if len(payload) != entry.bytes or hashlib.sha256(payload).hexdigest() != entry.sha256:
            raise ValueError("replay evidence file integrity differs from manifest")
    return manifest
