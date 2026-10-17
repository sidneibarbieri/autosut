"""Replay file seals must preserve identity and reject retained-output changes."""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from planning.replay_integrity import (
    begin_replay,
    seal_replay_evidence,
    verify_replay_evidence,
)


def test_new_runs_get_distinct_persisted_identities(tmp_path):
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    first_identity = begin_replay(first, "campaign-one")
    second_identity = begin_replay(second, "campaign-one")
    assert first_identity.run_id != second_identity.run_id
    assert first_identity.run_label == "first"
    with pytest.raises(FileExistsError):
        begin_replay(first, "campaign-one")


def test_generated_manifest_binds_observation_and_identity(tmp_path):
    identity = begin_replay(tmp_path, "campaign-one")
    observation = tmp_path / "observation.log"
    observation.write_bytes(b"observed")
    manifest, digest = seal_replay_evidence(tmp_path, identity)
    assert {entry.path for entry in manifest.files} == {"observation.log", "replay-identity.json"}
    assert digest == hashlib.sha256((tmp_path / "replay-evidence-manifest.json").read_bytes()).hexdigest()
    assert verify_replay_evidence(tmp_path, digest, identity.run_id).campaign_id == "campaign-one"
    observation.write_bytes(b"changed!")
    with pytest.raises(ValueError, match="file integrity"):
        verify_replay_evidence(tmp_path, digest, identity.run_id)


def test_sealing_cannot_follow_an_external_symlink(tmp_path):
    identity = begin_replay(tmp_path, "campaign-one")
    (tmp_path / "external").symlink_to(tmp_path.parent)
    with pytest.raises(ValueError, match="symlink"):
        seal_replay_evidence(tmp_path, identity)


def test_sealing_cannot_overwrite_an_existing_manifest(tmp_path):
    identity = begin_replay(tmp_path, "campaign-one")
    seal_replay_evidence(tmp_path, identity)
    with pytest.raises(FileExistsError):
        seal_replay_evidence(tmp_path, identity)
