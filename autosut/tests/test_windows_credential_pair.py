"""Two Windows clones must reject each other's ephemeral credentials."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from infra import windows_credential_pair


def test_identity_line_requires_three_nonempty_fields():
    identity = windows_credential_pair.parse_identity("WIN-A|S-1-5-21-123|guid-a\r\n")

    assert identity.hostname == "WIN-A"
    assert identity.machine_sid == "S-1-5-21-123"
    assert identity.machine_guid == "guid-a"
    with pytest.raises(ValueError, match="identity response"):
        windows_credential_pair.parse_identity("WIN-A|S-1-5-21-123|")


def test_pair_verdict_requires_cross_rejection_and_distinct_machine_identity():
    first = windows_credential_pair.CloneResult(
        label="a", hostname="WIN-A", machine_sid="SID-A", machine_guid="GUID-A",
        own_credential_accepted=True, other_credential_rejected=True, clean_teardown=True,
    )
    second = windows_credential_pair.CloneResult(
        label="b", hostname="WIN-B", machine_sid="SID-B", machine_guid="GUID-B",
        own_credential_accepted=True, other_credential_rejected=True, clean_teardown=True,
    )

    assert windows_credential_pair.pair_passed(first, second, True, True)
    assert not windows_credential_pair.pair_passed(
        first, second.model_copy(update={"other_credential_rejected": False}), True, True,
    )
    assert not windows_credential_pair.pair_passed(
        first, second.model_copy(update={"machine_sid": "SID-A"}), True, True,
    )


def test_pair_clone_uses_the_qualified_windows_vm_resources(tmp_path):
    profile = windows_credential_pair.clone_profile("first", tmp_path / "prepared.qcow2")

    assert profile.smp == 4
    assert profile.memory_mb == 6144
    assert profile.backend == "windows-qemu"
