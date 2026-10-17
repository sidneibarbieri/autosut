"""Inspect the actual stopped guest disk before teardown deletes it."""

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from orchestrator.windows_qemu_environment import WindowsQemuEnvironment


def make_stopped_backend(tmp_path, observer):
    overlay = tmp_path / "guest.qcow2"
    overlay.write_bytes(b"synthetic stopped guest state")
    monitor = tmp_path / "monitor"
    monitor.mkdir()
    tpm_state = tmp_path / "tpm-state"
    tpm_state.mkdir()
    backend = WindowsQemuEnvironment(
        sut=None, run_dir=tmp_path, workdir=tmp_path, namespace="observer-test",
        winrm_port=41235, password="synthetic-only",
        guest=SimpleNamespace(poll=lambda: 0), tpm=SimpleNamespace(poll=lambda: 0),
        tpm_socket=tmp_path / "tpm.sock", overlay=overlay,
        vars_file=tmp_path / "vars.fd", tpm_state=tpm_state,
        monitor_dir=monitor, log_handles=[], hostname="synthetic",
        stopped_disk_observer=observer,
    )
    backend.residual_inventory = lambda: SimpleNamespace(clean=True)
    return backend, overlay, monitor, tpm_state


def test_observer_reads_actual_disk_before_removal(tmp_path):
    observed = []

    def acquire(overlay):
        observed.append(overlay.read_bytes())

    backend, overlay, monitor, tpm_state = make_stopped_backend(tmp_path, acquire)
    backend.teardown()
    backend.teardown()

    assert observed == [b"synthetic stopped guest state"]
    assert not overlay.exists()
    assert not monitor.exists()
    assert not tpm_state.exists()
    assert backend._password == ""
    assert backend.teardown_record.controller_credential_cleared
    with pytest.raises(RuntimeError, match="credential has been cleared"):
        backend._session()

def test_observer_failure_propagates_after_resource_cleanup(tmp_path):
    def acquire(overlay):
        assert overlay.read_bytes() == b"synthetic stopped guest state"
        raise ValueError("synthetic acquisition failure")

    backend, overlay, monitor, tpm_state = make_stopped_backend(tmp_path, acquire)

    with pytest.raises(ValueError, match="synthetic acquisition failure"):
        backend.teardown()

    assert not overlay.exists()
    assert not monitor.exists()
    assert not tpm_state.exists()
    assert backend.teardown() is False
    assert backend._password == ""
