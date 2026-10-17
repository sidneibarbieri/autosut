"""Caldera teardown must not mistake a failed inventory for a clean host."""

from types import SimpleNamespace

import pytest
from infrastructure.caldera_instance import CalderaInstance, CalderaResidualError


@pytest.mark.parametrize(
    ("inventory_code", "listing", "expected_error"),
    [
        (0, "", None),
        (0, "autosut-run\n", CalderaResidualError),
        (1, "", RuntimeError),
    ],
)
def test_destroy_requires_completed_container_inventory(
    monkeypatch, inventory_code, listing, expected_error,
):
    calls = []

    def run(command, **options):
        calls.append(command)
        if command[1] == "rm":
            return SimpleNamespace(returncode=0)
        return SimpleNamespace(returncode=inventory_code, stdout=listing)

    monkeypatch.setattr("infrastructure.caldera_instance.subprocess.run", run)
    instance = CalderaInstance(container_name="autosut-run", host_port=8123)

    if expected_error is None:
        instance.destroy()
    else:
        with pytest.raises(expected_error):
            instance.destroy()

    assert [command[1] for command in calls] == ["rm", "ps"]
