"""The endpoint context manager retargets the client and restores the previous target on exit.

Every client function reads the module target by name, so the context manager only needs to rebind
it; the point of these tests is that the rebinding is scoped and always restored, including when the
block raises.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from orchestrator import caldera_client  # noqa: E402


def test_endpoint_retargets_url_and_container_inside_the_block():
    default_url = caldera_client.CALDERA_URL
    with caldera_client.endpoint("http://127.0.0.1:59999", "autosut-run-caldera"):
        assert caldera_client.CALDERA_URL == "http://127.0.0.1:59999"
        assert caldera_client.CALDERA_CONTAINER == "autosut-run-caldera"
    assert caldera_client.CALDERA_URL == default_url


def test_endpoint_restores_the_previous_target_even_when_the_block_raises():
    default_url = caldera_client.CALDERA_URL
    default_container = caldera_client.CALDERA_CONTAINER
    with pytest.raises(RuntimeError):
        with caldera_client.endpoint("http://127.0.0.1:59998", "autosut-other-caldera"):
            raise RuntimeError("operation failed mid-block")
    assert caldera_client.CALDERA_URL == default_url
    assert caldera_client.CALDERA_CONTAINER == default_container
