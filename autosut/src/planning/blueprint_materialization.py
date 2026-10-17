"""Map a synthesized SUT blueprint to a materializable SUTProfile.

The blueprint declares the minimal hosts a campaign needs (platform, image, backend, resources); this
turns it into the profile the canonical backend materializes. It decouples the end-to-end driver from
any single hand-authored SUT. Materialization remains bounded by the supported backend and topology.
"""

from __future__ import annotations

import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parents[1]
_SCRIPTS = _SRC.parent / "scripts"
for _root in (_SRC, _SCRIPTS):
    if str(_root) not in sys.path:
        sys.path.insert(0, str(_root))

from orchestrator.models import ProvenanceSource, SUTHost, SUTProfile  # noqa: E402
from infrastructure.fleet_capabilities import require_docker_fleet_backend  # noqa: E402
from planning.sut_blueprint import BlueprintHost, SUTBlueprint  # noqa: E402

_SUPPORTED_BACKENDS = {"docker", "qemu", "windows-qemu"}


def _sut_host(host: BlueprintHost) -> SUTHost:
    return SUTHost(
        name=host.host_id,
        base_image=host.recipe.base_image,
        role=host.role,
        memory_mb=host.recipe.memory_mb,
        smp=host.recipe.cpu_count,
    )


def sut_profile_from_blueprint(blueprint: SUTBlueprint) -> SUTProfile:
    """Return the materializable profile for a synthesized blueprint.

    Every host must declare one shared backend that the orchestrator supports; a single-host blueprint
    fills the profile's scalar fields, a multi-host blueprint fills ``hosts``. The SUT is synthesized, so
    its provenance is autosut_concretized.
    """
    backends = {host.recipe.backend for host in blueprint.hosts}
    if len(backends) != 1:
        raise ValueError(f"blueprint mixes backends {sorted(backends)}; one materialization backend required")
    backend = backends.pop()
    if backend not in _SUPPORTED_BACKENDS:
        raise ValueError(f"unsupported materialization backend {backend!r}; known: {sorted(_SUPPORTED_BACKENDS)}")
    if len(blueprint.hosts) > 1:
        require_docker_fleet_backend(backend)
    primary = blueprint.hosts[0]
    multi_host = [_sut_host(host) for host in blueprint.hosts] if len(blueprint.hosts) > 1 else []
    return SUTProfile(
        sut_id=f"{blueprint.campaign_id}-sut",
        base_image=primary.recipe.base_image,
        platform_source=ProvenanceSource.autosut_concretized,
        memory_mb=primary.recipe.memory_mb,
        smp=primary.recipe.cpu_count,
        backend=backend,
        hosts=multi_host or None,
    )
