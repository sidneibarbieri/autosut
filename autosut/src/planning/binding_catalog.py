"""Generate the versioned binding catalog consumed by STICKS concretization."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from .sut_blueprint import SUTBlueprint


class BindingValue(BaseModel):
    model_config = ConfigDict(extra="forbid")

    binding_id: str
    kind: str
    value: str
    source: str
    scope: str = "lab"
    secret_reference: bool = False


class BindingCatalog(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "1"
    sut_id: str
    source_sha256: str
    initial_facts: list[str] = Field(default_factory=list)
    goal_facts: list[str] = Field(default_factory=list)
    bindings: list[BindingValue] = Field(default_factory=list)
    content_sha256: str = ""

    def finalize_hash(self) -> None:
        payload = self.model_dump(mode="json", exclude={"content_sha256"})
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        self.content_sha256 = hashlib.sha256(encoded).hexdigest()


def _binding(
    binding_id: str,
    kind: str,
    value: str,
    *,
    source: str,
    secret_reference: bool = False,
) -> BindingValue:
    return BindingValue(
        binding_id=binding_id,
        kind=kind,
        value=value,
        source=source,
        secret_reference=secret_reference,
    )


def build_binding_catalog(
    blueprint: SUTBlueprint,
    campaign_spec_path: Path,
) -> BindingCatalog:
    campaign_spec = json.loads(campaign_spec_path.read_text(encoding="utf-8"))
    source_campaign_id = str(campaign_spec.get("source_campaign_id", ""))
    if source_campaign_id != blueprint.campaign_id:
        raise ValueError(
            f"campaign/blueprint mismatch: {source_campaign_id} != {blueprint.campaign_id}"
        )
    raw_contract = campaign_spec.get("execution_contract")
    if not isinstance(raw_contract, dict):
        raise ValueError("campaign specification has no execution_contract")
    if not blueprint.hosts:
        raise ValueError("blueprint has no target hosts")
    target = blueprint.hosts[0]
    target_ref = f"lab://{target.host_id}"
    bindings = [
        _binding("actor.primary", "actor_host", "lab://actor-1", source="sut"),
        _binding("target.primary", "target_host", target_ref, source="sut"),
        _binding(
            "endpoint.public_service",
            "endpoint",
            f"{target_ref}/service/public-facing-application",
            source="sut",
        ),
        _binding("runtime.python3", "runtime", f"{target_ref}/runtime/python3", source="sut"),
        _binding(
            "toolkit.benign",
            "toolkit",
            "artifact://actor-1/toolkit/pinned-benign",
            source="system_choice",
        ),
        _binding(
            "artifact.shell_config",
            "shell_config_artifact",
            "artifact://target-1/shell-config/lab-only",
            source="system_choice",
        ),
        _binding(
            "artifact.encoded",
            "encoded_artifact",
            "artifact://target-1/encoded/benign",
            source="system_choice",
        ),
        _binding(
            "boundary.no_live_exploit",
            "privilege_boundary",
            "policy://target-1/no-live-local-exploit",
            source="system_choice",
        ),
        _binding(
            "credential.synthetic_fixture",
            "credential_source",
            f"secret://sut/{campaign_spec['campaign_id']}/credential-fixture",
            source="sut",
            secret_reference=True,
        ),
        _binding(
            "network.private_interface",
            "network_interface",
            f"{target_ref}/network/private",
            source="sut",
        ),
        _binding(
            "channel.private_http",
            "channel",
            "lab://actor-1/to/target-1/http",
            source="sut",
        ),
        _binding(
            "payload.benign",
            "payload",
            "artifact://actor-1/payload/pinned-benign",
            source="system_choice",
        ),
        _binding(
            "workload.bounded_hash",
            "compute_workload",
            "workload://target-1/bounded-hash-5s",
            source="system_choice",
        ),
        _binding(
            "infrastructure.lab_manifest",
            "infrastructure_artifact",
            "artifact://actor-1/infrastructure/lab-only",
            source="system_choice",
        ),
        _binding(
            "capability.benign_specification",
            "capability_specification",
            "artifact://actor-1/capability/benign-specification",
            source="system_choice",
        ),
        _binding(
            "web_asset.benign_landing",
            "web_asset",
            "artifact://actor-1/web/benign-landing",
            source="sut",
        ),
        _binding(
            "data.synthetic_fixture",
            "data_source",
            "artifact://target-1/data/synthetic-fixture",
            source="sut",
        ),
        _binding(
            "archive_tool.local",
            "archive_tool",
            f"{target_ref}/utility/archive",
            source="sut",
        ),
        _binding(
            "archive.synthetic_collection",
            "archive_artifact",
            "artifact://target-1/archive/synthetic-collection",
            source="system_choice",
        ),
        _binding(
            "chunk_policy.bounded_local",
            "chunk_policy",
            "policy://target-1/chunks/local-bounded",
            source="system_choice",
        ),
    ]
    source_payload = {
        "blueprint_sha256": blueprint.content_sha256,
        "campaign_sha256": hashlib.sha256(
            campaign_spec_path.read_bytes()
        ).hexdigest(),
    }
    source_sha256 = hashlib.sha256(
        json.dumps(source_payload, sort_keys=True).encode()
    ).hexdigest()
    catalog = BindingCatalog(
        sut_id=str(campaign_spec["campaign_id"]),
        source_sha256=source_sha256,
        initial_facts=list(raw_contract.get("initial_facts", [])),
        goal_facts=list(
            raw_contract.get("techniques", [{}])[-1].get("produces", [])
            if raw_contract.get("techniques")
            else []
        ),
        bindings=bindings,
    )
    catalog.finalize_hash()
    return catalog


def build_reference_catalog(catalog: BindingCatalog) -> BindingCatalog:
    """Remove campaign-conditioned SUT bindings for the fixed-reference arm."""

    excluded_kinds = {
        "endpoint",
        "credential_source",
        "channel",
    }
    reference = BindingCatalog(
        sut_id="reference-linux-sut",
        source_sha256=catalog.content_sha256,
        initial_facts=[
            fact_id
            for fact_id in catalog.initial_facts
            if fact_id in {"sut.ready", "actor.ready"}
        ],
        goal_facts=list(catalog.goal_facts),
        bindings=[
            binding
            for binding in catalog.bindings
            if binding.kind not in excluded_kinds
        ],
    )
    reference.finalize_hash()
    return reference
