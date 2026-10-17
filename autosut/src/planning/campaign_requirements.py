"""Typed, provenance-bearing campaign requirements for environment planning.

``CampaignRequirements`` is the boundary between structured CTI interpretation
and substrate planning.  It records what a campaign needs a laboratory to
provide; it does not claim that the historical campaign used a particular
environment and it does not contain commands, credentials, or provisioner
scripts.

The model is intentionally stricter than a convenience configuration file:

* every requirement is linked to a declared provenance record;
* runtime credentials are references to environment-variable names, never
  values;
* network addresses are confined to RFC 1918 ranges; and
* unresolved requirements remain explicit instead of being silently filled in
  by a planner.

This makes a generated provider plan inspectable and replayable without
turning a provider choice into CTI evidence.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from enum import Enum
from typing import cast

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

_IDENTIFIER_RE = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
_ENVIRONMENT_VARIABLE_RE = re.compile(r"^[A-Z][A-Z0-9_]{2,127}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_TECHNIQUE_RE = re.compile(r"^T[0-9]{4}(?:\.[0-9]{3})?$")
_USERNAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,63}$")
_RFC1918_NETWORKS = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
)


def _is_rfc1918_network(network: ipaddress.IPv4Network) -> bool:
    """Return true only for a subnet of RFC 1918, not all ``is_private`` ranges."""
    return any(network.subnet_of(private_network) for private_network in _RFC1918_NETWORKS)


def _is_rfc1918_address(address: ipaddress.IPv4Address) -> bool:
    """Return true only for the three RFC 1918 address ranges."""
    return any(address in private_network for private_network in _RFC1918_NETWORKS)


class PlatformFamily(str, Enum):
    """Operating-system families a campaign can require."""

    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"


class IdentityModel(str, Enum):
    """Identity topology that the planned environment must provide."""

    WORKGROUP = "workgroup"
    ACTIVE_DIRECTORY = "active_directory"


class PrivilegeLevel(str, Enum):
    """Minimum privilege expected by a procedure or principal."""

    USER = "user"
    LOCAL_ADMINISTRATOR = "local_administrator"
    SYSTEM = "system"


class ProvenanceKind(str, Enum):
    """The source class behind a requirement value."""

    STIX = "stix"
    SEMANTIC_ENRICHMENT = "semantic_enrichment"
    DEPLOYMENT_CATALOG = "deployment_catalog"
    ANALYST_DECISION = "analyst_decision"


class RequirementProvenance(BaseModel):
    """One hash-bound source supporting or delimiting a requirement."""

    model_config = ConfigDict(extra="forbid")

    provenance_id: str
    kind: ProvenanceKind
    source_sha256: str
    locator: str
    note: str = ""

    @field_validator("provenance_id")
    @classmethod
    def _validate_provenance_id(cls, value: str) -> str:
        if not _IDENTIFIER_RE.fullmatch(value):
            raise ValueError("provenance_id must be a lowercase identifier")
        return value

    @field_validator("source_sha256")
    @classmethod
    def _validate_sha256(cls, value: str) -> str:
        normalized = value.lower()
        if not _SHA256_RE.fullmatch(normalized):
            raise ValueError("source_sha256 must be a lowercase SHA-256 digest")
        return normalized

    @field_validator("locator")
    @classmethod
    def _validate_locator(cls, value: str) -> str:
        if not value.strip() or "\x00" in value:
            raise ValueError("locator must be a non-empty, NUL-free reference")
        return value


class NetworkSegmentRequirement(BaseModel):
    """A private layer-three segment in the intended SUT topology."""

    model_config = ConfigDict(extra="forbid")

    segment_id: str
    cidr: str
    provenance_refs: list[str] = Field(min_length=1)

    @field_validator("segment_id")
    @classmethod
    def _validate_segment_id(cls, value: str) -> str:
        if not _IDENTIFIER_RE.fullmatch(value):
            raise ValueError("segment_id must be a lowercase identifier")
        return value

    @field_validator("cidr")
    @classmethod
    def _validate_private_cidr(cls, value: str) -> str:
        network = ipaddress.IPv4Network(value, strict=True)
        if not _is_rfc1918_network(network):
            raise ValueError("network segments must use an RFC 1918 private IPv4 range")
        return str(network)


class HostRequirement(BaseModel):
    """One named host that the campaign topology requires."""

    model_config = ConfigDict(extra="forbid")

    host_id: str
    hostname: str
    role: str
    platform: PlatformFamily
    network_segment_id: str
    ipv4_address: str
    memory_mib: int = Field(ge=1024, le=131_072)
    cpus: int = Field(ge=1, le=64)
    provenance_refs: list[str] = Field(min_length=1)

    @field_validator("host_id", "hostname", "network_segment_id")
    @classmethod
    def _validate_identifier(cls, value: str) -> str:
        if not _IDENTIFIER_RE.fullmatch(value):
            raise ValueError("host and network identifiers must be lowercase identifiers")
        return value

    @field_validator("role")
    @classmethod
    def _validate_role(cls, value: str) -> str:
        if not value.strip() or "\n" in value or "\r" in value:
            raise ValueError("role must be a single non-empty line")
        return value

    @field_validator("ipv4_address")
    @classmethod
    def _validate_private_address(cls, value: str) -> str:
        address = ipaddress.IPv4Address(value)
        if not _is_rfc1918_address(address):
            raise ValueError("host addresses must use an RFC 1918 private IPv4 address")
        return str(address)


class IdentityRequirement(BaseModel):
    """A principal needed by a campaign, without materializing its secret."""

    model_config = ConfigDict(extra="forbid")

    principal_id: str
    host_id: str
    username: str
    privilege: PrivilegeLevel
    runtime_secret_environment_variable: str | None = None
    purpose: str
    provenance_refs: list[str] = Field(min_length=1)

    @field_validator("principal_id", "host_id")
    @classmethod
    def _validate_identifier(cls, value: str) -> str:
        if not _IDENTIFIER_RE.fullmatch(value):
            raise ValueError("principal_id and host_id must be lowercase identifiers")
        return value

    @field_validator("username")
    @classmethod
    def _validate_username(cls, value: str) -> str:
        if not _USERNAME_RE.fullmatch(value):
            raise ValueError("username contains unsupported characters")
        return value

    @field_validator("runtime_secret_environment_variable")
    @classmethod
    def _validate_runtime_secret_reference(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not _ENVIRONMENT_VARIABLE_RE.fullmatch(value):
            raise ValueError(
                "runtime_secret_environment_variable must name an environment variable, not a secret"
            )
        return value

    @field_validator("purpose")
    @classmethod
    def _validate_purpose(cls, value: str) -> str:
        if not value.strip() or "\n" in value or "\r" in value:
            raise ValueError("purpose must be a single non-empty line")
        return value


class NetworkExposureRequirement(BaseModel):
    """A service exposure required within the isolated laboratory only."""

    model_config = ConfigDict(extra="forbid")

    host_id: str
    service_name: str
    port: int = Field(ge=1, le=65_535)
    protocol: str = "tcp"
    scope: str = "private_lab"
    provenance_refs: list[str] = Field(min_length=1)

    @field_validator("host_id")
    @classmethod
    def _validate_host_id(cls, value: str) -> str:
        if not _IDENTIFIER_RE.fullmatch(value):
            raise ValueError("host_id must be a lowercase identifier")
        return value

    @field_validator("service_name")
    @classmethod
    def _validate_service_name(cls, value: str) -> str:
        if not value.strip() or "\n" in value or "\r" in value:
            raise ValueError("service_name must be a single non-empty line")
        return value

    @field_validator("protocol")
    @classmethod
    def _validate_protocol(cls, value: str) -> str:
        if value not in {"tcp", "udp"}:
            raise ValueError("protocol must be tcp or udp")
        return value

    @field_validator("scope")
    @classmethod
    def _validate_scope(cls, value: str) -> str:
        if value != "private_lab":
            raise ValueError("Windows provider plans support private_lab exposure only")
        return value


class PrivilegeRequirement(BaseModel):
    """The minimum privilege a specific technique needs on a named host."""

    model_config = ConfigDict(extra="forbid")

    technique_id: str
    host_id: str
    principal_id: str
    minimum_privilege: PrivilegeLevel
    provenance_refs: list[str] = Field(min_length=1)

    @field_validator("technique_id")
    @classmethod
    def _validate_technique_id(cls, value: str) -> str:
        if not _TECHNIQUE_RE.fullmatch(value):
            raise ValueError("technique_id must be an ATT&CK technique identifier")
        return value

    @field_validator("host_id", "principal_id")
    @classmethod
    def _validate_identifier(cls, value: str) -> str:
        if not _IDENTIFIER_RE.fullmatch(value):
            raise ValueError("privilege references must be lowercase identifiers")
        return value


class SoftwareRequirement(BaseModel):
    """A named software role, version, and host dependency without installer code."""

    model_config = ConfigDict(extra="forbid")

    host_id: str
    product: str
    version: str
    role: str
    required_by_technique_ids: list[str] = Field(min_length=1)
    provenance_refs: list[str] = Field(min_length=1)

    @field_validator("host_id")
    @classmethod
    def _validate_host_id(cls, value: str) -> str:
        if not _IDENTIFIER_RE.fullmatch(value):
            raise ValueError("host_id must be a lowercase identifier")
        return value

    @field_validator("product", "version", "role")
    @classmethod
    def _validate_text(cls, value: str) -> str:
        if not value.strip() or "\n" in value or "\r" in value or "\x00" in value:
            raise ValueError("software fields must be non-empty single-line values")
        return value

    @field_validator("required_by_technique_ids")
    @classmethod
    def _validate_techniques(cls, values: list[str]) -> list[str]:
        if any(not _TECHNIQUE_RE.fullmatch(value) for value in values):
            raise ValueError("required_by_technique_ids must contain ATT&CK technique identifiers")
        return sorted(set(values))


class ProcedureRequirement(BaseModel):
    """A non-executable condition needed to attempt one ATT&CK technique."""

    model_config = ConfigDict(extra="forbid")

    technique_id: str
    execution_domain: str
    required_host_ids: list[str] = Field(min_length=1)
    required_principal_ids: list[str] = Field(default_factory=list)
    evidence_predicates: list[str] = Field(min_length=1)
    provenance_refs: list[str] = Field(min_length=1)

    @field_validator("technique_id")
    @classmethod
    def _validate_technique_id(cls, value: str) -> str:
        if not _TECHNIQUE_RE.fullmatch(value):
            raise ValueError("technique_id must be an ATT&CK technique identifier")
        return value

    @field_validator("execution_domain")
    @classmethod
    def _validate_execution_domain(cls, value: str) -> str:
        if value not in {"target", "controller", "network"}:
            raise ValueError("execution_domain must be target, controller, or network")
        return value

    @field_validator("required_host_ids", "required_principal_ids")
    @classmethod
    def _validate_references(cls, values: list[str]) -> list[str]:
        if any(not _IDENTIFIER_RE.fullmatch(value) for value in values):
            raise ValueError("procedure references must be lowercase identifiers")
        return sorted(set(values))

    @field_validator("evidence_predicates")
    @classmethod
    def _validate_evidence_predicates(cls, values: list[str]) -> list[str]:
        if any(not value.strip() or "\n" in value or "\r" in value for value in values):
            raise ValueError("evidence predicates must be non-empty single-line labels")
        return sorted(set(values))


class UnresolvedRequirement(BaseModel):
    """An uncertainty that must remain visible until separately resolved."""

    model_config = ConfigDict(extra="forbid")

    item_id: str
    category: str
    description: str
    blocks_materialization: bool
    provenance_refs: list[str] = Field(min_length=1)

    @field_validator("item_id")
    @classmethod
    def _validate_item_id(cls, value: str) -> str:
        if not _IDENTIFIER_RE.fullmatch(value):
            raise ValueError("item_id must be a lowercase identifier")
        return value

    @field_validator("category", "description")
    @classmethod
    def _validate_text(cls, value: str) -> str:
        if not value.strip() or "\x00" in value:
            raise ValueError("unresolved item text must be non-empty and NUL-free")
        return value


class CampaignRequirements(BaseModel):
    """The versioned input to an environment provider for one campaign.

    The model describes requirements only.  It is not a record of a completed
    execution and cannot be used as evidence that a procedure ran.
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: str = "campaign-requirements/v1"
    campaign_id: str
    source_bundle_sha256: str
    target_platforms: list[PlatformFamily] = Field(min_length=1)
    identity_model: IdentityModel
    network_segments: list[NetworkSegmentRequirement] = Field(min_length=1)
    hosts: list[HostRequirement] = Field(min_length=1)
    identities: list[IdentityRequirement] = Field(default_factory=list)
    network_exposures: list[NetworkExposureRequirement] = Field(default_factory=list)
    privilege_requirements: list[PrivilegeRequirement] = Field(default_factory=list)
    software_requirements: list[SoftwareRequirement] = Field(default_factory=list)
    procedure_requirements: list[ProcedureRequirement] = Field(min_length=1)
    provenance: list[RequirementProvenance] = Field(min_length=1)
    unresolved_items: list[UnresolvedRequirement] = Field(default_factory=list)

    @field_validator("campaign_id")
    @classmethod
    def _validate_campaign_id(cls, value: str) -> str:
        if not value.strip() or "\n" in value or "\r" in value:
            raise ValueError("campaign_id must be a non-empty single line")
        return value

    @field_validator("source_bundle_sha256")
    @classmethod
    def _validate_bundle_sha256(cls, value: str) -> str:
        normalized = value.lower()
        if not _SHA256_RE.fullmatch(normalized):
            raise ValueError("source_bundle_sha256 must be a lowercase SHA-256 digest")
        return normalized

    @model_validator(mode="after")
    def _validate_references_and_topology(self) -> "CampaignRequirements":
        provenance_ids = [record.provenance_id for record in self.provenance]
        if len(provenance_ids) != len(set(provenance_ids)):
            raise ValueError("provenance_id values must be unique")
        provenance_id_set = set(provenance_ids)

        segment_ids = [segment.segment_id for segment in self.network_segments]
        if len(segment_ids) != len(set(segment_ids)):
            raise ValueError("network segment identifiers must be unique")
        segments = {
            segment.segment_id: ipaddress.IPv4Network(segment.cidr)
            for segment in self.network_segments
        }
        if any(not _is_rfc1918_network(segment) for segment in segments.values()):
            raise ValueError("network segments must use an RFC 1918 private IPv4 range")

        host_ids = [host.host_id for host in self.hosts]
        if len(host_ids) != len(set(host_ids)):
            raise ValueError("host identifiers must be unique")
        hostnames = [host.hostname for host in self.hosts]
        if len(hostnames) != len(set(hostnames)):
            raise ValueError("hostnames must be unique")
        host_id_set = set(host_ids)
        addresses: set[str] = set()
        for host in self.hosts:
            if host.network_segment_id not in segments:
                raise ValueError(f"host {host.host_id} references an unknown network segment")
            address = ipaddress.IPv4Address(host.ipv4_address)
            if not _is_rfc1918_address(address):
                raise ValueError(f"host {host.host_id} must use an RFC 1918 private IPv4 address")
            segment = segments[host.network_segment_id]
            if address not in segment or address in {
                segment.network_address,
                segment.broadcast_address,
            }:
                raise ValueError(
                    f"host {host.host_id} address must be a usable address in its segment"
                )
            if host.ipv4_address in addresses:
                raise ValueError("host IPv4 addresses must be unique")
            addresses.add(host.ipv4_address)

        for identity in self.identities:
            if identity.host_id not in host_id_set:
                raise ValueError(f"identity {identity.principal_id} references an unknown host")
            secret_reference = identity.runtime_secret_environment_variable
            if secret_reference is not None and not _ENVIRONMENT_VARIABLE_RE.fullmatch(
                secret_reference
            ):
                raise ValueError(
                    "runtime_secret_environment_variable must name an environment variable, not a secret"
                )
        principal_ids = [identity.principal_id for identity in self.identities]
        if len(principal_ids) != len(set(principal_ids)):
            raise ValueError("principal identifiers must be unique")
        principal_id_set = set(principal_ids)

        for exposure in self.network_exposures:
            if exposure.host_id not in host_id_set:
                raise ValueError(f"network exposure references unknown host {exposure.host_id}")
        for software in self.software_requirements:
            if software.host_id not in host_id_set:
                raise ValueError(f"software requirement references unknown host {software.host_id}")
        for privilege in self.privilege_requirements:
            if privilege.host_id not in host_id_set:
                raise ValueError(
                    f"privilege requirement {privilege.technique_id} references unknown host"
                )
            if privilege.principal_id not in principal_id_set:
                raise ValueError(
                    f"privilege requirement {privilege.technique_id} references unknown principal"
                )
        for procedure in self.procedure_requirements:
            missing_hosts = set(procedure.required_host_ids) - host_id_set
            missing_principals = set(procedure.required_principal_ids) - principal_id_set
            if missing_hosts:
                raise ValueError(f"procedure {procedure.technique_id} references unknown hosts")
            if missing_principals:
                raise ValueError(
                    f"procedure {procedure.technique_id} references unknown principals"
                )

        all_references: list[str] = []
        reference_lists = [
            *(item.provenance_refs for item in self.network_segments),
            *(item.provenance_refs for item in self.hosts),
            *(item.provenance_refs for item in self.identities),
            *(item.provenance_refs for item in self.network_exposures),
            *(item.provenance_refs for item in self.privilege_requirements),
            *(item.provenance_refs for item in self.software_requirements),
            *(item.provenance_refs for item in self.procedure_requirements),
            *(item.provenance_refs for item in self.unresolved_items),
        ]
        for references in reference_lists:
            all_references.extend(references)
        unknown_provenance = set(all_references) - provenance_id_set
        if unknown_provenance:
            raise ValueError("requirements reference undeclared provenance records")
        if PlatformFamily.WINDOWS in self.target_platforms and not any(
            host.platform is PlatformFamily.WINDOWS for host in self.hosts
        ):
            raise ValueError("a Windows target platform requires at least one Windows host")
        unresolved_ids = [item.item_id for item in self.unresolved_items]
        if len(unresolved_ids) != len(set(unresolved_ids)):
            raise ValueError("unresolved item identifiers must be unique")
        return self

    def canonical_payload(self) -> dict[str, object]:
        """Return a deterministic, secret-free representation suitable for hashing."""
        return cast(dict[str, object], self.model_dump(mode="json", exclude_none=True))

    def content_sha256(self) -> str:
        """Hash the canonical requirement payload without timestamps or runtime values."""
        encoded = json.dumps(
            self.canonical_payload(), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()
