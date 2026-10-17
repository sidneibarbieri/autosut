"""Campaign requirement DTO tests: provenance, private topology, and secret boundaries."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.planning.campaign_requirements import (  # noqa: E402
    CampaignRequirements,
    HostRequirement,
    IdentityModel,
    IdentityRequirement,
    NetworkSegmentRequirement,
    PlatformFamily,
    PrivilegeLevel,
    ProcedureRequirement,
    ProvenanceKind,
    RequirementProvenance,
)


def _provenance() -> list[RequirementProvenance]:
    return [
        RequirementProvenance(
            provenance_id="stix-plan",
            kind=ProvenanceKind.STIX,
            source_sha256="a" * 64,
            locator="relationship--example",
        ),
        RequirementProvenance(
            provenance_id="lab-policy",
            kind=ProvenanceKind.ANALYST_DECISION,
            source_sha256="b" * 64,
            locator="policy/windows-workgroup-v1",
        ),
    ]


def requirements_payload() -> dict:
    return {
        "campaign_id": "C-EXAMPLE",
        "source_bundle_sha256": "c" * 64,
        "target_platforms": [PlatformFamily.WINDOWS],
        "identity_model": IdentityModel.WORKGROUP,
        "network_segments": [
            NetworkSegmentRequirement(
                segment_id="labnet", cidr="192.168.56.0/24", provenance_refs=["lab-policy"]
            )
        ],
        "hosts": [
            HostRequirement(
                host_id="host-a",
                hostname="host-a",
                role="workstation",
                platform=PlatformFamily.WINDOWS,
                network_segment_id="labnet",
                ipv4_address="192.168.56.30",
                memory_mib=4096,
                cpus=2,
                provenance_refs=["lab-policy"],
            ),
            HostRequirement(
                host_id="host-b",
                hostname="host-b",
                role="peer-workstation",
                platform=PlatformFamily.WINDOWS,
                network_segment_id="labnet",
                ipv4_address="192.168.56.31",
                memory_mib=4096,
                cpus=2,
                provenance_refs=["lab-policy"],
            ),
        ],
        "identities": [
            IdentityRequirement(
                principal_id="host-a-admin",
                host_id="host-a",
                username="autosutadmin",
                privilege=PrivilegeLevel.LOCAL_ADMINISTRATOR,
                runtime_secret_environment_variable="AUTOSUT_WINDOWS_HOST_A_ADMIN_PASSWORD",
                purpose="provider administration",
                provenance_refs=["lab-policy"],
            ),
            IdentityRequirement(
                principal_id="host-b-admin",
                host_id="host-b",
                username="autosutadmin",
                privilege=PrivilegeLevel.LOCAL_ADMINISTRATOR,
                runtime_secret_environment_variable="AUTOSUT_WINDOWS_HOST_B_ADMIN_PASSWORD",
                purpose="provider administration",
                provenance_refs=["lab-policy"],
            ),
        ],
        "procedure_requirements": [
            ProcedureRequirement(
                technique_id="T1021.002",
                execution_domain="target",
                required_host_ids=["host-a", "host-b"],
                required_principal_ids=["host-a-admin"],
                evidence_predicates=["remote-service-session-observed"],
                provenance_refs=["stix-plan"],
            )
        ],
        "provenance": _provenance(),
    }


def test_valid_requirements_are_deterministically_hashable_and_secret_free() -> None:
    requirements = CampaignRequirements(**requirements_payload())

    assert (
        requirements.content_sha256()
        == CampaignRequirements(**requirements_payload()).content_sha256()
    )
    payload = requirements.canonical_payload()
    assert "AUTOSUT_WINDOWS_HOST_A_ADMIN_PASSWORD" in str(payload)
    assert "test-only-password" not in str(payload)


def test_unknown_provenance_reference_fails_closed() -> None:
    payload = requirements_payload()
    payload["hosts"][0] = payload["hosts"][0].model_copy(
        update={"provenance_refs": ["not-declared"]}
    )

    with pytest.raises(ValidationError, match="undeclared provenance"):
        CampaignRequirements(**payload)


def test_public_address_or_out_of_segment_address_is_rejected() -> None:
    payload = requirements_payload()
    payload["hosts"][0] = payload["hosts"][0].model_copy(update={"ipv4_address": "8.8.8.8"})

    with pytest.raises(ValidationError, match="RFC 1918"):
        CampaignRequirements(**payload)


def test_loopback_is_not_accepted_as_an_rfc1918_laboratory_network() -> None:
    payload = requirements_payload()
    payload["network_segments"][0] = payload["network_segments"][0].model_copy(
        update={"cidr": "127.0.0.0/24"}
    )
    payload["hosts"][0] = payload["hosts"][0].model_copy(update={"ipv4_address": "127.0.0.30"})
    payload["hosts"][1] = payload["hosts"][1].model_copy(update={"ipv4_address": "127.0.0.31"})

    with pytest.raises(ValidationError, match="RFC 1918"):
        CampaignRequirements(**payload)


def test_secret_reference_must_be_an_environment_variable_name() -> None:
    payload = requirements_payload()
    payload["identities"][0] = payload["identities"][0].model_copy(
        update={"runtime_secret_environment_variable": "password=not-a-reference"}
    )

    with pytest.raises(ValidationError, match="environment variable"):
        CampaignRequirements(**payload)
