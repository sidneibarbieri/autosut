#!/usr/bin/env python3
"""Additional executors for expanded campaign/SUT coverage."""

from __future__ import annotations

import hashlib
import shutil
import socket
import subprocess
import tarfile
import threading
import urllib.request
from dataclasses import dataclass
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable, List, Tuple

from .campaign_expansion_executors import (
    _bounded_collection_files,
    _campaign_dir,
    _ensure_collection_archive,
    _write_json,
)
from .executor_registry import (
    ExecutionFidelity,
    ExecutionMode,
    ExecutorMetadata,
    register_executor,
    registry,
)
from .fox_kitten_real import execute_t1071_001_inspired

ExecutionResult = Tuple[bool, str, str, List[str]]


def _write_text(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def _record_manifest(
    campaign_id: str,
    filename: str,
    payload: dict,
) -> Path:
    manifest_path = _campaign_dir(campaign_id) / filename
    _write_json(manifest_path, payload)
    return manifest_path


def _seed_collection_files(campaign_id: str) -> List[Path]:
    source_files = list(_bounded_collection_files(campaign_id))
    campaign_dir = _campaign_dir(campaign_id)

    if campaign_id == "0.apt41_dust":
        source_files.append(
            _write_text(
                campaign_dir / "bounded_collection" / "mysql_customer_dump.sql",
                (
                    "CREATE TABLE customer_finance "
                    "(entity TEXT, amount INTEGER, closed_at TEXT);\n"
                    "INSERT INTO customer_finance VALUES "
                    "('Alpha Corp',125000,'2024-01-15');\n"
                    "INSERT INTO customer_finance VALUES "
                    "('Beta Ltd',87500,'2024-02-03');\n"
                ),
            )
        )
    elif campaign_id == "0.operation_midnighteclipse":
        source_files.append(
            _write_text(
                campaign_dir / "bounded_collection" / "partner_registry.csv",
                (
                    "partner_id,name,region\n"
                    "5001,Helios Transit,NA\n"
                    "5002,Polar Freight,EMEA\n"
                    "5003,Atlas Marine,APAC\n"
                ),
            )
        )
    elif campaign_id == "0.salesforce_data_exfiltration":
        source_files.extend(
            [
                _write_text(
                    campaign_dir / "bounded_collection" / "crm_accounts.csv",
                    (
                        "account_id,name,region,owner\n"
                        "1001,Northwind Logistics,NA,alice\n"
                        "1002,Blue Solar,EMEA,bob\n"
                        "1003,River Analytics,APAC,carol\n"
                    ),
                ),
                _write_text(
                    campaign_dir / "bounded_collection" / "crm_opportunities.txt",
                    (
                        "Q2 pipeline summary\n"
                        "- Northwind Logistics renewal: $125000\n"
                        "- Blue Solar expansion: $98000\n"
                        "- River Analytics migration: $143000\n"
                    ),
                ),
            ]
        )

    return source_files


def _create_archive(
    archive_path: Path,
    source_files: List[Path],
) -> Path:
    archive_path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive_path, "w:gz") as archive:
        for source_file in source_files:
            archive.add(source_file, arcname=source_file.name)
    return archive_path


def _ensure_staged_archive(
    campaign_id: str,
    archive_name: str,
) -> Tuple[Path, List[Path]]:
    source_files = _seed_collection_files(campaign_id)
    archive_path = _create_archive(_campaign_dir(campaign_id) / archive_name, source_files)
    return archive_path, source_files


def _generate_rsa_material(
    output_dir: Path,
    basename: str,
) -> Tuple[Path, Path]:
    private_key = output_dir / f"{basename}.key.pem"
    public_key = output_dir / f"{basename}.pub.pem"
    subprocess.run(
        [
            "openssl",
            "genpkey",
            "-algorithm",
            "RSA",
            "-out",
            str(private_key),
            "-pkeyopt",
            "rsa_keygen_bits:2048",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    subprocess.run(
        [
            "openssl",
            "rsa",
            "-pubout",
            "-in",
            str(private_key),
            "-out",
            str(public_key),
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    return private_key, public_key


def _generate_code_signing_material(
    campaign_id: str,
) -> Tuple[Path, Path]:
    campaign_dir = _campaign_dir(campaign_id)
    private_key = campaign_dir / "code_signing.key.pem"
    certificate = campaign_dir / "code_signing.crt.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            str(private_key),
            "-out",
            str(certificate),
            "-nodes",
            "-days",
            "30",
            "-subj",
            "/CN=autosut-signing.local",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    return private_key, certificate


def _write_capability_manifest(
    campaign_id: str,
    technique_id: str,
    technique_name: str,
    category: str,
    details: dict,
) -> ExecutionResult:
    manifest_path = _record_manifest(
        campaign_id,
        f"{technique_id.replace('.', '_').lower()}_manifest.json",
        {
            "campaign_id": campaign_id,
            "technique_id": technique_id,
            "technique_name": technique_name,
            "category": category,
            "details": details,
            "timestamp": datetime.now().isoformat(),
        },
    )
    return True, f"{technique_id} manifest created", "", [str(manifest_path)]


@dataclass(frozen=True)
class ManifestExecutorSpec:
    technique_id: str
    technique_name: str
    execution_mode: ExecutionMode
    execution_fidelity: ExecutionFidelity
    produces: List[str]
    requires: List[str]
    description: str
    fidelity_justification: str
    original_platform: str
    platform: str = "linux"
    requires_privilege: str = "user"
    category: str = "bounded_manifest"
    detail_factory: Callable[[str, str], dict] | None = None


def _register_manifest_executor(
    spec: ManifestExecutorSpec,
) -> None:
    def execute_manifest(
        campaign_id: str,
        sut_profile_id: str,
        **kwargs,
    ) -> ExecutionResult:
        details = (
            spec.detail_factory(campaign_id, sut_profile_id)
            if spec.detail_factory
            else {}
        )
        return _write_capability_manifest(
            campaign_id=campaign_id,
            technique_id=spec.technique_id,
            technique_name=spec.technique_name,
            category=spec.category,
            details=details,
        )

    registry.register(
        spec.technique_id,
        ExecutorMetadata(
            technique_id=spec.technique_id,
            technique_name=spec.technique_name,
            execution_mode=spec.execution_mode,
            produces=spec.produces,
            requires=spec.requires,
            safe_simulation=True,
            cleanup_supported=True,
            description=spec.description,
            platform=spec.platform,
            execution_fidelity=spec.execution_fidelity,
            fidelity_justification=spec.fidelity_justification,
            original_platform=spec.original_platform,
            requires_privilege=spec.requires_privilege,
        ),
        execute_manifest,
    )


def _resource_details(label: str) -> Callable[[str, str], dict]:
    def build_details(campaign_id: str, sut_profile_id: str) -> dict:
        return {
            "campaign_label": label,
            "sut_profile_id": sut_profile_id,
        }

    return build_details


for _spec in [
    ManifestExecutorSpec(
        technique_id="T1078",
        technique_name="Valid Accounts",
        execution_mode=ExecutionMode.REAL_CONTROLLED,
        execution_fidelity=ExecutionFidelity.ADAPTED,
        produces=["access:initial"],
        requires=["network:ssh_available"],
        description="Record bounded valid-account access for the MidnightEclipse substrate",
        fidelity_justification=(
            "T1078 abuses valid credentials. This execution materializes a bounded "
            "access record using local lab credentials rather than compromised "
            "production identities."
        ),
        original_platform="any",
        category="access_session",
        detail_factory=_resource_details("bounded_valid_account"),
    ),
    ManifestExecutorSpec(
        technique_id="T1078.002",
        technique_name="Domain Accounts",
        execution_mode=ExecutionMode.NAIVE_SIMULATED,
        execution_fidelity=ExecutionFidelity.INSPIRED,
        produces=["access:domain_identity"],
        requires=["network:ssh_available"],
        description="Create a bounded domain-account access manifest",
        fidelity_justification=(
            "T1078.002 depends on domain infrastructure. This execution records a "
            "controlled domain-style credential use case without requiring live AD services."
        ),
        original_platform="windows",
        category="identity_manifest",
        detail_factory=_resource_details("domain_account_reuse"),
    ),
    ManifestExecutorSpec(
        technique_id="T1021.002",
        technique_name="SMB/Windows Admin Shares",
        execution_mode=ExecutionMode.NAIVE_SIMULATED,
        execution_fidelity=ExecutionFidelity.INSPIRED,
        produces=["access:lateral_share"],
        requires=["access:initial"],
        description="Record a bounded SMB admin-share movement manifest",
        fidelity_justification=(
            "T1021.002 depends on Windows admin shares. This execution preserves "
            "the lateral-movement intent while representing the remote share action "
            "as an audit artifact."
        ),
        original_platform="windows",
        category="lateral_movement",
        detail_factory=_resource_details("admin_share_pivot"),
    ),
    ManifestExecutorSpec(
        technique_id="T1021.006",
        technique_name="Windows Remote Management",
        execution_mode=ExecutionMode.NAIVE_SIMULATED,
        execution_fidelity=ExecutionFidelity.INSPIRED,
        produces=["access:lateral_winrm"],
        requires=["access:initial"],
        description="Record a bounded WinRM lateral-movement manifest",
        fidelity_justification=(
            "T1021.006 requires Windows Remote Management. This execution captures "
            "the remote-management intent in a bounded manifest instead of claiming "
            "a live WinRM session."
        ),
        original_platform="windows",
        category="lateral_movement",
        detail_factory=_resource_details("winrm_session"),
    ),
    ManifestExecutorSpec(
        technique_id="T1583.007",
        technique_name="Serverless",
        execution_mode=ExecutionMode.NAIVE_SIMULATED,
        execution_fidelity=ExecutionFidelity.INSPIRED,
        produces=["resources:serverless_plan"],
        requires=[],
        description="Create a serverless infrastructure planning manifest",
        fidelity_justification=(
            "T1583.007 concerns serverless infrastructure acquisition. This execution "
            "preserves the planning step without provisioning external cloud resources."
        ),
        original_platform="pre",
        category="resource_development",
        detail_factory=_resource_details("serverless_acquisition"),
    ),
    ManifestExecutorSpec(
        technique_id="T1584.003",
        technique_name="Virtual Private Server",
        execution_mode=ExecutionMode.NAIVE_SIMULATED,
        execution_fidelity=ExecutionFidelity.INSPIRED,
        produces=["resources:vps_plan"],
        requires=[],
        description="Create a VPS compromise manifest",
        fidelity_justification=(
            "T1584.003 involves compromising VPS infrastructure. This execution "
            "records the infrastructure intent without touching an external VPS provider."
        ),
        original_platform="pre",
        category="resource_development",
        detail_factory=_resource_details("vps_compromise"),
    ),
    ManifestExecutorSpec(
        technique_id="T1584.006",
        technique_name="Web Services",
        execution_mode=ExecutionMode.NAIVE_SIMULATED,
        execution_fidelity=ExecutionFidelity.INSPIRED,
        produces=["resources:web_service_plan"],
        requires=[],
        description="Create a compromised web-service manifest",
        fidelity_justification=(
            "T1584.006 depends on external web services. This execution captures "
            "the web-service compromise intent as a bounded manifest."
        ),
        original_platform="pre",
        category="resource_development",
        detail_factory=_resource_details("web_service_compromise"),
    ),
    ManifestExecutorSpec(
        technique_id="T1585",
        technique_name="Establish Accounts",
        execution_mode=ExecutionMode.NAIVE_SIMULATED,
        execution_fidelity=ExecutionFidelity.INSPIRED,
        produces=["resources:account_plan"],
        requires=[],
        description="Create an account-establishment manifest",
        fidelity_justification=(
            "T1585 establishes external accounts. This execution preserves that "
            "planning step without creating real third-party accounts."
        ),
        original_platform="pre",
        category="resource_development",
        detail_factory=_resource_details("account_establishment"),
    ),
    ManifestExecutorSpec(
        technique_id="T1585.002",
        technique_name="Email Accounts",
        execution_mode=ExecutionMode.NAIVE_SIMULATED,
        execution_fidelity=ExecutionFidelity.INSPIRED,
        produces=["resources:email_account_plan"],
        requires=[],
        description="Create an email-account establishment manifest",
        fidelity_justification=(
            "T1585.002 creates external email accounts. This execution records the "
            "account-establishment intent without provisioning a live mailbox."
        ),
        original_platform="pre",
        category="resource_development",
        detail_factory=_resource_details("email_account_establishment"),
    ),
    ManifestExecutorSpec(
        technique_id="T1586.002",
        technique_name="Email Accounts",
        execution_mode=ExecutionMode.NAIVE_SIMULATED,
        execution_fidelity=ExecutionFidelity.INSPIRED,
        produces=["access:email_account_compromise"],
        requires=[],
        description="Create an email-account compromise manifest",
        fidelity_justification=(
            "T1586.002 compromises email accounts. This execution captures the "
            "resource-development intent as a bounded compromise record."
        ),
        original_platform="pre",
        category="resource_development",
        detail_factory=_resource_details("email_account_compromise"),
    ),
    ManifestExecutorSpec(
        technique_id="T1586.003",
        technique_name="Cloud Accounts",
        execution_mode=ExecutionMode.NAIVE_SIMULATED,
        execution_fidelity=ExecutionFidelity.INSPIRED,
        produces=["access:cloud_account_compromise"],
        requires=[],
        description="Create a cloud-account compromise manifest",
        fidelity_justification=(
            "T1586.003 compromises cloud accounts. This execution preserves the "
            "account-compromise planning step without accessing a live cloud tenant."
        ),
        original_platform="pre",
        category="resource_development",
        detail_factory=_resource_details("cloud_account_compromise"),
    ),
    ManifestExecutorSpec(
        technique_id="T1593.002",
        technique_name="Search Engines",
        execution_mode=ExecutionMode.NAIVE_SIMULATED,
        execution_fidelity=ExecutionFidelity.INSPIRED,
        produces=["recon:search_results"],
        requires=[],
        description="Create a search-engine reconnaissance manifest",
        fidelity_justification=(
            "T1593.002 uses search engines for recon. This execution records bounded "
            "search findings rather than issuing uncontrolled internet queries."
        ),
        original_platform="pre",
        category="reconnaissance",
        detail_factory=_resource_details("search_engine_recon"),
    ),
    ManifestExecutorSpec(
        technique_id="T1594",
        technique_name="Search Victim-Owned Websites",
        execution_mode=ExecutionMode.NAIVE_SIMULATED,
        execution_fidelity=ExecutionFidelity.INSPIRED,
        produces=["recon:victim_web_inventory"],
        requires=["recon:search_results"],
        description="Create a victim-website reconnaissance manifest",
        fidelity_justification=(
            "T1594 inspects victim-owned websites. This execution captures the "
            "website reconnaissance output as a bounded manifest."
        ),
        original_platform="pre",
        category="reconnaissance",
        detail_factory=_resource_details("victim_website_recon"),
    ),
    ManifestExecutorSpec(
        technique_id="T1596.005",
        technique_name="Scan Databases",
        execution_mode=ExecutionMode.NAIVE_SIMULATED,
        execution_fidelity=ExecutionFidelity.INSPIRED,
        produces=["recon:database_inventory"],
        requires=[],
        description="Create a database-scan reconnaissance manifest",
        fidelity_justification=(
            "T1596.005 scans exposed databases. This execution preserves the recon "
            "intent while constraining results to bounded lab metadata."
        ),
        original_platform="pre",
        category="reconnaissance",
        detail_factory=_resource_details("database_surface_scan"),
    ),
    ManifestExecutorSpec(
        technique_id="T1598.004",
        technique_name="Spearphishing Voice",
        execution_mode=ExecutionMode.NAIVE_SIMULATED,
        execution_fidelity=ExecutionFidelity.INSPIRED,
        produces=["recon:voice_pretext"],
        requires=[],
        description="Create a vishing pretext manifest",
        fidelity_justification=(
            "T1598.004 involves voice phishing. This execution records the pretext "
            "and target notes without placing real calls."
        ),
        original_platform="pre",
        category="reconnaissance",
        detail_factory=_resource_details("voice_phishing_pretext"),
    ),
    ManifestExecutorSpec(
        technique_id="T1608.005",
        technique_name="Link Target",
        execution_mode=ExecutionMode.REAL_CONTROLLED,
        execution_fidelity=ExecutionFidelity.ADAPTED,
        produces=["resources:delivery_link"],
        requires=["resources:staging_directory"],
        description="Create a bounded delivery-link staging manifest",
        fidelity_justification=(
            "T1608.005 stages delivery links. This execution materializes a bounded "
            "link-delivery record without distributing a live lure."
        ),
        original_platform="pre",
        category="resource_development",
        detail_factory=_resource_details("delivery_link_staging"),
    ),
    ManifestExecutorSpec(
        technique_id="T1656",
        technique_name="Impersonation",
        execution_mode=ExecutionMode.NAIVE_SIMULATED,
        execution_fidelity=ExecutionFidelity.INSPIRED,
        produces=["defense_evasion:impersonation"],
        requires=["access:initial"],
        description="Create a bounded impersonation manifest",
        fidelity_justification=(
            "T1656 impersonates users or services. This execution preserves the "
            "intent through a bounded session manifest rather than claiming a real impersonation boundary bypass."
        ),
        original_platform="any",
        category="defense_evasion",
        detail_factory=_resource_details("impersonation_session"),
    ),
    ManifestExecutorSpec(
        technique_id="T1671",
        technique_name="Cloud Application Integration",
        execution_mode=ExecutionMode.NAIVE_SIMULATED,
        execution_fidelity=ExecutionFidelity.INSPIRED,
        produces=["persistence:cloud_integration"],
        requires=["resources:delivery_link"],
        description="Create a bounded cloud-integration manifest",
        fidelity_justification=(
            "T1671 depends on SaaS or cloud application integrations. This execution "
            "captures the persistence intent as a bounded integration record."
        ),
        original_platform="saas",
        category="persistence",
        detail_factory=_resource_details("cloud_app_integration"),
    ),
]:
    _register_manifest_executor(_spec)


@register_executor(
    technique_id="T1071.001",
    metadata=ExecutorMetadata(
        technique_id="T1071.001",
        technique_name="Application Layer Protocol: Web Protocols",
        execution_mode=ExecutionMode.NAIVE_SIMULATED,
        produces=["c2:http_channel", "c2_channel"],
        requires=[],
        safe_simulation=True,
        cleanup_supported=True,
        description="HTTP protocol simulation with a generic C2 capability for cross-step auditability",
        platform="linux",
        execution_fidelity=ExecutionFidelity.INSPIRED,
        fidelity_justification=(
            "Real C2 over HTTP still requires external infrastructure. This executor "
            "keeps the existing inspired simulation but also emits a generic "
            "c2_channel capability so downstream transfer steps can be audited consistently."
        ),
        original_platform="multi",
        requires_privilege="user",
    ),
    overwrite=True,
)
def execute_t1071_001_parity(
    campaign_id: str,
    sut_profile_id: str,
    **kwargs,
) -> ExecutionResult:
    return execute_t1071_001_inspired(campaign_id, sut_profile_id, **kwargs)


@register_executor(
    technique_id="T1090",
    metadata=ExecutorMetadata(
        technique_id="T1090",
        technique_name="Proxy",
        execution_mode=ExecutionMode.NAIVE_SIMULATED,
        produces=["c2:proxy_channel"],
        requires=[],
        safe_simulation=True,
        cleanup_supported=True,
        description="Record a bounded proxy channel instead of requiring live relay tooling",
        platform="linux",
        execution_fidelity=ExecutionFidelity.INSPIRED,
        fidelity_justification=(
            "T1090 requires relay infrastructure. This executor preserves the proxying "
            "claim as a bounded manifest so reviewers do not depend on optional host tooling."
        ),
        original_platform="multi",
        requires_privilege="user",
    ),
    overwrite=True,
)
def execute_t1090_parity(
    campaign_id: str,
    sut_profile_id: str,
    **kwargs,
) -> ExecutionResult:
    return _write_capability_manifest(
        campaign_id=campaign_id,
        technique_id="T1090",
        technique_name="Proxy",
        category="command_and_control",
        details={
            "proxy_type": "bounded_local_proxy_plan",
            "sut_profile_id": sut_profile_id,
        },
    )


@register_executor(
    technique_id="T1090.003",
    metadata=ExecutorMetadata(
        technique_id="T1090.003",
        technique_name="Multi-hop Proxy",
        execution_mode=ExecutionMode.NAIVE_SIMULATED,
        produces=["network:proxied_channel"],
        requires=["network:http_available"],
        safe_simulation=True,
        cleanup_supported=True,
        description="Record a bounded multi-hop proxy route",
        platform="linux",
        execution_fidelity=ExecutionFidelity.INSPIRED,
        fidelity_justification=(
            "T1090.003 requires multi-hop relay infrastructure. This executor records "
            "the routing intent as a bounded manifest instead of claiming live chained proxies."
        ),
        original_platform="multi",
        requires_privilege="user",
    ),
    overwrite=True,
)
def execute_t1090_003_parity(
    campaign_id: str,
    sut_profile_id: str,
    **kwargs,
) -> ExecutionResult:
    return _write_capability_manifest(
        campaign_id=campaign_id,
        technique_id="T1090.003",
        technique_name="Multi-hop Proxy",
        category="command_and_control",
        details={
            "proxy_hops": ["mullvad-egress", "tor-exit"],
            "sut_profile_id": sut_profile_id,
        },
    )


@register_executor(
    technique_id="T1005",
    metadata=ExecutorMetadata(
        technique_id="T1005",
        technique_name="Data from Local System",
        execution_mode=ExecutionMode.REAL_CONTROLLED,
        produces=["discovery:file_listing", "collection:local_data"],
        requires=["code_execution"],
        safe_simulation=True,
        cleanup_supported=True,
        description="Collect bounded local campaign data into a reviewable bundle",
        platform="linux",
        execution_fidelity=ExecutionFidelity.ADAPTED,
        fidelity_justification=(
            "T1005 collects local data. This execution gathers bounded campaign "
            "documents from the published substrate without touching uncontrolled files."
        ),
        original_platform="any",
        requires_privilege="user",
    ),
    overwrite=True,
)
def execute_t1005_real(
    campaign_id: str,
    sut_profile_id: str,
    **kwargs,
) -> ExecutionResult:
    source_files = _seed_collection_files(campaign_id)
    manifest_path = _record_manifest(
        campaign_id,
        "local_data_collection.json",
        {
            "campaign_id": campaign_id,
            "sources": [str(path) for path in source_files],
            "timestamp": datetime.now().isoformat(),
        },
    )
    artifacts = [str(manifest_path)] + [str(path) for path in source_files]
    return True, "Bounded local data collected", "", artifacts


@register_executor(
    technique_id="T1074.001",
    metadata=ExecutorMetadata(
        technique_id="T1074.001",
        technique_name="Local Data Staging",
        execution_mode=ExecutionMode.REAL_CONTROLLED,
        produces=["collection:archive", "collection:staged_local_data"],
        requires=["collection:local_data"],
        safe_simulation=True,
        cleanup_supported=True,
        description="Stage bounded local data into a compressed archive",
        platform="linux",
        execution_fidelity=ExecutionFidelity.ADAPTED,
        fidelity_justification=(
            "T1074.001 stages data locally. This execution copies bounded source files "
            "into a local staging directory and produces a real archive."
        ),
        original_platform="any",
        requires_privilege="user",
    ),
)
def execute_t1074_001_real(
    campaign_id: str,
    sut_profile_id: str,
    **kwargs,
) -> ExecutionResult:
    source_files = _seed_collection_files(campaign_id)
    stage_dir = _campaign_dir(campaign_id) / "local_stage"
    stage_dir.mkdir(parents=True, exist_ok=True)
    staged_files: List[str] = []
    for source_file in source_files:
        staged_path = stage_dir / source_file.name
        shutil.copy2(source_file, staged_path)
        staged_files.append(str(staged_path))
    archive_path = _create_archive(stage_dir / "staged_collection.tar.gz", list(stage_dir.iterdir()))
    manifest_path = _record_manifest(
        campaign_id,
        "local_staging_manifest.json",
        {
            "campaign_id": campaign_id,
            "staged_files": staged_files,
            "archive": str(archive_path),
            "timestamp": datetime.now().isoformat(),
        },
    )
    return True, "Local data staging completed", "", staged_files + [str(archive_path), str(manifest_path)]


@register_executor(
    technique_id="T1213.004",
    metadata=ExecutorMetadata(
        technique_id="T1213.004",
        technique_name="Customer Relationship Management Software",
        execution_mode=ExecutionMode.REAL_CONTROLLED,
        produces=["discovery:file_listing", "collection:local_data", "collection:archive"],
        requires=["code_execution"],
        safe_simulation=True,
        cleanup_supported=True,
        description="Export bounded CRM-like data into a reviewable archive",
        platform="linux",
        execution_fidelity=ExecutionFidelity.ADAPTED,
        fidelity_justification=(
            "T1213.004 targets CRM data. This execution materializes bounded CRM exports "
            "and archives them locally instead of replaying against a live SaaS tenant."
        ),
        original_platform="saas",
        requires_privilege="user",
    ),
)
def execute_t1213_004_real(
    campaign_id: str,
    sut_profile_id: str,
    **kwargs,
) -> ExecutionResult:
    archive_path, source_files = _ensure_staged_archive(campaign_id, "crm_export_bundle.tar.gz")
    manifest_path = _record_manifest(
        campaign_id,
        "crm_export_manifest.json",
        {
            "campaign_id": campaign_id,
            "archive": str(archive_path),
            "sources": [str(path) for path in source_files],
            "timestamp": datetime.now().isoformat(),
        },
    )
    artifacts = [str(archive_path), str(manifest_path)] + [str(path) for path in source_files]
    return True, "Bounded CRM export archived", "", artifacts


@register_executor(
    technique_id="T1213.006",
    metadata=ExecutorMetadata(
        technique_id="T1213.006",
        technique_name="Databases",
        execution_mode=ExecutionMode.REAL_CONTROLLED,
        produces=["discovery:file_listing", "collection:local_data"],
        requires=["code_execution"],
        safe_simulation=True,
        cleanup_supported=True,
        description="Create a bounded database-export artifact",
        platform="linux",
        execution_fidelity=ExecutionFidelity.ADAPTED,
        fidelity_justification=(
            "T1213.006 collects database content. This execution creates a bounded "
            "database dump artifact that preserves collection intent without touching a live DBMS."
        ),
        original_platform="any",
        requires_privilege="user",
    ),
)
def execute_t1213_006_real(
    campaign_id: str,
    sut_profile_id: str,
    **kwargs,
) -> ExecutionResult:
    source_files = _seed_collection_files(campaign_id)
    manifest_path = _record_manifest(
        campaign_id,
        "database_collection_manifest.json",
        {
            "campaign_id": campaign_id,
            "database_exports": [str(path) for path in source_files if path.suffix in {".sql", ".csv", ".txt"}],
            "timestamp": datetime.now().isoformat(),
        },
    )
    artifacts = [str(manifest_path)] + [str(path) for path in source_files]
    return True, "Bounded database content collected", "", artifacts


@register_executor(
    technique_id="T1505.003",
    metadata=ExecutorMetadata(
        technique_id="T1505.003",
        technique_name="Web Shell",
        execution_mode=ExecutionMode.REAL_CONTROLLED,
        produces=["persistence:webshell"],
        requires=["access:initial"],
        safe_simulation=True,
        cleanup_supported=True,
        description="Stage a benign web-shell artifact in a bounded web root",
        platform="linux",
        execution_fidelity=ExecutionFidelity.ADAPTED,
        fidelity_justification=(
            "T1505.003 places a web shell in server software. This execution stages "
            "a benign PHP-like artifact in a bounded directory without exposing a live shell."
        ),
        original_platform="multi",
        requires_privilege="user",
    ),
)
def execute_t1505_003_real(
    campaign_id: str,
    sut_profile_id: str,
    **kwargs,
) -> ExecutionResult:
    web_root = _campaign_dir(campaign_id) / "bounded_web_root"
    web_root.mkdir(parents=True, exist_ok=True)
    web_shell = _write_text(
        web_root / "healthcheck.php",
        "<?php echo 'bounded_web_shell'; ?>\n",
    )
    evidence = _record_manifest(
        campaign_id,
        "web_shell_manifest.json",
        {
            "campaign_id": campaign_id,
            "path": str(web_shell),
            "timestamp": datetime.now().isoformat(),
        },
    )
    return True, "Benign web-shell artifact staged", "", [str(web_shell), str(evidence)]


@register_executor(
    technique_id="T1543.003",
    metadata=ExecutorMetadata(
        technique_id="T1543.003",
        technique_name="Windows Service",
        execution_mode=ExecutionMode.REAL_CONTROLLED,
        produces=["persistence:service"],
        requires=["code_execution"],
        safe_simulation=True,
        cleanup_supported=True,
        description="Stage a bounded service definition using a Linux systemd analog",
        platform="linux",
        execution_fidelity=ExecutionFidelity.ADAPTED,
        fidelity_justification=(
            "T1543.003 is Windows-specific. This execution preserves the persistence "
            "mechanism by staging a benign systemd unit as the Linux substrate analog."
        ),
        original_platform="windows",
        requires_privilege="user",
    ),
)
def execute_t1543_003_real(
    campaign_id: str,
    sut_profile_id: str,
    **kwargs,
) -> ExecutionResult:
    campaign_dir = _campaign_dir(campaign_id)
    service_script = _write_text(
        campaign_dir / "service_payload.sh",
        "#!/bin/sh\necho sticks_service_payload >> service_payload.log\n",
    )
    service_script.chmod(0o755)
    service_unit = _write_text(
        campaign_dir / "sticks-bounded.service",
        (
            "[Unit]\nDescription=STICKS bounded service\n\n"
            "[Service]\nType=oneshot\n"
            f"ExecStart={service_script}\n\n"
            "[Install]\nWantedBy=multi-user.target\n"
        ),
    )
    manifest = _record_manifest(
        campaign_id,
        "service_persistence_manifest.json",
        {
            "campaign_id": campaign_id,
            "unit_file": str(service_unit),
            "payload": str(service_script),
            "timestamp": datetime.now().isoformat(),
        },
    )
    return True, "Bounded service persistence staged", "", [str(service_unit), str(service_script), str(manifest)]


@register_executor(
    technique_id="T1569.002",
    metadata=ExecutorMetadata(
        technique_id="T1569.002",
        technique_name="Service Execution",
        execution_mode=ExecutionMode.REAL_CONTROLLED,
        produces=["execution:service_payload"],
        requires=["persistence:service"],
        safe_simulation=True,
        cleanup_supported=True,
        description="Execute a bounded service payload locally",
        platform="linux",
        execution_fidelity=ExecutionFidelity.ADAPTED,
        fidelity_justification=(
            "T1569.002 executes a service. This execution runs a benign local service "
            "payload derived from the staged systemd analog."
        ),
        original_platform="windows",
        requires_privilege="user",
    ),
)
def execute_t1569_002_real(
    campaign_id: str,
    sut_profile_id: str,
    **kwargs,
) -> ExecutionResult:
    execute_t1543_003_real(campaign_id, sut_profile_id, **kwargs)
    service_script = _campaign_dir(campaign_id) / "service_payload.sh"
    result = subprocess.run(
        [str(service_script)],
        capture_output=True,
        text=True,
        check=True,
    )
    execution_log = _write_text(
        _campaign_dir(campaign_id) / "service_execution.log",
        result.stdout or "sticks_service_payload\n",
    )
    return True, "Bounded service payload executed", result.stderr, [str(service_script), str(execution_log)]


@register_executor(
    technique_id="T1036",
    metadata=ExecutorMetadata(
        technique_id="T1036",
        technique_name="Masquerading",
        execution_mode=ExecutionMode.REAL_CONTROLLED,
        produces=["defense_evasion:masqueraded_artifact"],
        requires=["code_execution"],
        safe_simulation=True,
        cleanup_supported=True,
        description="Create a benign artifact under a misleading filename",
        platform="linux",
        execution_fidelity=ExecutionFidelity.ADAPTED,
        fidelity_justification=(
            "T1036 disguises malicious artifacts. This execution preserves the "
            "misleading naming behavior using a bounded local file."
        ),
        original_platform="any",
        requires_privilege="user",
    ),
)
def execute_t1036_real(
    campaign_id: str,
    sut_profile_id: str,
    **kwargs,
) -> ExecutionResult:
    campaign_dir = _campaign_dir(campaign_id)
    source_file = _write_text(campaign_dir / "audit.log", "bounded audit content\n")
    masqueraded_file = campaign_dir / "quarterly_report.pdf"
    shutil.copy2(source_file, masqueraded_file)
    manifest = _record_manifest(
        campaign_id,
        "masquerading_manifest.json",
        {
            "source": str(source_file),
            "masqueraded": str(masqueraded_file),
            "timestamp": datetime.now().isoformat(),
        },
    )
    return True, "Masqueraded artifact created", "", [str(source_file), str(masqueraded_file), str(manifest)]


@register_executor(
    technique_id="T1036.004",
    metadata=ExecutorMetadata(
        technique_id="T1036.004",
        technique_name="Masquerade Task or Service",
        execution_mode=ExecutionMode.REAL_CONTROLLED,
        produces=["defense_evasion:masqueraded_service"],
        requires=["code_execution"],
        safe_simulation=True,
        cleanup_supported=True,
        description="Create a benign service-like artifact under a trusted name",
        platform="linux",
        execution_fidelity=ExecutionFidelity.ADAPTED,
        fidelity_justification=(
            "T1036.004 disguises tasks or services. This execution stages a benign "
            "service artifact with a trusted-looking name."
        ),
        original_platform="any",
        requires_privilege="user",
    ),
)
def execute_t1036_004_real(
    campaign_id: str,
    sut_profile_id: str,
    **kwargs,
) -> ExecutionResult:
    service_path = _write_text(
        _campaign_dir(campaign_id) / "system-healthd.service",
        (
            "[Unit]\nDescription=System Health Monitor\n\n"
            "[Service]\nType=oneshot\nExecStart=/bin/true\n"
        ),
    )
    manifest = _record_manifest(
        campaign_id,
        "masqueraded_service_manifest.json",
        {
            "service_path": str(service_path),
            "timestamp": datetime.now().isoformat(),
        },
    )
    return True, "Masqueraded service artifact created", "", [str(service_path), str(manifest)]


@register_executor(
    technique_id="T1053.003",
    metadata=ExecutorMetadata(
        technique_id="T1053.003",
        technique_name="Cron",
        execution_mode=ExecutionMode.REAL_CONTROLLED,
        produces=["persistence:scheduled_task"],
        requires=["code_execution"],
        safe_simulation=True,
        cleanup_supported=True,
        description="Stage a benign cron-style persistence entry",
        platform="linux",
        execution_fidelity=ExecutionFidelity.ADAPTED,
        fidelity_justification=(
            "T1053.003 uses cron for persistence or execution. This execution creates "
            "a bounded cron entry and payload script inside the artifact workspace."
        ),
        original_platform="linux",
        requires_privilege="user",
    ),
)
def execute_t1053_003_real(
    campaign_id: str,
    sut_profile_id: str,
    **kwargs,
) -> ExecutionResult:
    campaign_dir = _campaign_dir(campaign_id)
    cron_script = _write_text(
        campaign_dir / "cron_payload.sh",
        "#!/bin/sh\necho cron_payload_executed >> cron_payload.log\n",
    )
    cron_script.chmod(0o755)
    cron_file = _write_text(
        campaign_dir / "cron.tab",
        f"*/15 * * * * {cron_script}\n",
    )
    manifest = _record_manifest(
        campaign_id,
        "cron_manifest.json",
        {
            "cron_file": str(cron_file),
            "payload": str(cron_script),
            "timestamp": datetime.now().isoformat(),
        },
    )
    return True, "Bounded cron persistence staged", "", [str(cron_file), str(cron_script), str(manifest)]


@register_executor(
    technique_id="T1070.004",
    metadata=ExecutorMetadata(
        technique_id="T1070.004",
        technique_name="File Deletion",
        execution_mode=ExecutionMode.REAL_CONTROLLED,
        produces=["defense_evasion:file_cleanup"],
        requires=["code_execution"],
        safe_simulation=True,
        cleanup_supported=True,
        description="Delete a bounded artifact and record its prior checksum",
        platform="linux",
        execution_fidelity=ExecutionFidelity.ADAPTED,
        fidelity_justification=(
            "T1070.004 deletes files to reduce forensic visibility. This execution "
            "deletes only bounded local artifacts and records a checksum before removal."
        ),
        original_platform="any",
        requires_privilege="user",
    ),
)
def execute_t1070_004_real(
    campaign_id: str,
    sut_profile_id: str,
    **kwargs,
) -> ExecutionResult:
    campaign_dir = _campaign_dir(campaign_id)
    doomed_file = _write_text(campaign_dir / "cleanup_me.tmp", "bounded cleanup target\n")
    sha256 = hashlib.sha256(doomed_file.read_bytes()).hexdigest()
    doomed_file.unlink()
    manifest = _record_manifest(
        campaign_id,
        "file_deletion_manifest.json",
        {
            "deleted_file": str(doomed_file),
            "sha256_before_delete": sha256,
            "timestamp": datetime.now().isoformat(),
        },
    )
    return True, "Bounded file deleted", "", [str(manifest)]


@register_executor(
    technique_id="T1553.002",
    metadata=ExecutorMetadata(
        technique_id="T1553.002",
        technique_name="Code Signing",
        execution_mode=ExecutionMode.REAL_CONTROLLED,
        produces=["defense_evasion:signed_payload"],
        requires=["resources:openssl_available"],
        safe_simulation=True,
        cleanup_supported=True,
        description="Sign a bounded archive with generated local signing material",
        platform="linux",
        execution_fidelity=ExecutionFidelity.ADAPTED,
        fidelity_justification=(
            "T1553.002 signs code to reduce suspicion. This execution performs real "
            "local signing over bounded artifacts using lab-generated certificates."
        ),
        original_platform="windows",
        requires_privilege="user",
    ),
)
def execute_t1553_002_real(
    campaign_id: str,
    sut_profile_id: str,
    **kwargs,
) -> ExecutionResult:
    archive_path = _ensure_collection_archive(campaign_id)
    private_key, certificate = _generate_code_signing_material(campaign_id)
    signature = _campaign_dir(campaign_id) / "archive.sig"
    subprocess.run(
        [
            "openssl",
            "dgst",
            "-sha256",
            "-sign",
            str(private_key),
            "-out",
            str(signature),
            str(archive_path),
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    manifest = _record_manifest(
        campaign_id,
        "code_signing_manifest.json",
        {
            "signed_artifact": str(archive_path),
            "signature": str(signature),
            "certificate": str(certificate),
            "timestamp": datetime.now().isoformat(),
        },
    )
    return True, "Bounded artifact signed", "", [str(archive_path), str(private_key), str(certificate), str(signature), str(manifest)]


@register_executor(
    technique_id="T1574.001",
    metadata=ExecutorMetadata(
        technique_id="T1574.001",
        technique_name="DLL",
        execution_mode=ExecutionMode.REAL_CONTROLLED,
        produces=["persistence:search_order_hijack"],
        requires=["code_execution"],
        safe_simulation=True,
        cleanup_supported=True,
        description="Stage a bounded shared-library hijack analog",
        platform="linux",
        execution_fidelity=ExecutionFidelity.ADAPTED,
        fidelity_justification=(
            "T1574.001 is documented as DLL search-order hijacking on Windows. This "
            "execution preserves the hijack pattern by staging a benign Linux shared-library analog."
        ),
        original_platform="windows",
        requires_privilege="user",
    ),
)
def execute_t1574_001_real(
    campaign_id: str,
    sut_profile_id: str,
    **kwargs,
) -> ExecutionResult:
    campaign_dir = _campaign_dir(campaign_id)
    preload_dir = campaign_dir / "shared_library_hijack"
    preload_dir.mkdir(parents=True, exist_ok=True)
    library_path = _write_text(
        preload_dir / "libmonitor.so",
        "bounded shared-library placeholder\n",
    )
    launcher = _write_text(
        preload_dir / "launch_with_preload.sh",
        (
            "#!/bin/sh\n"
            f"LD_PRELOAD={library_path} /bin/echo bounded_hijack_launch\n"
        ),
    )
    launcher.chmod(0o755)
    manifest = _record_manifest(
        campaign_id,
        "shared_library_hijack_manifest.json",
        {
            "library_path": str(library_path),
            "launcher": str(launcher),
            "timestamp": datetime.now().isoformat(),
        },
    )
    return True, "Bounded shared-library hijack staged", "", [str(library_path), str(launcher), str(manifest)]


@register_executor(
    technique_id="T1559",
    metadata=ExecutorMetadata(
        technique_id="T1559",
        technique_name="Inter-Process Communication",
        execution_mode=ExecutionMode.REAL_CONTROLLED,
        produces=["execution:ipc_channel"],
        requires=["code_execution"],
        safe_simulation=True,
        cleanup_supported=True,
        description="Exchange bounded data over a local IPC socketpair",
        platform="linux",
        execution_fidelity=ExecutionFidelity.ADAPTED,
        fidelity_justification=(
            "T1559 uses inter-process communication. This execution performs a real "
            "local IPC exchange with a UNIX socketpair in the artifact workspace."
        ),
        original_platform="any",
        requires_privilege="user",
    ),
)
def execute_t1559_real(
    campaign_id: str,
    sut_profile_id: str,
    **kwargs,
) -> ExecutionResult:
    left, right = socket.socketpair()
    try:
        right.sendall(b"midnight-eclipse-ipc")
        received = left.recv(1024).decode("utf-8")
    finally:
        left.close()
        right.close()
    log_path = _write_text(
        _campaign_dir(campaign_id) / "ipc_exchange.log",
        f"payload={received}\n",
    )
    return True, "Local IPC exchange completed", "", [str(log_path)]


@register_executor(
    technique_id="T1567",
    metadata=ExecutorMetadata(
        technique_id="T1567",
        technique_name="Exfiltration Over Web Service",
        execution_mode=ExecutionMode.REAL_CONTROLLED,
        produces=["exfiltration:web_service"],
        requires=["collection:archive"],
        safe_simulation=True,
        cleanup_supported=True,
        description="Upload a bounded archive to a local HTTP receiver",
        platform="linux",
        execution_fidelity=ExecutionFidelity.ADAPTED,
        fidelity_justification=(
            "T1567 exfiltrates via web services. This execution performs a bounded "
            "local HTTP upload rather than using external SaaS infrastructure."
        ),
        original_platform="any",
        requires_privilege="user",
    ),
)
def execute_t1567_real(
    campaign_id: str,
    sut_profile_id: str,
    **kwargs,
) -> ExecutionResult:
    archive_path = _ensure_collection_archive(campaign_id)
    upload_path = _campaign_dir(campaign_id) / "generic_web_service_upload.bin"

    class UploadHandler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            payload = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            upload_path.write_bytes(payload)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"OK")

        def log_message(self, format: str, *args) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), UploadHandler)
    worker = threading.Thread(target=server.handle_request)
    worker.start()
    try:
        request = urllib.request.Request(
            url=f"http://127.0.0.1:{server.server_port}/upload",
            data=archive_path.read_bytes(),
            method="POST",
            headers={"Content-Type": "application/octet-stream"},
        )
        with urllib.request.urlopen(request, timeout=15) as response:
            response_body = response.read().decode("utf-8")
    finally:
        worker.join(timeout=15)
        server.server_close()

    manifest = _record_manifest(
        campaign_id,
        "generic_web_service_transfer.json",
        {
            "campaign_id": campaign_id,
            "archive": str(archive_path),
            "upload_path": str(upload_path),
            "response": response_body,
            "bytes_uploaded": upload_path.stat().st_size,
            "sha256": hashlib.sha256(upload_path.read_bytes()).hexdigest(),
            "timestamp": datetime.now().isoformat(),
        },
    )
    return True, "Archive uploaded to bounded web-service receiver", "", [str(archive_path), str(upload_path), str(manifest)]


@register_executor(
    technique_id="T1573.002",
    metadata=ExecutorMetadata(
        technique_id="T1573.002",
        technique_name="Asymmetric Cryptography",
        execution_mode=ExecutionMode.REAL_CONTROLLED,
        produces=["c2:encrypted_channel", "c2_channel"],
        requires=["resources:openssl_available"],
        safe_simulation=True,
        cleanup_supported=True,
        description="Encrypt a bounded channel token with RSA material",
        platform="linux",
        execution_fidelity=ExecutionFidelity.ADAPTED,
        fidelity_justification=(
            "T1573.002 uses asymmetric cryptography to protect C2 traffic. This "
            "execution performs real RSA encryption over a bounded channel token."
        ),
        original_platform="any",
        requires_privilege="user",
    ),
)
def execute_t1573_002_real(
    campaign_id: str,
    sut_profile_id: str,
    **kwargs,
) -> ExecutionResult:
    campaign_dir = _campaign_dir(campaign_id)
    private_key, public_key = _generate_rsa_material(campaign_dir, "channel_key")
    message = _write_text(campaign_dir / "channel_token.txt", "bounded-channel-token\n")
    encrypted = campaign_dir / "channel_token.enc"
    subprocess.run(
        [
            "openssl",
            "pkeyutl",
            "-encrypt",
            "-pubin",
            "-inkey",
            str(public_key),
            "-in",
            str(message),
            "-out",
            str(encrypted),
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    manifest = _record_manifest(
        campaign_id,
        "asymmetric_crypto_manifest.json",
        {
            "public_key": str(public_key),
            "private_key": str(private_key),
            "message": str(message),
            "encrypted": str(encrypted),
            "timestamp": datetime.now().isoformat(),
        },
    )
    return True, "Bounded channel token encrypted", "", [str(private_key), str(public_key), str(message), str(encrypted), str(manifest)]


@register_executor(
    technique_id="T1588.003",
    metadata=ExecutorMetadata(
        technique_id="T1588.003",
        technique_name="Code Signing Certificates",
        execution_mode=ExecutionMode.REAL_CONTROLLED,
        produces=["resources:code_signing_material"],
        requires=["resources:openssl_available"],
        safe_simulation=True,
        cleanup_supported=True,
        description="Generate bounded code-signing material for later use",
        platform="linux",
        execution_fidelity=ExecutionFidelity.ADAPTED,
        fidelity_justification=(
            "T1588.003 acquires code-signing certificates. This execution creates "
            "bounded lab certificates for later signing steps."
        ),
        original_platform="pre",
        requires_privilege="user",
    ),
)
def execute_t1588_003_real(
    campaign_id: str,
    sut_profile_id: str,
    **kwargs,
) -> ExecutionResult:
    private_key, certificate = _generate_code_signing_material(campaign_id)
    manifest = _record_manifest(
        campaign_id,
        "code_signing_material_manifest.json",
        {
            "private_key": str(private_key),
            "certificate": str(certificate),
            "timestamp": datetime.now().isoformat(),
        },
    )
    return True, "Bounded code-signing material generated", "", [str(private_key), str(certificate), str(manifest)]


@register_executor(
    technique_id="T1003.003",
    metadata=ExecutorMetadata(
        technique_id="T1003.003",
        technique_name="NTDS",
        execution_mode=ExecutionMode.NAIVE_SIMULATED,
        produces=["credential_access:directory_dump"],
        requires=["access:initial"],
        safe_simulation=True,
        cleanup_supported=True,
        description="Create a bounded NTDS-style credential dump manifest",
        platform="linux",
        execution_fidelity=ExecutionFidelity.INSPIRED,
        fidelity_justification=(
            "T1003.003 targets Windows NTDS data. This execution represents the "
            "credential-dump outcome as a bounded manifest because the Linux substrate "
            "cannot replay the real NTDS mechanism."
        ),
        original_platform="windows",
        requires_privilege="user",
    ),
)
def execute_t1003_003_real(
    campaign_id: str,
    sut_profile_id: str,
    **kwargs,
) -> ExecutionResult:
    dump_path = _write_text(
        _campaign_dir(campaign_id) / "bounded_ntds_dump.txt",
        "Administrator:aad3b435b51404eeaad3b435b51404ee:1122334455667788\n",
    )
    manifest = _record_manifest(
        campaign_id,
        "ntds_manifest.json",
        {
            "dump_path": str(dump_path),
            "timestamp": datetime.now().isoformat(),
        },
    )
    return True, "Bounded NTDS-style dump recorded", "", [str(dump_path), str(manifest)]
