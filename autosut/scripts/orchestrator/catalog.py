"""Per-campaign tuple catalog.

This file is the single source of truth for how each campaign maps to:

    (AttackerProfile, SUTProfile, CVEInjection[])

Today the catalog ships with one fully resolved entry (`0.shadowray`) that
uses adapted_real CVE injection. The remaining campaigns are listed with
adapted_surrogate or inspired fidelity so the catalog is complete; their
recipes will be promoted as the artifact matures.

Reviewers can read this file end-to-end in under a minute.
"""

from __future__ import annotations

from .models import (
    AttackerProfile, CVEInjection, FidelityLevel, ProvenanceSource,
    Realization, SUTProfile,
)


def shadowray_sut() -> SUTProfile:
    """Linux node that hosts Ray ML with the vulnerable dashboard exposed."""
    from .models import (
        Credential, NetworkExposure, StagedArtifact, SUTComposition,
    )
    composition = SUTComposition(
        credentials=[
            Credential(
                kind="api_token", user="ray", secret="(no-auth)",
                purpose="Ray dashboard ships without authentication on the "
                        "unauthenticated job-submission endpoint exploited "
                        "by CVE-2023-48022.",
                # The *absence* of authentication is not a lab credential
                # choice — it IS the CVE-2023-48022 vulnerability property.
                source=ProvenanceSource.external_reference,
            ),
        ],
        artifacts=[
            StagedArtifact(
                path="/opt/sensitive/credentials.txt",
                content_text="API_KEY=ya29.demo-credential\n",
                owner="root", mode="0644",
                purpose="Decoy ML-pipeline credentials — T1005 collection "
                        "target after the unauthenticated job-submission RCE.",
                source=ProvenanceSource.analyst_authored,
            ),
            StagedArtifact(
                path="/opt/sensitive/manifest.txt",
                content_text="training_dataset_v3.parquet\n",
                owner="root", mode="0644",
                purpose="Decoy ML-pipeline artefact manifest — T1083 / T1005 "
                        "target post-exploitation.",
                source=ProvenanceSource.analyst_authored,
            ),
        ],
        exposures=[
            # :8265 is the documented Ray dashboard exploit surface for
            # CVE-2023-48022 — the corpus tells us this port must be exposed.
            NetworkExposure(port=8265, service="ray_dashboard_http",
                             expose_to="private_network",
                             purpose="Documented CVE-2023-48022 exploit surface — "
                                     "the unauthenticated Ray dashboard "
                                     "job-submission endpoint.",
                             source=ProvenanceSource.external_reference),
        ],
        notes="Ray 2.6.3 install is driven by the existing injector "
              "(ray_2_6_3 / ray_dashboard_surrogate). The composition here "
              "declares the *additional* SUT realism (decoy data + exposure) "
              "so the manifest carries the full picture even when the real-"
              "CVE install falls back to surrogate.",
    )
    return SUTProfile(
        sut_id="linux_python_compute_node",
        base_image="python:3.11-slim",
        services=["python3", "ray_2_6_3"],
        memory_mb=4096,
        smp=2,
        composition=composition,
        notes="Ray cluster dashboard is the unauthenticated RCE surface "
              "exploited by CVE-2023-48022. Python slim base avoids the "
              "ARM64 apt/GPG issues seen on Ubuntu Jammy images. The "
              "vulnerable Ray version is installed by the CVE injector; "
              "the composer applies the surrounding realism layer.",
    )


def shadowray_attacker() -> AttackerProfile:
    return AttackerProfile(
        profile_id="python_rpc_attacker",
        capabilities=["rpc_rce", "db_dump", "pivot"],
        notes="Python + requests to drive the Ray dashboard job submission "
              "endpoint, plus mysql client for follow-on data exfiltration.",
    )


def shadowray_cves(prefer_real: bool = True) -> list[CVEInjection]:
    """Resolve the CVE list. Two recipes are registered:

    - ``ray_2_6_3``: fidelity=adapted, realization=real_cve. Installs Ray
      2.6.3 (the disclosed vulnerable version). On ARM64 Docker the plasma
      store binary shipped with that wheel does not initialise (known Ray
      <2.40 ARM64 issue); the run still records the attempted realisation.
    - ``ray_dashboard_surrogate``: fidelity=adapted, realization=surrogate.
      Runs a minimal HTTP service mimicking the unauthenticated job-submission
      endpoint of the Ray dashboard. The exploit code path the attacker
      executes is byte-for-byte identical to the real-CVE path.
    """
    if prefer_real:
        return [
            CVEInjection(
                cve_id="CVE-2023-48022",
                target_software="ray",
                target_version="2.6.3",
                fidelity=FidelityLevel.adapted,
                realization=Realization.real_cve,
                install_recipe="ray_2_6_3",
                source=ProvenanceSource.external_reference,
                reason="Ray is open source on PyPI; the vulnerable dashboard "
                       "is reproducible by pip install ray==2.6.3.",
            ),
        ]
    return [
        CVEInjection(
            cve_id="CVE-2023-48022",
            target_software="ray (surrogate)",
            target_version="surrogate-1.0",
            fidelity=FidelityLevel.adapted,
            realization=Realization.surrogate,
            install_recipe="ray_dashboard_surrogate",
            source=ProvenanceSource.external_reference,
            reason="Surrogate retains the unauthenticated POST /api/jobs/ RCE "
                   "semantics without requiring the upstream Ray distribution "
                   "to initialise. Used as the executable fallback when ARM64 "
                   "ray==2.6.3 plasma store fails to start.",
        ),
    ]


def c0011_sut() -> SUTProfile:
    """c0011 SUT: Linux workstation with applied weak-credential evidence."""
    from .models import (
        Credential, NetworkExposure, StagedArtifact, SUTComposition,
        ApplicationStack,
    )
    composition = SUTComposition(
        credentials=[
            Credential(
                kind="password", user="vulnuser", secret="vulnpass123",
                purpose="T1078 lab pre-staged weak credentials; AutoSUT "
                        "materializes the usable user/password pair.",
                # T1078/Valid-Accounts implies a usable credential exists; the
                # literal vulnuser:vulnpass123 is AutoSUT's concretization.
                source=ProvenanceSource.autosut_concretized,
            ),
        ],
        artifacts=[
            StagedArtifact(
                path="/home/vulnuser/documents/confidential.txt",
                content_text=("CONFIDENTIAL DATA - Company Secrets\n"
                              "API Keys: LAB_DECOY_API_KEY\n"),
                owner="vulnuser", mode="0644",
                purpose="Decoy sensitive document — collection target for "
                        "T1005 / T1213.",
                source=ProvenanceSource.analyst_authored,
            ),
            StagedArtifact(
                path="/home/vulnuser/documents/passwords.txt",
                content_text="admin:admin123\ndbuser:dbpass456\n",
                owner="vulnuser", mode="0600",
                purpose="Decoy credentials store — collection target "
                        "for T1552.001.",
                source=ProvenanceSource.analyst_authored,
            ),
            StagedArtifact(
                path="/root/.ssh/known_hosts",
                content_text="10.0.0.5 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILabKnownHostKey\n",
                owner="root", mode="0644",
                purpose="Remote-system-discovery seed for Caldera T1018 "
                        "(Parse SSH known_hosts). The file is an analyst-authored "
                        "lab affordance, not corpus-supported CTI.",
                source=ProvenanceSource.analyst_authored,
            ),
        ],
        applications=[
            ApplicationStack(
                name="openssh", version="default",
                recipe="openssh_weak_password",
                purpose="ssh service the lab weak credential reaches "
                        "(password authentication enabled).",
                # Generic inherited service, no CVE — the campaign needs an
                # affordance, not this specific product.
                source=ProvenanceSource.analyst_authored,
            ),
        ],
        exposures=[
            NetworkExposure(port=22, service="ssh",
                             expose_to="private_network",
                             purpose="SSH service the lab weak credential reaches "
                                     "(port 22).",
                             source=ProvenanceSource.analyst_authored),
        ],
        notes="Applies each declared weak-credential and service element through "
              "the SUT composer and records per-element evidence.",
    )
    return SUTProfile(
        sut_id="linux_generic_workstation",
        base_image="python:3.11-slim",
        services=["ssh", "openssl"],
        memory_mb=1024,
        smp=1,
        composition=composition,
        notes="c0011 — realistic Linux workstation with weak SSH, decoy "
              "sensitive files, and ssh service. Base is python:3.11-slim "
              "because the c0011 technique recipes assume openssl and python3.",
    )


def c0011_attacker() -> AttackerProfile:
    return AttackerProfile(
        profile_id="generic_kill_chain_attacker",
        capabilities=["cert_gen", "web_rce"],
        notes="OpenSSL for certificate generation; curl/python3 for staging.",
    )


def c0011_cves() -> list[CVEInjection]:
    # c0011 has no CVE evidence and no specific exploit surface.
    return []


# ---------------------------------------------------------------------------
# 0.pivot_demo — three-host SSH pivot reference campaign
# ---------------------------------------------------------------------------

_PIVOT_BASE_IMAGE = "alpine:3.19"
_PIVOT_LAB_USER = "labuser"
_PIVOT_LAB_PW = "Lab-Demo-2026!"
# Alpine is used because Ubuntu's ARM64 mirror has chronic GPG-signature
# issues on `apt-get update` inside slim containers. Alpine's apk is
# small, reliable on ARM64, and ships the binaries we need (openssh,
# sshpass, netcat-openbsd) without architecture-specific friction.
# The SSH server is now a FREE composition application (see
# target_composition.applications) so the non-uniqueness witness can
# substitute it (OpenSSH <-> Dropbear) and execute BOTH. Startup only
# pre-creates the lab user; the chosen SSH implementation, its host keys, and
# its daemon are installed by the application recipe (openssh_weak_password or,
# in the variant, dropbear_equivalent).
_PIVOT_TARGET_STARTUP = [
    "apk add --no-cache bash shadow openssh-client sshpass >/dev/null 2>&1",
]
_PIVOT_ATTACKER_STARTUP = [
    "apk add --no-cache openssh-client sshpass netcat-openbsd bash "
    ">/dev/null 2>&1 && echo attacker_tools_installed",
]


def pivot_demo_attacker() -> AttackerProfile:
    return AttackerProfile(
        profile_id="pivot_attacker",
        capabilities=["ssh_client", "sshpass", "netcat", "scp"],
        notes="ubuntu:22.04 with openssh-client + sshpass + netcat for the "
              "lateral movement chain.",
    )


# ---------------------------------------------------------------------------
# 0.operation_midnighteclipse — Palo Alto GlobalProtect CVE-2024-3400 surrogate
# ---------------------------------------------------------------------------

def midnighteclipse_attacker() -> AttackerProfile:
    return AttackerProfile(
        profile_id="globalprotect_attacker",
        capabilities=["http_client", "session_cookie_injection"],
        notes="curl + python3 to inject the SESSID command-injection payload "
              "the CVE-2024-3400 advisory describes.",
    )


def midnighteclipse_sut() -> SUTProfile:
    """SUT for the Operation MidnightEclipse GlobalProtect surrogate."""
    from .models import (
        Credential, NetworkExposure, StagedArtifact, SUTComposition,
    )
    composition = SUTComposition(
        credentials=[
            Credential(
                kind="password", user="eclipseops", secret="Eclipse123!",
                purpose="Operator account for the GlobalProtect surrogate "
                        "(eclipseops:Eclipse123!).",
                source=ProvenanceSource.autosut_concretized,
            ),
        ],
        artifacts=[
            StagedArtifact(
                path="/var/lib/eclipseops/network_inventory.txt",
                content_text="vpn-gateway-01\nvpn-gateway-02\n",
                owner="root", mode="0644",
                purpose="Decoy network inventory the CVE-2024-3400 attacker "
                        "would enumerate post-exploitation.",
                source=ProvenanceSource.analyst_authored,
            ),
        ],
        exposures=[
            # :443 GlobalProtect HTTPS is the documented CVE-2024-3400 exploit
            # surface (real CVE). The surrogate-ness lives in realization=
            # surrogate + the vulnerability dimension, not here.
            NetworkExposure(port=443, service="globalprotect_https_surrogate",
                             expose_to="private_network",
                             purpose="Documented CVE-2024-3400 GlobalProtect HTTPS "
                                     "exploit surface (realised by the surrogate).",
                             source=ProvenanceSource.corpus_supported),
        ],
        notes="Realism for the GlobalProtect surrogate target.",
    )
    return SUTProfile(
        sut_id="globalprotect_target",
        base_image="python:3.11-slim",
        services=["python3", "openssl"],
        memory_mb=1024, smp=1,
        composition=composition,
        notes="Surrogate of the Palo Alto GlobalProtect appliance — "
              "CVE-2024-3400 SESSID command-injection semantics are "
              "preserved by the injector recipe.",
    )


# ---------------------------------------------------------------------------
# 0.salesforce_data_exfiltration — CRM API surrogate
# ---------------------------------------------------------------------------

def salesforce_attacker() -> AttackerProfile:
    return AttackerProfile(
        profile_id="salesforce_attacker",
        capabilities=["bearer_token", "http_client"],
        notes="curl + python3 for Bearer-authenticated CRM REST API queries.",
    )


def salesforce_sut() -> SUTProfile:
    """SUT for the Salesforce-style data-exfiltration surrogate."""
    from .models import (
        Credential, NetworkExposure, StagedArtifact, SUTComposition,
    )
    composition = SUTComposition(
        credentials=[
            Credential(
                kind="password", user="salesops", secret="SalesOps123!",
                purpose="Operator account for the Salesforce-style API surrogate.",
                source=ProvenanceSource.autosut_concretized,
            ),
            Credential(
                kind="api_token", user="api_consumer", secret="LAB-TOKEN",
                purpose="Bearer token the surrogate Salesforce-style API "
                        "requires for /services/data/v59.0/query — matches "
                        "the salesforce_api_surrogate injector recipe.",
                # No CVE backs this; the token is a surrogate-only affordance
                # AutoSUT concretized so the exfil campaign has something to hit.
                source=ProvenanceSource.autosut_concretized,
            ),
        ],
        artifacts=[
            StagedArtifact(
                path="/opt/crm/records.json",
                content_text=('{"records":[{"Name":"Acme","Email":'
                              '"contact@acme.test"}]}\n'),
                owner="root", mode="0644",
                purpose="Decoy CRM record the API surrogate serves.",
                source=ProvenanceSource.analyst_authored,
            ),
        ],
        exposures=[
            # No CVE for Salesforce in ATT&CK; the :8443 CRM REST surface is a
            # named-product surrogate AutoSUT invented (not a generic service).
            NetworkExposure(port=8443, service="crm_rest_api_surrogate",
                             expose_to="private_network",
                             purpose="Named-product surrogate CRM REST surface the "
                                     "exfiltration campaign targets (no disclosed CVE).",
                             source=ProvenanceSource.autosut_concretized),
        ],
        notes="Realism for the Salesforce-style CRM surrogate.",
    )
    return SUTProfile(
        sut_id="crm_surrogate_target",
        base_image="python:3.11-slim",
        services=["python3", "openssl"],
        memory_mb=1024, smp=1,
        composition=composition,
        notes="Surrogate of a Salesforce REST API for exercising CRM data "
              "exfiltration techniques (T1213.004 etc.).",
    )


# ---------------------------------------------------------------------------
# 0.dmz_segmentation_demo topology-realism reference
# ---------------------------------------------------------------------------

def dmz_segmentation_attacker() -> AttackerProfile:
    return AttackerProfile(
        profile_id="dmz_segmentation_attacker",
        capabilities=["http_client", "ssh_client", "netcat"],
        notes="alpine + curl + netcat-openbsd to probe each zone boundary.",
    )


def dmz_segmentation_sut() -> SUTProfile:
    """Three-zone topology declared explicitly as Docker networks."""
    from .models import (
        Credential, NetworkExposure, SUTComposition, SUTHost,
        Topology, Zone,
    )
    topology = Topology(
        zones=[
            # Topology is the dimension public CTI supports least — ATT&CK/STIX
            # rarely pin zone counts or trust boundaries, so every zone is an
            # explicit analyst lab choice rather than corpus evidence.
            Zone(name="internet_edge",
                 description="Where the attacker originates. Has no enterprise access.",
                 source=ProvenanceSource.analyst_authored),
            Zone(name="dmz",
                 description="Bridges internet_edge and enterprise. Hosts edge-facing services.",
                 source=ProvenanceSource.analyst_authored),
            Zone(name="enterprise",
                 description="Backend zone. No direct path from internet_edge.",
                 source=ProvenanceSource.analyst_authored),
        ],
        notes="Three-zone segmentation declared at the SUT level.",
    )

    # All tools (openssh, sshpass, netcat-openbsd, curl) + the per-host
    # ssh_config are baked into the `autosut/dmz-host:s28` image at build
    # time. Runtime startup just confirms the bake-in is present.
    install_alpine_tools = "echo dmz_tools_baked_in_image"
    install_server = (
        "adduser -D -s /bin/sh labuser && "
        "echo 'labuser:Zone-Demo-2026!' | chpasswd && "
        "sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && "
        "/usr/sbin/sshd"
    )

    target_creds = SUTComposition(
        credentials=[
            Credential(kind="password", user="labuser",
                       secret="Zone-Demo-2026!",
                       purpose="Lab-pre-staged SSH credential, identical on "
                               "every server host so the pivot chain can "
                               "reuse it as it crosses zone boundaries.",
                       source=ProvenanceSource.autosut_concretized),
        ],
        exposures=[
            NetworkExposure(port=22, service="ssh",
                             expose_to="private_network",
                             purpose="SSH boundary each zone host exposes so the "
                                     "pivot chain can cross zone boundaries.",
                             source=ProvenanceSource.analyst_authored),
        ],
        notes="Pivot target — accepts lab SSH credential.",
    )
    attacker_comp = SUTComposition(
        notes="Attacker has no pre-staged credentials of its own.",
    )

    hosts = [
        SUTHost(
            name="attacker", role="attacker",
            base_image="autosut/dmz-host:s28",
            memory_mb=256, smp=1,
            startup_commands=[install_alpine_tools],
            composition=attacker_comp,
            zones=["internet_edge"],
        ),
        SUTHost(
            name="nginx", role="gateway",
            base_image="autosut/dmz-host:s28",
            memory_mb=256, smp=1,
            startup_commands=[install_server],
            composition=target_creds,
            # Dual-homed: bridges internet_edge and dmz.
            zones=["internet_edge", "dmz"],
        ),
        SUTHost(
            name="app_server", role="gateway",
            base_image="autosut/dmz-host:s28",
            memory_mb=256, smp=1,
            startup_commands=[install_server],
            composition=target_creds,
            # Dual-homed: bridges dmz and enterprise.
            zones=["dmz", "enterprise"],
        ),
        SUTHost(
            name="db", role="target",
            base_image="autosut/dmz-host:s28",
            memory_mb=256, smp=1,
            startup_commands=[install_server],
            composition=target_creds,
            zones=["enterprise"],
        ),
    ]
    return SUTProfile(
        sut_id="dmz_segmentation_three_zone",
        base_image="alpine:3.19",
        services=["ssh"],
        memory_mb=256, smp=1,
        hosts=hosts,
        topology=topology,
        notes="Three-zone topology with two dual-homed gateways (nginx, "
              "app_server). Attacker has L2 reachability to nginx only; "
              "db has L2 reachability from app_server only. The dual-homed "
              "gateway shape is declared explicitly via SUTProfile.topology "
              "and SUTHost.zones.",
    )


def cve_2021_41773_attacker() -> AttackerProfile:
    return AttackerProfile(
        profile_id="cve_2021_41773_attacker",
        capabilities=["http_client", "path_traversal"],
        notes="alpine + curl/wget; explores the path traversal disclosed in "
              "the Apache Security advisory for CVE-2021-41773.",
    )


def cve_2021_41773_sut() -> SUTProfile:
    """Two-host SUT: attacker (alpine + curl) + target (httpd:2.4.49 with
    the vulnerable httpd.conf staged by the composer)."""
    from .models import (
        ApplicationStack, SUTComposition, SUTHost, StagedArtifact,
        NetworkExposure,
    )
    target_composition = SUTComposition(
        applications=[
            ApplicationStack(
                name="apache_httpd",
                version="2.4.49",
                recipe="apache_httpd_2.4.49_cve_2021_41773",
                cve_pins=["CVE-2021-41773"],
                purpose="Vulnerable web server — pre-patch httpd 2.4.49 with "
                        "the Alias+cgi-bin trigger the advisory documents.",
                # CVE-anchored version pin -> version + product are
                # corpus-supported by NVD/MITRE; the install recipe choice
                # is autosut_concretized but that's tracked elsewhere.
                source=ProvenanceSource.external_reference,
            ),
        ],
        artifacts=[
            StagedArtifact(
                path="/usr/local/apache2/cgi-bin/lab.sh",
                content_text="#!/bin/sh\necho Content-Type: text/plain\necho\necho LAB_CGI_OK\n",
                mode="0755",
                purpose="Decoy CGI to confirm script alias mounted.",
                source=ProvenanceSource.analyst_authored,
            ),
        ],
        exposures=[
            # :80 is the documented CVE-2021-41773 path-traversal exploit
            # surface, realised against the real vulnerable httpd 2.4.49.
            NetworkExposure(port=80, service="http",
                             expose_to="private_network",
                             purpose="Documented CVE-2021-41773 path-traversal "
                                     "exploit surface on the vulnerable httpd 2.4.49.",
                             source=ProvenanceSource.external_reference),
        ],
        notes="Reference composition: every realism element is "
              "declared, applied, and audit-logged.",
    )
    attacker_startup = [
        "apk add --no-cache curl >/dev/null 2>&1 && echo attacker_curl_ok",
    ]
    hosts = [
        SUTHost(
            name="attacker", role="attacker", base_image="autosut/dmz-host:s28",
            memory_mb=256, smp=1,
            startup_commands=attacker_startup,
        ),
        SUTHost(
            name="target", role="target", base_image="httpd:2.4.49",
            services=["http"], memory_mb=512, smp=1,
            composition=target_composition,
        ),
    ]
    return SUTProfile(
        sut_id="0.cve_2021_41773",
        base_image="httpd:2.4.49",
        services=["http"],
        memory_mb=512, smp=1,
        hosts=hosts,
        notes="Two-host CVE-2021-41773 reference. Target uses the canonical "
              "vulnerable httpd:2.4.49 multi-arch image; the SUT composer "
              "applies a vulnerable httpd.conf the advisory documents.",
    )


def pivot_demo_sut() -> SUTProfile:
    """Three-host SUT: attacker + target1 + target2 on a private network."""
    from .models import (
        ApplicationStack, Credential, NetworkExposure, SUTComposition,
        SUTHost,
    )

    target_composition = SUTComposition(
        credentials=[
            Credential(
                kind="password", user=_PIVOT_LAB_USER, secret=_PIVOT_LAB_PW,
                purpose="Lab pre-staged weak credential — the attacker "
                        "discovers it via T1110.001 brute-force against the "
                        "target's SSH service.",
                # T1110.001 brute-force implies a discoverable credential; the
                # literal labuser pair is AutoSUT's concretization.
                source=ProvenanceSource.autosut_concretized,
            ),
        ],
        applications=[
            ApplicationStack(
                name="openssh", version="default",
                recipe="openssh_weak_password",
                purpose="The remote authenticated SSH service the attacker "
                        "brute-forces (T1110.001) and pivots through "
                        "(T1021.004). A FREE, analyst-authored implementation "
                        "choice: the corpus pins only that a remote "
                        "authenticated service must exist, not which SSH "
                        "server realises it. The non-uniqueness witness "
                        "substitutes it (OpenSSH <-> Dropbear) and executes "
                        "both to completion under one corpus fingerprint.",
                source=ProvenanceSource.analyst_authored,
            ),
        ],
        exposures=[
            NetworkExposure(port=22, service="ssh",
                             expose_to="private_network",
                             purpose="SSH service the attacker brute-forces "
                                     "(T1110.001) on the pivot target.",
                             source=ProvenanceSource.analyst_authored),
        ],
        notes="Pivot target realism: weak SSH credential + listening port "
              "22 on the per-run private Docker network.",
    )
    attacker_composition = SUTComposition(
        notes="Attacker host has no pre-staged credentials of its own; the "
              "campaign's recipes harvest target credentials by brute force.",
    )

    hosts = [
        SUTHost(
            name="attacker", role="attacker", base_image=_PIVOT_BASE_IMAGE,
            memory_mb=512, smp=1,
            startup_commands=_PIVOT_ATTACKER_STARTUP,
            composition=attacker_composition,
        ),
        SUTHost(
            name="target1", role="target", base_image=_PIVOT_BASE_IMAGE,
            services=["ssh"], memory_mb=512, smp=1,
            startup_commands=_PIVOT_TARGET_STARTUP,
            composition=target_composition,
        ),
        SUTHost(
            name="target2", role="target", base_image=_PIVOT_BASE_IMAGE,
            services=["ssh"], memory_mb=512, smp=1,
            startup_commands=_PIVOT_TARGET_STARTUP,
            composition=target_composition,
        ),
    ]
    return SUTProfile(
        sut_id="0.pivot_demo",
        base_image=_PIVOT_BASE_IMAGE,
        services=["ssh"],
        memory_mb=512, smp=1,
        hosts=hosts,
        notes="Three-host SSH pivot reference. Lab pre-stages a single "
              "weak password on both targets to satisfy a minimal Q3 audit "
              "trail — the attacker still has to discover it via T1110.001.",
    )


# ---------------------------------------------------------------------------
# 0.web_demo — two-host edge-HTTP witness (Apache <-> Nginx)
# ---------------------------------------------------------------------------

_WEB_BASE_IMAGE = "alpine:3.19"
_WEB_ATTACKER_STARTUP = [
    "apk add --no-cache curl bash >/dev/null 2>&1 && echo attacker_tools_installed",
]
# The web target needs no user setup: the edge-HTTP application recipe
# (apache_basic_auth or, in the variant, nginx_equivalent) installs the server,
# stages the HTTP Basic Auth credential and the protected secret, and starts it
# on :80.
_WEB_TARGET_STARTUP = [
    "apk add --no-cache bash >/dev/null 2>&1 || true",
]


def web_demo_attacker() -> AttackerProfile:
    return AttackerProfile(
        profile_id="web_attacker",
        capabilities=["http_client", "basic_auth_bruteforce"],
        notes="alpine with curl for the HTTP Basic Auth brute-force and exfil "
              "chain.",
    )


def web_demo_sut() -> SUTProfile:
    """Two-host SUT: attacker + web target on a private network. The web server
    is a FREE element so the non-uniqueness witness can substitute it
    (Apache <-> Nginx) and execute the same HTTP Basic Auth chain on both."""
    from .models import (
        ApplicationStack, NetworkExposure, SUTComposition, SUTHost,
    )

    target_composition = SUTComposition(
        applications=[
            ApplicationStack(
                name="apache_httpd", version="default",
                recipe="apache_basic_auth",
                purpose="The edge HTTP service whose Basic Auth realm the "
                        "attacker brute-forces (T1110.001) and authenticates to "
                        "(T1078) before exfiltrating the protected secret "
                        "(T1005). A FREE, analyst-authored implementation "
                        "choice: the corpus pins only that an edge HTTP service "
                        "must exist, not which web server realises it. The "
                        "non-uniqueness witness substitutes it (Apache <-> "
                        "Nginx) and executes both to completion under one corpus "
                        "fingerprint.",
                source=ProvenanceSource.analyst_authored,
            ),
        ],
        exposures=[
            NetworkExposure(port=80, service="http",
                             expose_to="private_network",
                             purpose="HTTP service the attacker brute-forces "
                                     "(T1110.001) on the web target.",
                             source=ProvenanceSource.analyst_authored),
        ],
        notes="Web target realism: HTTP Basic Auth realm with a pre-staged weak "
              "credential and a protected secret on the per-run private network.",
    )
    attacker_composition = SUTComposition(
        notes="Attacker host has no pre-staged credentials of its own; the "
              "campaign's recipes recover the web credential by brute force.",
    )

    hosts = [
        SUTHost(
            name="attacker", role="attacker", base_image=_WEB_BASE_IMAGE,
            memory_mb=512, smp=1,
            startup_commands=_WEB_ATTACKER_STARTUP,
            composition=attacker_composition,
        ),
        SUTHost(
            name="webtarget", role="target", base_image=_WEB_BASE_IMAGE,
            services=["http"], memory_mb=512, smp=1,
            startup_commands=_WEB_TARGET_STARTUP,
            composition=target_composition,
        ),
    ]
    return SUTProfile(
        sut_id="0.web_demo",
        base_image=_WEB_BASE_IMAGE,
        services=["http"],
        memory_mb=512, smp=1,
        hosts=hosts,
        notes="Two-host edge-HTTP witness. Lab pre-stages a weak HTTP Basic "
              "Auth credential on the web target; the attacker discovers it via "
              "T1110.001 and exfiltrates the protected secret.",
    )


# ---------------------------------------------------------------------------
# SUT declarations for the remaining inspired campaign profiles.
#
# Each function declares a SUTComposition for one campaign-specific lab shape.
# Three patterns are in use:
#
#   * Linux-credentialed (c0011-shape): vulnuser-style + ssh + decoy files.
#   * Linux-web (c0010-shape): adds apache web surface.
#   * Linux-web-db (apt41_dust-shape): adds mysql.
#
# Apache and MySQL recipes are not yet registered in sut_applications.py,
# so the composer will log a "no recipe" breadcrumb for those stacks on
# bring-up (honest gap rather than fake success). The declarations land
# now so the catalog is complete; apache/mysql recipes
# follow once the host disk is freed.
# ---------------------------------------------------------------------------

def _generic_attacker(profile_id: str, notes: str) -> AttackerProfile:
    return AttackerProfile(
        profile_id=profile_id,
        capabilities=["ssh_client", "http_client"],
        notes=notes,
    )


def _inspired_single_host_sut(*, sut_id: str, user: str, password: str,
                              file_specs: list[tuple[str, str, str]],
                              extra_services: tuple[str, ...] = (),
                              notes: str) -> SUTProfile:
    """Build a single-host Linux SUT with ssh, weak credentials, and decoys.

    ``file_specs`` is a list of ``(path, owner, content_text)`` triples;
    each lands as a :class:`StagedArtifact`. ``extra_services`` may list
    additional services (``apache2``, ``mysql``) that are declared as
    :class:`ApplicationStack` entries even when no install recipe exists
    yet — the composer logs the gap rather than fake the install.
    """
    from .models import (
        ApplicationStack, Credential, NetworkExposure, StagedArtifact,
        SUTComposition,
    )
    # Every element in an inspired SUT is generic lab construction: the
    # campaign needs *an* affordance (ssh/apache/mysql), not a CVE-pinned
    # product, so services + their ports + decoys are all analyst_authored.
    # Only the operator credential is autosut_concretized (the campaign's
    # valid-accounts/credential-access techniques imply a usable credential
    # exists; the literal user:password pair is AutoSUT's pick).
    applications: list[ApplicationStack] = [
        ApplicationStack(
            name="openssh", version="default",
            recipe="openssh_weak_password",
            purpose="ssh service with password authentication enabled.",
            source=ProvenanceSource.analyst_authored,
        ),
    ]
    exposures: list[NetworkExposure] = [
        NetworkExposure(port=22, service="ssh",
                         expose_to="private_network",
                         purpose="SSH service with password authentication enabled.",
                         source=ProvenanceSource.analyst_authored),
    ]
    for extra_service in extra_services:
        if extra_service == "apache2":
            applications.append(ApplicationStack(
                name="apache_httpd", version="default",
                recipe="apache_default_site",  # recipe pending follow-up
                purpose="HTTP web surface required by this lab profile.",
                source=ProvenanceSource.analyst_authored,
            ))
            exposures.append(NetworkExposure(
                port=80, service="http", expose_to="private_network",
                purpose="HTTP web surface required by this lab profile.",
                source=ProvenanceSource.analyst_authored))
        elif extra_service == "mysql":
            applications.append(ApplicationStack(
                name="mysql", version="default",
                recipe="mysql_default_instance",  # recipe pending
                purpose="MySQL instance the lab profile declares "
                        "(default_instance_exposed).",
                source=ProvenanceSource.analyst_authored,
            ))
            exposures.append(NetworkExposure(
                port=3306, service="mysql",
                expose_to="private_network",
                purpose="MySQL instance the lab profile declares "
                        "(default_instance_exposed).",
                source=ProvenanceSource.analyst_authored))
    composition = SUTComposition(
        credentials=[
            Credential(
                kind="password", user=user, secret=password,
                purpose=f"Operator account declared by the lab profile "
                        f"declaration ({user}:{password}).",
                source=ProvenanceSource.autosut_concretized,
            ),
        ],
        artifacts=[
            StagedArtifact(
                path=path, content_text=content, owner=owner, mode="0644",
                purpose=f"Decoy artefact declared by the lab profile "
                        f"({path}).",
                source=ProvenanceSource.analyst_authored,
            )
            for path, owner, content in file_specs
        ],
        applications=applications,
        exposures=exposures,
        notes=notes,
    )
    return SUTProfile(
        sut_id=sut_id,
        base_image="python:3.11-slim",
        services=["ssh", *extra_services],
        memory_mb=1024, smp=1,
        composition=composition,
        notes=notes,
    )


def c0010_sut() -> SUTProfile:
    return _inspired_single_host_sut(
        sut_id="c0010_apt20_watering_hole",
        user="ubuntu", password="ubuntu",
        file_specs=[
            ("/var/www/html/index.html", "www-data",
             "<html><body>Welcome to the lab landing page.</body></html>\n"),
            ("/home/ubuntu/shipping_notice.txt", "ubuntu",
             "Shipping notice — internal use only.\n"),
        ],
        extra_services=("apache2",),
        notes="0.c0010 — APT20 Operation Wocao watering-hole chain. Linux "
              "web target with weak ssh + apache landing page.",
    )


def c0012_sut() -> SUTProfile:
    return _inspired_single_host_sut(
        sut_id="c0012_apt28_recon",
        user="ubuntu", password="ubuntu",
        file_specs=[],
        notes="0.c0012 — APT28-style reconnaissance against minimal Linux SUT "
              "with weak ssh.",
    )


def c0013_sut() -> SUTProfile:
    return _inspired_single_host_sut(
        sut_id="c0013_lazarus_tool_transfer",
        user="ubuntu", password="ubuntu",
        file_specs=[],
        extra_services=("apache2",),
        notes="0.c0013 — Lazarus-style intrusion with shell access and "
              "tool transfer over a Linux web surface.",
    )


def c0015_sut() -> SUTProfile:
    return _inspired_single_host_sut(
        sut_id="c0015_credentialed_postcompromise",
        user="testuser", password="password123",
        file_specs=[
            ("/tmp/sensitive_data.txt", "testuser",
             "Confidential data — staging\n"),
            ("/tmp/credentials.txt", "testuser",
             "admin:admin\nroot:toor\n"),
        ],
        notes="0.c0015 — minimal Linux SUT for credentialed access and "
              "post-compromise enumeration / collection.",
    )


def c0017_sut() -> SUTProfile:
    return _inspired_single_host_sut(
        sut_id="c0017_apt29_stealth",
        user="testuser", password="password123",
        file_specs=[
            ("/tmp/phishing_context.txt", "testuser",
             "Phishing payload context — staging\n"),
        ],
        notes="0.c0017 — APT29-style stealth execution and persistence "
              "flow on a minimal Linux SUT.",
    )


def c0026_sut() -> SUTProfile:
    return _inspired_single_host_sut(
        sut_id="c0026_collection_archive_chunk",
        user="ubuntu", password="ubuntu",
        file_specs=[
            ("/home/ubuntu/andromeda_notes.txt", "ubuntu",
             "Operation notes\n"),
            ("/home/ubuntu/staged_docs/report_2021.txt", "ubuntu",
             "Quarterly report — internal\n"),
        ],
        notes="0.c0026 — Linux collection / archive / chunked exfil flow.",
    )


def apt41_dust_sut() -> SUTProfile:
    return _inspired_single_host_sut(
        sut_id="apt41_dust_dual_ops",
        user="dustops", password="Dust2024!",
        file_specs=[
            ("/home/dustops/intel/targets.txt", "dustops",
             "Targets: target-financial-01, target-financial-02\n"),
            ("/home/dustops/intel/financials.csv", "dustops",
             "Q,Account,Amount\nQ1,A123,1000\n"),
            ("/tmp/staged_payload.sh", "dustops",
             "#!/bin/sh\necho payload_ran\n"),
        ],
        extra_services=("apache2", "mysql"),
        notes="0.apt41_dust — APT41 DUST dual espionage + financial ops on "
              "multi-service Linux SUT (ssh + apache + mysql).",
    )


def apt41_dust_full_sut() -> SUTProfile:
    return _inspired_single_host_sut(
        sut_id="apt41_dust_full_chain",
        user="testuser", password="password123",
        file_specs=[
            ("/home/testuser/documents/financial_report.xlsx", "testuser",
             "(binary financial report placeholder)\n"),
            ("/home/testuser/.ssh/id_rsa", "testuser",
             "SIMULATED SSH KEY MATERIAL\nLAB_DECOY_KEY\n"
             "END SIMULATED SSH KEY MATERIAL\n"),
        ],
        notes="0.apt41_dust_full — extended APT41 DUST chain (discovery, "
              "collection, exfil, impact) on minimal Linux SUT.",
    )


def costaricto_sut() -> SUTProfile:
    return _inspired_single_host_sut(
        sut_id="costaricto_proxy_collection",
        user="reconuser", password="reconpass123",
        file_specs=[
            ("/home/reconuser/collection/finance_notes.txt", "reconuser",
             "Finance reconnaissance notes — internal\n"),
            ("/home/reconuser/proxy/multi_hop_proxy.conf", "reconuser",
             "# multi-hop proxy configuration\nfrontends=proxy1,proxy2\n"),
            ("/home/reconuser/tools/network_scan.sh", "reconuser",
             "#!/bin/sh\nfor host in target1 target2; do nc -z -w 1 $host 22; done\n"),
        ],
        extra_services=("apache2",),
        notes="0.costaricto — service discovery, tool staging, local "
              "collection and proxy artefacts on Linux SUT.",
    )


def outer_space_sut() -> SUTProfile:
    return _inspired_single_host_sut(
        sut_id="outer_space_browser_discovery",
        user="clouduser", password="cloudpass123",
        file_specs=[
            ("/home/clouduser/.mozilla/firefox/profiles.ini", "clouduser",
             "[General]\nStartWithLastProfile=1\n[Profile0]\n"
             "Name=default\n"),
            ("/home/clouduser/.config/google-chrome/Default/Preferences",
             "clouduser", '{"profile":{"name":"Default"}}\n'),
            ("/home/clouduser/staging/encoded_payload.b64", "clouduser",
             "TEFCX1BBWUxPQUQK\n"),
        ],
        extra_services=("apache2",),
        notes="0.outer_space — browser discovery, tool staging, cloud "
              "infrastructure artefacts on Linux SUT.",
    )


# Stubs for the remaining campaigns. (cve, product, fidelity, realization).
# Inspired campaigns run the technique sequence against a generic primitive;
# adapted/surrogate runs reproduce the exploit surface without the paywalled
# product.
_CAMPAIGN_STUBS: dict[str, tuple[str | None, str, FidelityLevel, Realization]] = {
    "0.apt28_nearest_neighbor": ("CVE-2022-38028", "Windows Print Spooler", FidelityLevel.adapted, Realization.surrogate),
    "0.operation_midnighteclipse": ("CVE-2024-3400", "Palo Alto GlobalProtect", FidelityLevel.adapted, Realization.surrogate),
    "0.versa_director": ("CVE-2024-39717", "Versa Director", FidelityLevel.adapted, Realization.surrogate),
    "0.sharepoint_toolshell": ("CVE-2025-49704", "Microsoft SharePoint", FidelityLevel.adapted, Realization.surrogate),
    "0.c0010": (None, "generic Linux web stack", FidelityLevel.inspired, Realization.generic_primitive),
    "0.c0011": (None, "generic Linux web stack", FidelityLevel.inspired, Realization.generic_primitive),
    "0.c0012": (None, "generic Linux web stack", FidelityLevel.inspired, Realization.generic_primitive),
    "0.c0013": (None, "generic Linux web stack", FidelityLevel.inspired, Realization.generic_primitive),
    "0.c0015": (None, "generic Linux web stack", FidelityLevel.inspired, Realization.generic_primitive),
    "0.c0017": (None, "generic Linux web stack", FidelityLevel.inspired, Realization.generic_primitive),
    "0.c0026": (None, "generic Linux web stack", FidelityLevel.inspired, Realization.generic_primitive),
    "0.apt41_dust": (None, "generic Linux web stack", FidelityLevel.inspired, Realization.generic_primitive),
    "0.costaricto": (None, "generic Linux web stack", FidelityLevel.inspired, Realization.generic_primitive),
    "0.outer_space": (None, "generic Linux web stack", FidelityLevel.inspired, Realization.generic_primitive),
    "0.salesforce_data_exfiltration": (None, "SaaS API surrogate", FidelityLevel.adapted, Realization.surrogate),
}


def resolve(campaign_id: str, *,
            fidelity_preference: str = "real_then_surrogate"
            ) -> tuple[AttackerProfile, SUTProfile, list[CVEInjection]]:
    """Return the tuple for one campaign.

    `fidelity_preference` accepts ``real_then_surrogate`` (default; try real
    install, allow caller to retry with surrogate on failure), ``real_only``,
    or ``surrogate``.
    """
    if campaign_id == "0.shadowray":
        prefer_real = fidelity_preference in ("real_then_surrogate", "real_only")
        return (shadowray_attacker(), shadowray_sut(),
                shadowray_cves(prefer_real=prefer_real))
    if campaign_id == "0.c0011":
        return c0011_attacker(), c0011_sut(), c0011_cves()
    if campaign_id == "0.pivot_demo":
        return pivot_demo_attacker(), pivot_demo_sut(), []
    if campaign_id == "0.web_demo":
        return web_demo_attacker(), web_demo_sut(), []
    if campaign_id == "0.dmz_segmentation_demo":
        return dmz_segmentation_attacker(), dmz_segmentation_sut(), []
    if campaign_id == "0.cve_2021_41773":
        return cve_2021_41773_attacker(), cve_2021_41773_sut(), []
    # Each inspired campaign resolves to its own campaign-specific SUT shape.
    # Two campaigns (caldera_linux_demo, fin6_emulation) keep the c0011
    # baseline because they are AutoSUT-native references.
    _PER_CAMPAIGN_SUT: dict[str, tuple] = {
        "0.c0010": (_generic_attacker("c0010_attacker",
                                       "ssh+http client for watering-hole flow."),
                    c0010_sut()),
        "0.c0012": (_generic_attacker("c0012_attacker",
                                       "ssh client for APT28-style recon."),
                    c0012_sut()),
        "0.c0013": (_generic_attacker("c0013_attacker",
                                       "ssh+http client for Lazarus tool transfer."),
                    c0013_sut()),
        "0.c0015": (_generic_attacker("c0015_attacker",
                                       "ssh client for credentialed access."),
                    c0015_sut()),
        "0.c0017": (_generic_attacker("c0017_attacker",
                                       "ssh client for APT29 stealth flow."),
                    c0017_sut()),
        "0.c0026": (_generic_attacker("c0026_attacker",
                                       "ssh client for collection / archive / chunk."),
                    c0026_sut()),
        "0.apt41_dust": (_generic_attacker("apt41_dust_attacker",
                                            "multi-service client for APT41 DUST."),
                          apt41_dust_sut()),
        "0.apt41_dust_full": (_generic_attacker("apt41_dust_full_attacker",
                                                  "ssh client for extended APT41 DUST chain."),
                               apt41_dust_full_sut()),
        "0.costaricto": (_generic_attacker("costaricto_attacker",
                                            "ssh+http client for service discovery and proxy."),
                          costaricto_sut()),
        "0.outer_space": (_generic_attacker("outer_space_attacker",
                                              "ssh+http client for browser discovery."),
                           outer_space_sut()),
    }
    if campaign_id in _PER_CAMPAIGN_SUT:
        attacker, sut = _PER_CAMPAIGN_SUT[campaign_id]
        return attacker, sut, []
    if campaign_id in {"0.caldera_linux_demo", "0.fin6_emulation"}:
        # AutoSUT-native references that reuse the c0011 Linux workstation.
        return c0011_attacker(), c0011_sut(), []
    if campaign_id == "0.operation_midnighteclipse":
        cves = [CVEInjection(
            cve_id="CVE-2024-3400",
            target_software="Palo Alto GlobalProtect (surrogate)",
            target_version="surrogate-1.0",
            fidelity=FidelityLevel.adapted,
            realization=Realization.surrogate,
            install_recipe="globalprotect_surrogate",
            reason="Real product is paywalled; surrogate preserves the SESSID "
                   "cookie command-injection semantics.",
        )]
        return midnighteclipse_attacker(), midnighteclipse_sut(), cves
    if campaign_id == "0.salesforce_data_exfiltration":
        cves = [CVEInjection(
            cve_id="N/A_salesforce_surrogate",
            target_software="Salesforce REST API (surrogate)",
            target_version="surrogate-1.0",
            fidelity=FidelityLevel.adapted,
            realization=Realization.surrogate,
            install_recipe="salesforce_api_surrogate",
            reason="No CVE evidence in ATT&CK; surrogate exposes a "
                   "Bearer-token-protected Salesforce-like REST API for "
                   "exercising CRM data exfiltration techniques.",
        )]
        return salesforce_attacker(), salesforce_sut(), cves
    if campaign_id in _CAMPAIGN_STUBS:
        cve, product, fidelity, realization = _CAMPAIGN_STUBS[campaign_id]
        raise NotImplementedError(
            f"Campaign {campaign_id} declared but not yet implemented. "
            f"Target product: {product}. CVE: {cve or 'no CVE evidence'}. "
            f"Planned fidelity: {fidelity.value} / realization: {realization.value}. "
            f"See catalog.py."
        )
    raise KeyError(f"Unknown campaign: {campaign_id}")


def known_campaigns() -> list[str]:
    return ["0.shadowray", *_CAMPAIGN_STUBS.keys()]


def implemented_campaigns() -> list[str]:
    return [
        "0.shadowray",
        "0.c0010", "0.c0011", "0.c0012", "0.c0013", "0.c0015", "0.c0017", "0.c0026",
        "0.apt41_dust", "0.apt41_dust_full",
        "0.costaricto",
        "0.outer_space",
        "0.operation_midnighteclipse",
        "0.salesforce_data_exfiltration",
        "0.caldera_linux_demo",
        "0.fin6_emulation",
        "0.dmz_segmentation_demo",
        "0.pivot_demo",
        "0.web_demo",
        "0.cve_2021_41773",
    ]
