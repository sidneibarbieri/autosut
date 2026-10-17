"""Pydantic data models for the orchestrator tuple and outputs.

These types are intentionally narrow. Each model represents one component of
the campaign tuple (attacker, SUT, CVE set) or one result artifact (per
technique outcome, per CVE fidelity, per run manifest). Reviewers can audit
the manifest schema by reading this file.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class FidelityLevel(str, Enum):
    """Technique execution fidelity - three-tier taxonomy.

    AutoSUT adopts the three-tier vocabulary used by the frozen STICKS
    artifact and the 5-question rubric in :mod:`fidelity_rubric` decides the
    tier for each technique execution.

    - ``faithful``: the central mechanism, the substrate (OS/runtime/service),
      the operational preconditions, the observed effect, AND the auditable
      evidence trail all line up with what a real adversary would produce.
      Q3 (preconditions arose operationally, not pre-staged) is hard to
      satisfy in a controlled lab, so this tier is reserved for the rare
      execution where the pre-staging step itself is automated and the
      ability is dispatched via a canonical tool (e.g., Caldera ART against
      a real vulnerable build).
    - ``adapted``: the technique sequence runs with a realistic mechanism
      (real certificate, real DB query, real RCE against the actual or a
      semantically-equivalent surrogate service). The attacker observes the
      same protocol/state changes a real adversary would, but at least one
      precondition was pre-staged.
    - ``inspired``: the technique is exercised at the *concept* level only.
      No specific protocol or product is invoked; the run records that the
      attacker performed the conceptual action against a generic primitive.

    The frozen artifact ships this taxonomy but in practice scores **zero
    faithful** across all 10 campaigns it ships rubric data for - its lab
    constraints force Q3 to False. AutoSUT keeps the tier in the vocabulary
    so the manifest can declare/report against the canonical taxonomy and
    so future executions that genuinely satisfy Q3 (e.g., a real CVE attack
    chain with no pre-staging) can claim faithful honestly.
    """

    faithful = "faithful"
    adapted = "adapted"
    inspired = "inspired"


class ExecutionMode(str, Enum):
    """How the technique was executed at the mechanism level.

    This dimension is independent of fidelity. The campaign JSONs use it as
    ``expected_mode`` for every technique:

    - ``real_controlled``: a real execution was driven inside the lab - a
      command actually ran, a file was actually written, a network call
      actually traversed the wire. Reviewer can inspect the side effects.
    - ``naive_simulated``: the technique was acknowledged but not
      mechanistically executed (no real syscall, no real network traffic).
      A marker file records the conceptual step.
    - ``caldera_driven``: the execution was dispatched through a MITRE
      Caldera operation. The Caldera REST API + sandcat agent on the target
      are the source of truth for the run.
    - ``atomic_red_team``: the execution invoked an Atomic Red Team atomic
      directly (via Caldera's atomic plugin or as a stand-alone runner).
    """

    real_controlled = "real_controlled"
    naive_simulated = "naive_simulated"
    caldera_driven = "caldera_driven"
    atomic_red_team = "atomic_red_team"


class Realization(str, Enum):
    """How an execution was actually staged on the target side.

    Independent of fidelity AND mode.

    - ``real_cve``: the actual vulnerable software at the disclosed version
      was installed and exploited via its documented CVE surface.
    - ``surrogate``: a minimal service or script reproduces the exploit
      surface with equivalent semantics, used when the real product is
      paywalled or environmentally incompatible.
    - ``generic_primitive``: no exploit surface is recreated; the technique
      runs against a stock primitive (open SSH, exposed DB, generic shell).
    """

    real_cve = "real_cve"
    surrogate = "surrogate"
    generic_primitive = "generic_primitive"


class AttackerProfile(BaseModel):
    """The attacker side: declarative capabilities the campaign needs."""

    profile_id: str
    capabilities: list[str] = Field(default_factory=list)
    notes: Optional[str] = None


class ProvenanceSource(str, Enum):
    """How each SUT element was determined.

    Adopting the methodological recommendation that AutoSUT should make
    visible - per element - *which part of the SUT came from the corpus
    versus the analyst versus AutoSUT's own concretization*.

    - ``corpus_supported``: the value is anchored in CTI/ATT&CK/STIX
      evidence (a CVE pin, an ATT&CK technique software reference, an
      explicit campaign attribution).
    - ``external_reference``: the value is anchored outside the evaluated CTI
      snapshot, for example in a vendor advisory or NVD record.  It is evidence,
      but it must not inflate corpus-derived coverage.
    - ``analyst_authored``: the value is a deliberate analyst choice
      (a topology zone, a privilege boundary, a credential strategy)
      that the corpus does not constrain.
    - ``autosut_concretized``: AutoSUT chose a defensible concrete value
      (e.g. picking ``vulnuser:vulnpass123`` when the corpus says
      "weak credentials" without specifying which).
    - ``inferred``: a heuristic inference from the corpus that the
      reviewer should treat as a lower-confidence assumption.

    The release gate does not enforce specific distributions yet, but
    this tag is the load-bearing primitive for the provenance table the
    paper will report (corpus_supported % vs analyst_authored % vs ...).
    """

    corpus_supported = "corpus_supported"
    external_reference = "external_reference"
    analyst_authored = "analyst_authored"
    autosut_concretized = "autosut_concretized"
    inferred = "inferred"


class Credential(BaseModel):
    """One pre-staged credential on the SUT.

    Declarative so the manifest preserves *what realism the SUT claims to
    contribute*. ``purpose`` is the reviewer-facing rationale for why this
    credential exists: a Q3-honest lab pre-staging always declares its
    purpose rather than leaving the reader to infer it.
    """

    kind: str  # "password" | "ssh_key" | "api_token" | "session_cookie"
    user: str
    secret: str
    location: Optional[str] = None
    purpose: str = ""  # "ssh_login" | "service_auth" | "decoy" | ...
    source: ProvenanceSource = ProvenanceSource.analyst_authored


class StagedArtifact(BaseModel):
    """Data planted on the SUT before techniques run.

    Examples: a decoy ``/home/labuser/secret.txt``, a vulnerable web app
    payload at ``/var/www/html/index.html``, an SSH key in
    ``~/.ssh/authorized_keys``.
    """

    path: str
    content_text: Optional[str] = None
    content_b64: Optional[str] = None  # for binary blobs
    owner: str = "root"
    mode: str = "0644"
    purpose: str = ""
    source: ProvenanceSource = ProvenanceSource.analyst_authored


class NetworkExposure(BaseModel):
    """A port the SUT exposes inside the per-run private network.

    Hosts on the private network see each other directly; the host port
    forwarding is declared at the orchestrator level when needed. This
    model is a manifest-facing audit record of intentional exposure.
    """

    port: int
    protocol: str = "tcp"  # "tcp" | "udp"
    service: str = ""  # "ssh" | "http" | "mysql" | ...
    expose_to: str = "private_network"  # "private_network" | "loopback"
    purpose: str = ""
    source: ProvenanceSource = ProvenanceSource.analyst_authored


class ApplicationStack(BaseModel):
    """A pre-installed application stack on the SUT.

    Encodes the *realism contribution* of running a specific vulnerable
    version of a real product. ``cve_pins`` ties this stack to one or
    more disclosed CVEs so a reviewer can verify the version-to-CVE
    binding against MITRE NVD.

    ``recipe`` names a function in :mod:`sut_applications` that knows how
    to install + configure this stack on the host. Recipes are the only
    place imperative code lives; the rest of the composition is purely
    declarative.
    """

    name: str  # "apache_httpd" | "tomcat" | "log4j_app" | ...
    version: str  # exact version, e.g. "2.4.49"
    recipe: str  # name in sut_applications registry
    cve_pins: list[str] = Field(default_factory=list)
    config: dict[str, str] = Field(default_factory=dict)
    image_override: Optional[str] = None
    purpose: str = ""
    source: ProvenanceSource = ProvenanceSource.analyst_authored


class SUTComposition(BaseModel):
    """The full declarative SUT realism for one host."""

    credentials: list[Credential] = Field(default_factory=list)
    artifacts: list[StagedArtifact] = Field(default_factory=list)
    exposures: list[NetworkExposure] = Field(default_factory=list)
    applications: list[ApplicationStack] = Field(default_factory=list)
    notes: Optional[str] = None


class Zone(BaseModel):
    """A declarative network zone.

    A zone is a Docker network in our materialization, plus a human-facing
    label (``"internet_edge"``, ``"dmz"``, ``"enterprise"``,
    ``"crown_jewel"``). Hosts attach to one or more zones; hosts in two
    zones are *gateways* and bridge them.

    Honest scope: AutoSUT declares and materializes zones as separate
    Docker bridge networks. We do NOT enforce L7 firewall policy between
    zones - that would require iptables/eBPF policy injection per zone,
    which is out of scope for the artefact. The realism we ship is
    **topology declaration parity with enterprise designs**, not
    enterprise firewall fidelity.
    """

    name: str  # e.g. "internet_edge", "dmz", "enterprise"
    description: str = ""
    cidr: Optional[str] = None  # human-facing, e.g. "172.30.0.0/24"
    # Topology is the dimension public CTI supports least - ATT&CK/STIX
    # campaigns rarely pin zone counts, segmentation, or trust boundaries. A
    # zone is therefore almost always an analyst lab choice; tagging it makes
    # that explicit rather than letting topology masquerade as corpus evidence.
    source: ProvenanceSource = ProvenanceSource.analyst_authored


class Topology(BaseModel):
    """Declarative topology that the orchestrator materializes as Docker
    networks. Each :class:`Zone` becomes one Docker network; the catalog
    declares which hosts attach to which zones, and which hosts act as
    gateways (dual-homed).
    """

    zones: list[Zone] = Field(default_factory=list)
    notes: Optional[str] = None


class SUTHost(BaseModel):
    """One host inside a multi-host SUT topology.

    A campaign that pivots between attacker -> target1 -> target2 declares
    three :class:`SUTHost` entries in :attr:`SUTProfile.hosts`. The
    orchestrator brings up one :class:`EnvironmentBackend` per host on a
    shared private network so the executor can run techniques on any host
    and exercise cross-host moves (T1021 lateral movement, T1570 lateral
    tool transfer, T1572 protocol tunneling).

    ``startup_commands`` are executed in order after the host boots and
    before techniques run. They are part of the campaign's auditable
    pre-staging (Q3 of the fidelity rubric - lab preconditions are
    declared, not discovered).

    ``zones`` is the list of zone names this host attaches to. A
    host listed in multiple zones is a *gateway* that bridges them - for
    example an nginx host in both ``dmz`` and ``enterprise`` zones acts
    as a dual-homed chokepoint. When empty (default), the host attaches
    only to the per-run private network.
    """

    name: str  # e.g. "attacker", "target1", "target2"
    base_image: str
    platform_source: ProvenanceSource = ProvenanceSource.analyst_authored
    role: str = "target"  # "attacker" | "target" | "auxiliary" | "gateway"
    services: list[str] = Field(default_factory=list)
    memory_mb: int = 1024
    smp: int = 1
    startup_commands: list[str] = Field(default_factory=list)
    composition: Optional[SUTComposition] = None  # declarative realism
    zones: list[str] = Field(default_factory=list)  # zone attachments


class SUTProfile(BaseModel):
    """The target side: declarative environment shape (no CVEs).

    ``backend`` selects the execution substrate used to materialise the
    SUT. ``"docker"`` (default) is the canonical portable path; ``"qemu"``
    is the extended-realism VM path (Vagrant + QEMU, ARM64-friendly on
    Apple Silicon, libvirt on Linux); ``"tart"`` is an experimental
    Apple-only fast-path.

    Single-host campaigns declare ``base_image``/``memory_mb``/``smp``
    directly. Multi-host campaigns set ``hosts`` to a list of
    :class:`SUTHost` entries - in that case the base fields are still set
    (for backwards-compat with the single-host orchestrator path) and the
    hosts list takes precedence.
    """

    sut_id: str
    base_image: str
    platform_source: ProvenanceSource = ProvenanceSource.analyst_authored
    services: list[str] = Field(default_factory=list)
    memory_mb: int = 2048
    smp: int = 2
    backend: Optional[str] = None  # "docker" | "qemu" | "windows-qemu" | "tart" | None=>docker
    hosts: Optional[list[SUTHost]] = None
    composition: Optional[SUTComposition] = None  # single-host composition
    topology: Optional[Topology] = None  # multi-zone declaration
    notes: Optional[str] = None

    @property
    def is_multi_host(self) -> bool:
        return bool(self.hosts)


class CVEInjection(BaseModel):
    """One CVE to inject into the SUT, with declared fidelity + realization."""

    cve_id: str
    target_software: str
    target_version: Optional[str] = None
    fidelity: FidelityLevel
    realization: Realization
    install_recipe: str
    source: ProvenanceSource = ProvenanceSource.corpus_supported
    reason: Optional[str] = None  # why this combination was chosen


class CVEFidelity(BaseModel):
    """Audit record for one CVE after injection executed."""

    cve_id: str
    fidelity: FidelityLevel
    realization: Realization
    success: bool
    log_path: str
    notes: Optional[str] = None


class TechniqueOutcome(BaseModel):
    """Per-technique outcome captured during campaign execution.

    Four orthogonal dimensions are recorded:

    - ``declared_fidelity``/``executed_fidelity``: the WHAT (adapted vs
      inspired), as declared by the campaign JSON and as actually achieved.
    - ``declared_mode``/``executed_mode``: the HOW (real_controlled,
      naive_simulated, caldera_driven, atomic_red_team), again declared by
      the campaign JSON and as actually achieved.
    - ``realization``: how the target side was staged (real_cve, surrogate,
      generic_primitive).
    - ``status``: outcome bucket (success | failure | skipped).
    """

    technique_id: str
    declared_fidelity: FidelityLevel
    executed_fidelity: FidelityLevel
    declared_mode: ExecutionMode
    executed_mode: ExecutionMode
    realization: Realization
    status: str  # "success" | "failure" | "skipped"
    evidence_files: list[str] = Field(default_factory=list)
    duration_sec: float = 0.0
    notes: Optional[str] = None
    # A matching Caldera ability is catalog provenance. It is execution
    # evidence only when executed_mode records a dispatched execution path.
    caldera_ability_id: Optional[str] = None
    caldera_ability_name: Optional[str] = None


class RunResult(BaseModel):
    """Top-level manifest written for every campaign run."""

    campaign_id: str
    run_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    attacker: AttackerProfile
    sut: SUTProfile
    cves_injected: list[CVEFidelity] = Field(default_factory=list)
    techniques: list[TechniqueOutcome] = Field(default_factory=list)
    teardown_clean: bool = False
    manifest_path: Optional[str] = None
    summary_path: Optional[str] = None
    campaign_state_path: Optional[str] = None

    @property
    def total_techniques(self) -> int:
        return len(self.techniques)

    @property
    def successful(self) -> int:
        return sum(1 for outcome in self.techniques if outcome.status == "success")

    @property
    def evidence_backed_successful(self) -> int:
        """Successful steps that executed a controlled action with evidence."""

        return sum(
            1
            for outcome in self.techniques
            if outcome.status == "success"
            and outcome.executed_mode != ExecutionMode.naive_simulated
            and bool(outcome.evidence_files)
        )

    @property
    def adapted_successful(self) -> int:
        """Evidence-backed successful steps at adapted fidelity."""

        return sum(
            1
            for outcome in self.techniques
            if outcome.status == "success"
            and outcome.executed_mode != ExecutionMode.naive_simulated
            and outcome.executed_fidelity == FidelityLevel.adapted
            and bool(outcome.evidence_files)
        )

    @property
    def marker_only_successful(self) -> int:
        """Status-success steps represented only by a simulated marker."""

        return sum(
            1
            for outcome in self.techniques
            if outcome.status == "success"
            and outcome.executed_mode == ExecutionMode.naive_simulated
        )

    @property
    def caldera_driven_successful(self) -> int:
        """Successful steps that Caldera actually dispatched."""

        return sum(
            1
            for outcome in self.techniques
            if outcome.status == "success"
            and outcome.executed_mode == ExecutionMode.caldera_driven
            and bool(outcome.evidence_files)
        )

    @property
    def fidelity_distribution(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for outcome in self.techniques:
            level = outcome.executed_fidelity.value
            counts[level] = counts.get(level, 0) + 1
        return counts
