"""
Formal domain model for AutoSUT.

Four-layer architecture:
  1. Campaign — defines what happens: techniques, order, dependencies, fidelity expectations.
  2. SUTProfile — defines where it happens: hosts, services, credentials, weaknesses, topology.
  3. Executor — defines how each technique is realized in a given substrate (separate module).
  4. Evidence — defines what was observed: timestamps, artifacts, fidelity classification.

These models are pure DTOs. No side effects, no I/O, no orchestration logic.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class ExecutionFidelity(str, Enum):
    """Methodological classification of execution fidelity."""

    FAITHFUL = "faithful"
    ADAPTED = "adapted"
    INSPIRED = "inspired"


class ExecutionMode(str, Enum):
    """How the executor materializes the technique.

    The last two values were added when AutoSUT integrated MITRE Caldera as a
    live backend (S7-S9). Kept in lock-step with
    ``scripts/orchestrator/models.py::ExecutionMode``.
    """

    REAL_CONTROLLED = "real_controlled"
    NAIVE_SIMULATED = "naive_simulated"
    STATE_BRIDGE = "state_bridge"
    CALDERA_DRIVEN = "caldera_driven"
    ATOMIC_RED_TEAM = "atomic_red_team"


class Platform(str, Enum):
    LINUX = "linux"
    WINDOWS = "windows"
    MACOS = "macos"
    ANY = "any"


class Privilege(str, Enum):
    USER = "user"
    ADMIN = "admin"
    SYSTEM = "system"


# ---------------------------------------------------------------------------
# Layer 1 — Campaign
# ---------------------------------------------------------------------------


class TechniqueStep(BaseModel):
    """A single step in a campaign's attack chain."""

    technique_id: str = Field(description="MITRE ATT&CK technique ID (e.g. T1059.001)")
    technique_name: str = Field(description="Human-readable name")
    tactic: str = Field(
        default="",
        description="ATT&CK tactic label associated with the technique in this campaign",
    )
    platform: str = Field(
        default="",
        description="Execution platform declared by the published campaign metadata",
    )
    order: int = Field(description="Execution order within the campaign (1-based)")
    requires: List[str] = Field(
        default_factory=list,
        description="Logical preconditions (capabilities that must exist before execution)",
    )
    produces: List[str] = Field(
        default_factory=list,
        description="Capabilities produced upon successful execution",
    )
    expected_fidelity: ExecutionFidelity = Field(
        description="Expected fidelity classification for this technique in this campaign",
    )
    expected_mode: ExecutionMode = Field(
        default=ExecutionMode.REAL_CONTROLLED,
        description="Expected execution mode",
    )
    fidelity_rationale: str = Field(
        default="",
        description="Why this fidelity level is expected (e.g. platform mismatch)",
    )
    procedure_summary: str = Field(
        default="",
        description="Published step-level procedure summary or ATT&CK-grounded description",
    )
    sut_delta: Optional["TechniqueSUTDelta"] = Field(
        default=None,
        description=(
            "Optional step-conditioned SUT overlay applied immediately before "
            "this technique in VM-backed executions."
        ),
    )


class Campaign(BaseModel):
    """
    Layer 1: the operational playbook.

    Defines WHAT the adversary does, in WHICH order, with WHICH dependencies
    and WHICH fidelity is expected for each step.
    """

    campaign_id: str = Field(description="Unique identifier (e.g. 0.c0011)")
    name: str = Field(description="Descriptive campaign name")
    description: str = Field(default="")
    sut_profile_id: str = Field(
        description="ID of the required SUT profile (matches filename in data/sut_profiles/)",
    )
    steps: List[TechniqueStep] = Field(
        description="Ordered list of technique steps",
    )
    objective: str = Field(
        default="",
        description="High-level adversary objective",
    )

    def technique_ids(self) -> List[str]:
        return [step.technique_id for step in self.steps]

    def required_capabilities(self) -> List[str]:
        """All capabilities required across all steps (union)."""
        all_reqs = set()
        for step in self.steps:
            all_reqs.update(step.requires)
        return sorted(all_reqs)


# ---------------------------------------------------------------------------
# Layer 2 — SUT Profile
# ---------------------------------------------------------------------------


class SUTService(BaseModel):
    """A service running on a SUT host."""

    name: str
    version: str = "default"
    config: str = ""
    cgi_enabled: bool = False


class SUTUser(BaseModel):
    """A user account on a SUT host."""

    username: str
    password: str
    sudo: bool = False
    home_files: bool = False


class SUTFile(BaseModel):
    """A file pre-staged on a SUT host."""

    path: str
    content: str
    owner: str
    permissions: str = "644"


class SUTWeakness(BaseModel):
    """A deliberate weakness configured on the SUT for a specific technique."""

    weakness_type: str = Field(alias="type")
    description: str
    impact: str = ""
    target: str = ""
    username: str = ""
    password: str = ""
    path: str = ""
    binary: str = ""
    cve: str = ""
    services: List[str] = Field(default_factory=list)

    model_config = {"populate_by_name": True}


class NetworkConfig(BaseModel):
    """Network configuration for a SUT host."""

    ingress: List[int] = Field(default_factory=list)
    egress: List[str] = Field(default_factory=list)


class SUTHost(BaseModel):
    """Configuration of a single host in the SUT."""

    os: str = "ubuntu-2204"
    role: str = ""
    services: List[SUTService] = Field(default_factory=list)
    users: List[SUTUser] = Field(default_factory=list)
    files: List[SUTFile] = Field(default_factory=list)
    network: NetworkConfig = Field(default_factory=NetworkConfig)
    deliberate_weaknesses: List[SUTWeakness] = Field(default_factory=list)


class SUTProfile(BaseModel):
    """
    Layer 2: the experimental environment.

    Defines WHERE the campaign runs: hosts, OS, services, credentials,
    deliberate weaknesses, network topology, and fidelity expectations.
    """

    campaign_id: str
    description: str = ""
    min_hosts: int = 3
    required_vms: List[str] = Field(default_factory=list)
    extra_vms: List[str] = Field(default_factory=list)
    estimated_duration_minutes: int = 5
    hosts: Dict[str, SUTHost] = Field(
        default_factory=dict,
        description="Mapping of host-name -> host configuration",
    )
    fidelity_expectations: Dict[str, ExecutionFidelity] = Field(
        default_factory=dict,
        description="Technique ID -> expected fidelity",
    )
    execution_mode: str = "real_controlled"
    methodology_notes: str = ""

    def all_weaknesses(self) -> List[SUTWeakness]:
        """Collect every deliberate weakness across all hosts."""
        result = []
        for host in self.hosts.values():
            result.extend(host.deliberate_weaknesses)
        return result


class TechniqueSUTDelta(BaseModel):
    """Step-conditioned overlay applied to the declared base SUT."""

    target_host: str = Field(
        default="",
        description="Host alias within the SUT profile; blank means the primary target host",
    )
    services: List[SUTService] = Field(default_factory=list)
    users: List[SUTUser] = Field(default_factory=list)
    files: List[SUTFile] = Field(default_factory=list)
    deliberate_weaknesses: List[SUTWeakness] = Field(default_factory=list)
    notes: str = Field(
        default="",
        description="Human-readable rationale for the overlay",
    )


# ---------------------------------------------------------------------------
# Capability tracking
# ---------------------------------------------------------------------------


class Capability(BaseModel):
    """
    A capability produced or consumed during campaign execution.

    Capabilities form the dependency graph between technique steps.
    """

    name: str = Field(description="Capability identifier (e.g. access:initial)")
    produced_by: str = Field(default="", description="Technique ID that produced it")
    produced_at: Optional[datetime] = None
    host: str = Field(default="", description="Host where the capability exists")


# ---------------------------------------------------------------------------
# Layer 4 — Evidence
# ---------------------------------------------------------------------------


class FidelityAssessment(BaseModel):
    """
    Honest classification of how faithfully a technique was executed.

    This is the bridge between what the campaign expected and what
    actually happened in the substrate.
    """

    declared: ExecutionFidelity = Field(
        description="Fidelity declared by the executor metadata",
    )
    verified: ExecutionFidelity = Field(
        description="Fidelity after post-execution verification",
    )
    justification: str = Field(
        description="Explicit explanation of why this fidelity level was assigned",
    )
    platform_mismatch: bool = Field(
        default=False,
        description="True if technique was designed for a different platform than the substrate",
    )
    original_platform: Platform = Platform.ANY
    execution_platform: Platform = Platform.LINUX


class TechniqueEvidence(BaseModel):
    """Evidence for a single technique execution."""

    technique_id: str
    technique_name: str = ""
    status: str = Field(description="success | failed | skipped")
    execution_mode: ExecutionMode
    fidelity: FidelityAssessment
    artifacts: List[str] = Field(default_factory=list)
    capabilities_consumed: List[str] = Field(default_factory=list)
    capabilities_produced: List[str] = Field(default_factory=list)
    stdout: str = ""
    stderr: str = ""
    start_time: datetime
    end_time: datetime
    duration_ms: int = 0
    host: str = ""
    sut_adjustments_applied: List[str] = Field(default_factory=list)
    sut_adjustment_errors: List[str] = Field(default_factory=list)


class ArtifactMetadata(BaseModel):
    """
    ACM-aligned metadata for artifact evaluation.

    Maps to ACM's artifact evaluation axes:
    - Reproducibility: can results be obtained independently?
    - Exercitability: can the artifact be run as documented?
    - Consistency: do outputs match claims in the paper?

    This is NOT ACM terminology used directly — it is our alignment layer
    between the STICKS fidelity taxonomy and ACM evaluation criteria.
    """

    automation_level: str = Field(
        default="zero-touch",
        description="Level of automation: zero-touch | semi-automated | manual",
    )
    reproducibility_notes: str = Field(
        default="",
        description="What a reviewer needs to reproduce this execution",
    )
    known_limitations: List[str] = Field(
        default_factory=list,
        description="Explicit limitations affecting reproducibility or validity",
    )
    platform_requirements: str = Field(
        default="",
        description="Hardware/OS requirements for the reviewer",
    )
    estimated_duration_minutes: int = Field(
        default=0,
        description="Estimated wall-clock time for full execution",
    )
    rubric_consistent: bool = Field(
        default=False,
        description="True if all fidelity labels pass the 5-criterion rubric",
    )


class CampaignEvidence(BaseModel):
    """
    Complete evidence record for a campaign execution.

    This is what gets saved to release/evidence/<execution_id>/.
    """

    campaign_id: str
    sut_profile_id: str
    execution_mode: str = "unified_runner"
    start_time: datetime
    end_time: Optional[datetime] = None
    total_techniques: int = 0
    successful: int = 0
    failed: int = 0
    skipped: int = 0
    fidelity_distribution: Dict[str, int] = Field(default_factory=dict)
    technique_results: List[TechniqueEvidence] = Field(default_factory=list)
    accumulated_capabilities: List[str] = Field(default_factory=list)
    sut_profile_path: str = ""
    infrastructure_provider: str = ""
    artifact_metadata: ArtifactMetadata = Field(default_factory=ArtifactMetadata)

    def compute_summary(self):
        """Recompute summary fields from technique_results."""
        self.total_techniques = len(self.technique_results)
        self.successful = sum(
            1 for r in self.technique_results if r.status == "success"
        )
        self.failed = sum(
            1 for r in self.technique_results if r.status in {"failed", "error"}
        )
        self.skipped = sum(1 for r in self.technique_results if r.status == "skipped")

        dist: Dict[str, int] = {}
        for r in self.technique_results:
            key = r.fidelity.verified.value
            dist[key] = dist.get(key, 0) + 1
        self.fidelity_distribution = dist

        caps = set()
        for r in self.technique_results:
            caps.update(r.capabilities_produced)
        self.accumulated_capabilities = sorted(caps)


TechniqueStep.model_rebuild()
