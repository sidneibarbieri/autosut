"""Explicit maturity levels for every capability the substrate claims.

Presence of code is not a supported capability. Each capability carries one level, and the level
is bounded by the evidence that exists for it: a capability may only reach reproducible after
independently-verified clean reruns. A main claim additionally requires a clean-room or independent
reproduction context; author-environment runs are necessary evidence, not a claim-ready result. The
record is self-checking, so a level cannot be recorded without the evidence it implies.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, model_validator


class CapabilityLevel(str, Enum):
    """How far a capability has actually been demonstrated, weakest to strongest."""

    SPECIFIED = "specified"                    # a schema or contract exists
    IMPLEMENTED = "implemented"                # concrete code exists, untested here
    COMPONENT_TESTED = "component_tested"      # an isolated unit test passed
    INTEGRATION_TESTED = "integration_tested"  # passed against real dependencies
    END_TO_END_VALIDATED = "end_to_end_validated"  # the full lifecycle passed once, for real
    REPRODUCIBLE = "reproducible"  # a full clean run-set on one recorded implementation revision
    # Terminal qualifiers, not points on the maturity axis:
    DEVELOPMENT_IN_PROGRESS = "development_in_progress"  # active work, not yet qualified
    BLOCKED = "blocked"          # the contract exists but the environment is not qualified
    UNSUPPORTED = "unsupported"  # the requirements are outside the declared domain
    SURROGATE = "surrogate"      # a declared stand-in, never the real mechanism
    MOCK = "mock"                # a test double, never on the canonical path


class ReproductionContext(str, Enum):
    """A separate axis from maturity: where a reproducible result was reproduced."""

    AUTHOR_ENVIRONMENT = "author_environment"
    CLEAN_ROOM = "clean_room"
    INDEPENDENT_ENVIRONMENT = "independent_environment"


# Only reproducible may support a main claim: one clean run is not reproducibility.
_CLAIM_SUPPORTING = frozenset({CapabilityLevel.REPRODUCIBLE})
_CLAIM_READY_CONTEXTS = frozenset(
    {ReproductionContext.CLEAN_ROOM, ReproductionContext.INDEPENDENT_ENVIRONMENT}
)

# These levels assert real execution happened and therefore require observed clean runs.
_REQUIRES_RUNS = {
    CapabilityLevel.END_TO_END_VALIDATED: 1,
    CapabilityLevel.REPRODUCIBLE: 5,
}


class CapabilityRecord(BaseModel):
    """One capability, its demonstrated level, and the evidence that bounds it."""

    model_config = ConfigDict(extra="forbid")

    capability: str
    level: CapabilityLevel
    clean_runs_observed: int = 0
    implementation_revision: str | None = None
    # True only when the run-set that earned the level ran on the revision now present. A set on an
    # earlier revision is preserved evidence of that revision, but does not qualify the current one.
    applies_to_current_revision: bool = True
    reproduction_context: ReproductionContext = ReproductionContext.AUTHOR_ENVIRONMENT
    evidence_paths: list[str] = []
    note: str = ""

    @model_validator(mode="after")
    def _level_is_backed_by_evidence(self) -> "CapabilityRecord":
        required = _REQUIRES_RUNS.get(self.level)
        if required is not None and self.clean_runs_observed < required:
            raise ValueError(
                f"{self.capability}: level {self.level.value} requires at least {required} clean "
                f"run(s) but only {self.clean_runs_observed} recorded"
            )
        if required is not None and self.implementation_revision is None:
            # An observed execution without revision provenance remains useful historical
            # evidence, but it cannot qualify whichever source tree happens to be present.
            self.applies_to_current_revision = False
        if self.level in _CLAIM_SUPPORTING and not self.evidence_paths:
            raise ValueError(
                f"{self.capability}: level {self.level.value} may back a claim and so must cite "
                f"evidence_paths"
            )
        if self.level in _CLAIM_SUPPORTING and not self.implementation_revision:
            raise ValueError(
                f"{self.capability}: reproducible must name the implementation_revision its "
                f"run-set ran on"
            )
        return self

    @property
    def may_support_a_claim(self) -> bool:
        """Return whether this result may support a main claim.

        A repeatable author-machine run is a qualification milestone, not reviewer-path evidence.
        Claim readiness additionally requires the current revision and a clean-room or independent
        context. This prevents an implementation from promoting itself merely because its own host
        can repeat a run.
        """
        return (
            self.level in _CLAIM_SUPPORTING
            and self.applies_to_current_revision
            and self.reproduction_context in _CLAIM_READY_CONTEXTS
        )


class CapabilityLedger(BaseModel):
    """The honest, machine-checkable roster of what the substrate can actually do."""

    model_config = ConfigDict(extra="forbid")

    records: list[CapabilityRecord]

    @model_validator(mode="after")
    def _capabilities_are_unique(self) -> "CapabilityLedger":
        names = [record.capability for record in self.records]
        duplicates = {name for name in names if names.count(name) > 1}
        if duplicates:
            raise ValueError(f"duplicate capability records: {sorted(duplicates)}")
        return self

    def claim_supporting(self) -> list[CapabilityRecord]:
        """The capabilities mature enough to back a manuscript claim."""
        return [record for record in self.records if record.may_support_a_claim]
