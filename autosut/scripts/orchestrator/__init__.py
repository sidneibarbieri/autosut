"""Per-campaign isolated SUT orchestrator.

See docs/CAMPAIGN_ORCHESTRATION.md for the architectural rationale.

Public entrypoints:

    from orchestrator import CampaignOrchestrator, build_default

    orch = build_default()
    result = orch.run_campaign("0.shadowray")
    print(result.manifest_path)
"""

from .models import (
    AttackerProfile,
    CVEFidelity,
    CVEInjection,
    ExecutionMode,
    FidelityLevel,
    Realization,
    RunResult,
    SUTProfile,
    TechniqueOutcome,
)
from .orchestrator import CampaignOrchestrator, build_default

__all__ = [
    "AttackerProfile",
    "CVEFidelity",
    "CVEInjection",
    "ExecutionMode",
    "FidelityLevel",
    "Realization",
    "RunResult",
    "SUTProfile",
    "TechniqueOutcome",
    "CampaignOrchestrator",
    "build_default",
]
