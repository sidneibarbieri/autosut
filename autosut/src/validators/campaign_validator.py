#!/usr/bin/env python3
"""Campaign validation utilities."""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from executors.executor_registry import registry
from executors.models import Campaign, TechniqueStep
from loaders.campaign_loader import load_campaign
from runners.campaign_runner import BASE_CAPABILITIES


@dataclass
class ValidationIssue:
    technique_id: str
    message: str
    missing_capabilities: List[str] = field(default_factory=list)


@dataclass
class ValidationReport:
    campaign_id: str
    missing_executors: List[ValidationIssue] = field(default_factory=list)
    capability_gaps: List[ValidationIssue] = field(default_factory=list)
    invalid_steps: List[str] = field(default_factory=list)
    all_steps_resolvable: bool = True
    broken_dependency_chain: bool = False
    step_results: List[Dict[str, object]] = field(default_factory=list)

    @property
    def valid(self) -> bool:
        return (
            not self.missing_executors
            and not self.capability_gaps
            and self.all_steps_resolvable
            and not self.broken_dependency_chain
        )

    def log(self) -> None:
        print(f"[VALIDATION] Campaign {self.campaign_id} valid={self.valid}")
        if self.missing_executors:
            print("  Missing executors:")
            for issue in self.missing_executors:
                print(f"    - {issue.technique_id}: {issue.message}")
        if self.capability_gaps:
            print("  Capability gaps:")
            for issue in self.capability_gaps:
                print(
                    f"    - {issue.technique_id}: missing {issue.missing_capabilities}"
                )
        if self.invalid_steps:
            print("  Invalid steps:")
            for step in self.invalid_steps:
                print(f"    - {step}")


def validate_campaign(
    campaign: Campaign,
    initial_capabilities: Set[str],
) -> ValidationReport:
    """Validate campaign structure and executor availability."""

    report = ValidationReport(campaign_id=campaign.campaign_id)
    available_caps = set(initial_capabilities)

    for step in campaign.steps:
        step_result = _validate_step(step, available_caps, report)
        report.step_results.append(step_result)
        # Always accumulate declared produces to continue chain analysis
        available_caps.update(step.produces)

    return report


def _validate_step(
    step: TechniqueStep,
    available_caps: Set[str],
    report: ValidationReport,
) -> Dict[str, object]:
    executor = registry.get_executor(step.technique_id)
    if executor is None:
        report.missing_executors.append(
            ValidationIssue(step.technique_id, "Executor not registered")
        )
        report.all_steps_resolvable = False
        report.invalid_steps.append(step.technique_id)
        return {
            "technique_id": step.technique_id,
            "status": "missing_executor",
            "requires": step.requires,
            "produces": step.produces,
        }

    missing_caps = [req for req in step.requires if req not in available_caps]
    if missing_caps:
        report.capability_gaps.append(
            ValidationIssue(step.technique_id, "Missing capabilities", missing_caps)
        )
        report.all_steps_resolvable = False
        report.invalid_steps.append(step.technique_id)
        return {
            "technique_id": step.technique_id,
            "status": "missing_capability",
            "requires": step.requires,
            "produces": step.produces,
            "missing_capabilities": missing_caps,
            "available_capabilities": sorted(available_caps),
        }

    return {
        "technique_id": step.technique_id,
        "status": "ok",
        "requires": step.requires,
        "produces": step.produces,
    }


def validate_campaign_structure(
    campaign_id: str,
    initial_capabilities: Optional[Set[str]] = None,
) -> Dict[str, object]:
    """Convenience wrapper to load and validate a campaign by ID.

    Returns a serialisable dictionary report for programmatic consumption.
    """

    campaign: Campaign = load_campaign(campaign_id)
    caps = set(initial_capabilities or BASE_CAPABILITIES)
    report = validate_campaign(campaign, caps)

    return {
        "campaign_id": campaign_id,
        "valid": report.valid,
        "missing_executors": [issue.__dict__ for issue in report.missing_executors],
        "capability_gaps": [issue.__dict__ for issue in report.capability_gaps],
        "invalid_steps": report.invalid_steps,
        "all_steps_resolvable": report.all_steps_resolvable,
        "broken_dependency_chain": report.broken_dependency_chain,
        "steps": report.step_results,
    }


__all__ = [
    "validate_campaign",
    "validate_campaign_structure",
    "ValidationReport",
]
