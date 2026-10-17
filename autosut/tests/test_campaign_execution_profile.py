"""Consolidating campaign evidence before consulting a proposer.

The artifact resolves campaign CVEs to installable packages and extracts platform constraints
from the bundle, but in separate records. These tests pin the join and the narrowing that
follows it: a single deployable candidate is selected without a proposer, several candidates
leave a real choice, and none is reported as unsupported instead of being filled in.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from planning.campaign_execution_profile import (  # noqa: E402
    SelectionOutcome,
    build_profile,
)

PLATFORM_REQUIREMENT = {
    "kind": "platform",
    "acceptable_values": ["Linux"],
    "source": "stix_field",
}
ROLE_REQUIREMENT = {
    "kind": "service",
    "acceptable_values": ["public-facing-application"],
    "source": "curated_rule",
}


def _row(package: str, campaign: str = "ShadowRay", supported: bool = True) -> dict:
    return {
        "campaign_name": campaign,
        "cve_id": "CVE-2023-48022",
        "package_name": package,
        "ecosystem": "pip",
        "install_channel": "pip",
        "candidate_versions": ["2.6.3", "2.8.0"],
        "automatic_sut_support": supported,
        "overlay_template": "ray_jobs_api_exposure",
    }


def test_a_single_resolved_package_is_selected_without_a_proposer():
    profile = build_profile(
        "C0045", "ShadowRay", [PLATFORM_REQUIREMENT, ROLE_REQUIREMENT], [_row("ray")]
    )
    assert profile.outcome is SelectionOutcome.deterministic
    assert profile.selected is not None
    assert profile.selected.package_name == "ray"
    assert profile.consults_proposer is False


def test_several_packages_leave_the_choice_open():
    profile = build_profile(
        "C0045", "ShadowRay", [PLATFORM_REQUIREMENT], [_row("ray"), _row("ray-nightly")]
    )
    assert profile.outcome is SelectionOutcome.ambiguous
    assert profile.selected is None
    assert profile.consults_proposer is True


def test_no_resolved_package_is_reported_as_unsupported():
    profile = build_profile("C0010", "Operation Wocao", [PLATFORM_REQUIREMENT], [])
    assert profile.outcome is SelectionOutcome.unsupported
    assert profile.selected is None
    # Failing open matters: an unsupported campaign must not be filled in silently.
    assert profile.consults_proposer is False


def test_a_package_without_automatic_support_is_not_a_candidate():
    profile = build_profile(
        "C0045", "ShadowRay", [PLATFORM_REQUIREMENT], [_row("ray", supported=False)]
    )
    assert profile.outcome is SelectionOutcome.unsupported


def test_the_profile_carries_the_evidence_a_proposer_would_otherwise_lack():
    profile = build_profile(
        "C0045", "ShadowRay", [PLATFORM_REQUIREMENT, ROLE_REQUIREMENT], [_row("ray")]
    )
    assert profile.cve_ids == ["CVE-2023-48022"]
    assert profile.platform_values == ["Linux"]
    assert profile.role_requirements == ["public-facing-application"]
    assert profile.selected.candidate_versions == ["2.6.3", "2.8.0"]


def test_the_released_shadowray_evidence_selects_ray_deterministically():
    rows = json.loads(
        (PROJECT_ROOT / "release" / "cve_resolution_candidates.json").read_text(
            encoding="utf-8"
        )
    )["rows"]
    requirements = json.loads(
        (PROJECT_ROOT / "release" / "plans" / "C0045.sut-constraints.json").read_text(
            encoding="utf-8"
        )
    )["requirements"]
    profile = build_profile("C0045", "ShadowRay", requirements, rows)
    assert profile.outcome is SelectionOutcome.deterministic
    assert profile.selected.package_name == "ray"
