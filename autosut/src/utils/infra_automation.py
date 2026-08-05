"""Audit helpers for infrastructure and SUT automation coverage."""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, Field


HOSTNAME_VM_ALIAS = {
    "target-base": "target-linux-1",
    "target-secondary": "target-linux-2",
    "target-1": "target-linux-1",
    "target-2": "target-linux-2",
    "target-ray": "target-linux-1",
}
CONTROL_PLANE_HOSTS = {"caldera", "attacker"}


class InfraAutomationRow(BaseModel):
    """One campaign/SUT pair in the published subset."""

    campaign_id: str
    sut_profile_id: str
    pair_valid: bool
    pair_error: str = ""
    declared_runtime_vms: list[str] = Field(default_factory=list)
    runtime_vm_count: int
    target_hosts: list[str] = Field(default_factory=list)
    target_host_count: int
    topology_kind: str
    min_hosts: int
    base_service_count: int
    base_user_count: int
    base_file_count: int
    base_weakness_count: int
    step_overlay_count: int
    overlay_service_count: int
    overlay_file_count: int
    overlay_weakness_count: int
    has_latest_evidence: bool


class InfraAutomationTotals(BaseModel):
    published_campaigns: int
    campaigns_with_sut: int
    campaigns_with_strict_pair_validation: int
    campaigns_with_base_weaknesses: int
    campaigns_with_step_overlays: int
    campaigns_with_latest_evidence: int
    campaigns_with_single_target_host: int
    campaigns_with_multi_target_host: int
    campaigns_with_multi_vm_runtime: int


class InfraAutomationSummary(BaseModel):
    generated_from: dict[str, str]
    totals: InfraAutomationTotals
    rows: list[InfraAutomationRow]


def _resolved_runtime_vms(required_vms: list[str], extra_vms: list[str]) -> list[str]:
    resolved: list[str] = []
    for vm_name in [*required_vms, *extra_vms]:
        runtime_name = HOSTNAME_VM_ALIAS.get(vm_name, vm_name)
        if runtime_name not in resolved:
            resolved.append(runtime_name)
    return resolved


def _target_hosts(hosts: dict) -> list[str]:
    return [host_name for host_name in hosts.keys() if host_name not in CONTROL_PLANE_HOSTS]


def _topology_kind(target_host_count: int) -> str:
    return "multi_target" if target_host_count > 1 else "single_target"


def build_infra_automation_summary(
    *,
    project_root: Path,
    campaign_ids: list[str],
    load_campaign,
    load_sut_profile,
    validate_campaign_sut_pair,
    latest_summary,
) -> InfraAutomationSummary:
    rows: list[InfraAutomationRow] = []

    for campaign_id in campaign_ids:
        campaign = load_campaign(campaign_id)
        sut = load_sut_profile(campaign.sut_profile_id)
        pair_error = validate_campaign_sut_pair(campaign_id) or ""
        target_hosts = _target_hosts(sut.hosts)
        runtime_vms = _resolved_runtime_vms(sut.required_vms, sut.extra_vms)

        rows.append(
            InfraAutomationRow(
                campaign_id=campaign_id,
                sut_profile_id=campaign.sut_profile_id,
                pair_valid=pair_error == "",
                pair_error=pair_error,
                declared_runtime_vms=runtime_vms,
                runtime_vm_count=len(runtime_vms),
                target_hosts=target_hosts,
                target_host_count=len(target_hosts),
                topology_kind=_topology_kind(len(target_hosts)),
                min_hosts=sut.min_hosts,
                base_service_count=sum(len(host.services) for host in sut.hosts.values()),
                base_user_count=sum(len(host.users) for host in sut.hosts.values()),
                base_file_count=sum(len(host.files) for host in sut.hosts.values()),
                base_weakness_count=sum(
                    len(host.deliberate_weaknesses) for host in sut.hosts.values()
                ),
                step_overlay_count=sum(
                    1 for step in campaign.steps if step.sut_delta is not None
                ),
                overlay_service_count=sum(
                    len(step.sut_delta.services) for step in campaign.steps if step.sut_delta
                ),
                overlay_file_count=sum(
                    len(step.sut_delta.files) for step in campaign.steps if step.sut_delta
                ),
                overlay_weakness_count=sum(
                    len(step.sut_delta.deliberate_weaknesses)
                    for step in campaign.steps
                    if step.sut_delta
                ),
                has_latest_evidence=latest_summary(campaign_id) is not None,
            )
        )

    totals = InfraAutomationTotals(
        published_campaigns=len(rows),
        campaigns_with_sut=len(rows),
        campaigns_with_strict_pair_validation=sum(1 for row in rows if row.pair_valid),
        campaigns_with_base_weaknesses=sum(1 for row in rows if row.base_weakness_count > 0),
        campaigns_with_step_overlays=sum(1 for row in rows if row.step_overlay_count > 0),
        campaigns_with_latest_evidence=sum(1 for row in rows if row.has_latest_evidence),
        campaigns_with_single_target_host=sum(
            1 for row in rows if row.target_host_count == 1
        ),
        campaigns_with_multi_target_host=sum(
            1 for row in rows if row.target_host_count > 1
        ),
        campaigns_with_multi_vm_runtime=sum(1 for row in rows if row.runtime_vm_count > 1),
    )

    return InfraAutomationSummary(
        generated_from={
            "campaign_dir": "campaigns/",
            "sut_profile_dir": "data/sut_profiles/",
            "evidence_dir": "release/evidence/",
        },
        totals=totals,
        rows=rows,
    )


def markdown_report(summary: InfraAutomationSummary) -> str:
    totals = summary.totals
    lines = [
        "# Infrastructure and SUT Automation Coverage",
        "",
        "This report describes what the current public artifact can provision",
        "automatically for each published campaign/SUT pair. It measures declared",
        "infrastructure and configuration coverage, not historical completeness.",
        "",
        "## Summary",
        "",
        f"- Published campaign/SUT pairs: `{totals.published_campaigns}`",
        f"- Pairs passing strict validation: `{totals.campaigns_with_strict_pair_validation}`",
        f"- Campaigns with base weaknesses configured automatically: `{totals.campaigns_with_base_weaknesses}`",
        f"- Campaigns with step-conditioned overlays: `{totals.campaigns_with_step_overlays}`",
        f"- Campaigns with latest shipped evidence: `{totals.campaigns_with_latest_evidence}`",
        f"- Campaigns with single target host: `{totals.campaigns_with_single_target_host}`",
        f"- Campaigns with multi-target host topology: `{totals.campaigns_with_multi_target_host}`",
        f"- Campaigns with multi-VM runtime substrate: `{totals.campaigns_with_multi_vm_runtime}`",
        "",
        "## Interpretation",
        "",
        (
            "The current public subset already provisions a multi-VM substrate for every "
            "published campaign, automatically applies base weaknesses for every declared "
            "SUT, and supports step-conditioned overlays when a campaign declares them."
        ),
        (
            "At the same time, the published subset is still operationally conservative: "
            "all currently shipped campaign/SUT pairs use one target host even though the "
            "IaC path can resolve multiple declared runtime VMs."
        ),
        "",
        "## Campaign Matrix",
        "",
        "| Campaign | Pair Valid | Runtime VMs | Target Hosts | Topology | Base Weaknesses | Step Overlays | Latest Evidence |",
        "|---|---|---:|---:|---|---:|---:|---|",
    ]

    for row in summary.rows:
        lines.append(
            f"| `{row.campaign_id}` | "
            f"{'yes' if row.pair_valid else 'no'} | "
            f"{row.runtime_vm_count} | {row.target_host_count} | {row.topology_kind} | "
            f"{row.base_weakness_count} | {row.step_overlay_count} | "
            f"{'yes' if row.has_latest_evidence else 'no'} |"
        )

    invalid_rows = [row for row in summary.rows if not row.pair_valid]
    lines.extend(["", "## Validation Exceptions", ""])
    if invalid_rows:
        for row in invalid_rows:
            lines.append(f"- `{row.campaign_id}`: {row.pair_error}")
    else:
        lines.append("- None")

    lines.extend(["", "## Source Paths", ""])
    for name, path in summary.generated_from.items():
        lines.append(f"- `{name}`: `{path}`")
    return "\n".join(lines)


def csv_rows(summary: InfraAutomationSummary) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for row in summary.rows:
        rows.append(
            {
                "campaign_id": row.campaign_id,
                "sut_profile_id": row.sut_profile_id,
                "pair_valid": str(row.pair_valid),
                "pair_error": row.pair_error,
                "declared_runtime_vms": ";".join(row.declared_runtime_vms),
                "runtime_vm_count": str(row.runtime_vm_count),
                "target_hosts": ";".join(row.target_hosts),
                "target_host_count": str(row.target_host_count),
                "topology_kind": row.topology_kind,
                "min_hosts": str(row.min_hosts),
                "base_service_count": str(row.base_service_count),
                "base_user_count": str(row.base_user_count),
                "base_file_count": str(row.base_file_count),
                "base_weakness_count": str(row.base_weakness_count),
                "step_overlay_count": str(row.step_overlay_count),
                "overlay_service_count": str(row.overlay_service_count),
                "overlay_file_count": str(row.overlay_file_count),
                "overlay_weakness_count": str(row.overlay_weakness_count),
                "has_latest_evidence": str(row.has_latest_evidence),
            }
        )
    return rows


def json_report(summary: InfraAutomationSummary) -> str:
    return summary.model_dump_json(indent=2)
