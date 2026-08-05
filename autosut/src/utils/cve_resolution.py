"""Deterministic CVE-to-candidate-SUT resolution for published campaign evidence."""

from __future__ import annotations

import csv
import json
from pathlib import Path

import yaml
from pydantic import BaseModel, Field


class CVEResolutionRule(BaseModel):
    """Curated downstream rule for one CVE."""

    cve_id: str = Field(alias="cve")
    vendor: str
    product: str
    resolution_kind: str
    automatic_sut_support: bool = False
    ecosystem: str = ""
    package_name: str = ""
    install_channel: str = ""
    version_strategy: str = ""
    candidate_versions: list[str] = Field(default_factory=list)
    overlay_template: str = ""
    overlay_summary: str = ""
    attck_binding_names: list[str] = Field(default_factory=list)
    source_basis: str = ""
    evidence_sources: list[str] = Field(default_factory=list)

    model_config = {"populate_by_name": True}


class CVEPairResolution(BaseModel):
    """One campaign/CVE pair and the strongest deterministic resolution claim."""

    campaign_name: str
    campaign_id: str
    cve_id: str
    resolution_kind: str
    automatic_sut_support: bool
    ecosystem: str = ""
    package_name: str = ""
    install_channel: str = ""
    version_strategy: str = ""
    candidate_versions: list[str] = Field(default_factory=list)
    linked_software_count: int = 0
    linked_software_ids: list[str] = Field(default_factory=list)
    linked_software_names: list[str] = Field(default_factory=list)
    attck_binding_status: str
    binding_rationale: str
    overlay_template: str = ""
    overlay_summary: str = ""
    source_basis: str = ""
    evidence_sources: list[str] = Field(default_factory=list)
    notes: str = ""


class CVEResolutionTotals(BaseModel):
    """Aggregate counts used by release validation."""

    total_cve_positive_campaigns: int
    total_campaign_cve_pairs: int
    automatic_candidate_pairs: int
    automatic_candidate_campaigns: int
    direct_attck_binding_pairs: int
    curated_only_pairs: int
    appliance_or_server_pairs: int
    open_package_pairs: int
    open_package_campaigns: int


class CVEResolutionSummary(BaseModel):
    """Report payload written to JSON and Markdown."""

    generated_from: dict[str, str]
    totals: CVEResolutionTotals
    rows: list[CVEPairResolution]


def _split_semicolon_field(raw_value: str) -> list[str]:
    return [value.strip() for value in raw_value.split(";") if value.strip()]


def load_rules(path: Path) -> dict[str, CVEResolutionRule]:
    payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    rules = payload.get("rules", [])
    return {
        rule["cve"]: CVEResolutionRule.model_validate(rule)
        for rule in rules
    }


def load_campaign_cve_rows(path: Path) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    with path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            if int(row.get("cve_count", "0") or 0) <= 0:
                continue
            for cve_id in _split_semicolon_field(row.get("cves", "")):
                rows.append(
                    {
                        "campaign_name": row["campaign_name"],
                        "campaign_id": row["campaign_id"],
                        "cve_id": cve_id,
                    }
                )
    return rows


def load_campaign_structure_rows(path: Path) -> dict[str, dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return {
            row["campaign_name"]: row
            for row in csv.DictReader(handle)
            if row.get("campaign_name")
        }


def build_attack_software_index(bundle_path: Path) -> dict[str, str]:
    bundle = json.loads(bundle_path.read_text(encoding="utf-8")).get("objects", [])
    index: dict[str, str] = {}
    for obj in bundle:
        if obj.get("type") not in {"malware", "tool"}:
            continue
        object_id = obj.get("id", "")
        name = obj.get("name", "")
        if object_id and name:
            index[object_id] = name
    return index


def _binding_status(
    rule: CVEResolutionRule,
    linked_software_names: list[str],
) -> tuple[str, str]:
    lower_names = {name.lower() for name in linked_software_names}
    binding_names = {name.lower() for name in rule.attck_binding_names}

    if binding_names and lower_names & binding_names:
        return (
            "direct_attck_binding",
            (
                "ATT&CK software links already name the vulnerable target product or "
                "its product family."
            ),
        )
    if not linked_software_names and rule.automatic_sut_support:
        return (
            "cve_only_curated_binding",
            (
                "The campaign exposes a CVE but no ATT&CK software object names the "
                "target product, so the binding comes only from the curated CVE rule."
            ),
        )
    if not linked_software_names:
        return (
            "no_attck_software_link",
            "The campaign carries CVE evidence but no ATT&CK software link.",
        )
    return (
        "attacker_tooling_only",
        (
            "ATT&CK software links describe attacker tooling rather than the "
            "vulnerable target product."
        ),
    )


def _row_notes(rule: CVEResolutionRule) -> str:
    if rule.automatic_sut_support:
        return (
            "The current artifact can materialize this as a candidate vulnerable "
            "surface through a curated package-to-SUT mapping."
        )
    return (
        "This pair remains outside the current automatic public artifact path and "
        "still requires product-specific reconstruction."
    )


def resolve_campaign_cves(
    rules_path: Path,
    campaign_cves_path: Path,
    campaign_structure_path: Path,
    attack_bundle_path: Path,
) -> CVEResolutionSummary:
    rules = load_rules(rules_path)
    campaign_rows = load_campaign_cve_rows(campaign_cves_path)
    structure_rows = load_campaign_structure_rows(campaign_structure_path)
    software_index = build_attack_software_index(attack_bundle_path)

    resolved_rows: list[CVEPairResolution] = []

    for campaign_row in campaign_rows:
        rule = rules.get(campaign_row["cve_id"])
        if rule is None:
            raise KeyError(f"Missing CVE resolution rule for {campaign_row['cve_id']}")

        structure = structure_rows[campaign_row["campaign_name"]]
        linked_software_ids = _split_semicolon_field(structure.get("software_ids", ""))
        linked_software_names = [
            software_index[software_id]
            for software_id in linked_software_ids
            if software_id in software_index
        ]
        attck_binding_status, binding_rationale = _binding_status(rule, linked_software_names)

        resolved_rows.append(
            CVEPairResolution(
                campaign_name=campaign_row["campaign_name"],
                campaign_id=campaign_row["campaign_id"],
                cve_id=campaign_row["cve_id"],
                resolution_kind=rule.resolution_kind,
                automatic_sut_support=rule.automatic_sut_support,
                ecosystem=rule.ecosystem,
                package_name=rule.package_name,
                install_channel=rule.install_channel,
                version_strategy=rule.version_strategy,
                candidate_versions=rule.candidate_versions,
                linked_software_count=len(linked_software_ids),
                linked_software_ids=linked_software_ids,
                linked_software_names=linked_software_names,
                attck_binding_status=attck_binding_status,
                binding_rationale=binding_rationale,
                overlay_template=rule.overlay_template,
                overlay_summary=rule.overlay_summary,
                source_basis=rule.source_basis,
                evidence_sources=rule.evidence_sources,
                notes=_row_notes(rule),
            )
        )

    automatic_campaigns = {
        row.campaign_name for row in resolved_rows if row.automatic_sut_support
    }
    totals = CVEResolutionTotals(
        total_cve_positive_campaigns=len({row.campaign_name for row in resolved_rows}),
        total_campaign_cve_pairs=len(resolved_rows),
        automatic_candidate_pairs=sum(1 for row in resolved_rows if row.automatic_sut_support),
        automatic_candidate_campaigns=len(automatic_campaigns),
        direct_attck_binding_pairs=sum(
            1 for row in resolved_rows if row.attck_binding_status == "direct_attck_binding"
        ),
        curated_only_pairs=sum(
            1 for row in resolved_rows if row.attck_binding_status == "cve_only_curated_binding"
        ),
        appliance_or_server_pairs=sum(
            1
            for row in resolved_rows
            if row.resolution_kind in {"appliance", "enterprise_server", "windows_component"}
        ),
        open_package_pairs=sum(
            1 for row in resolved_rows if row.resolution_kind == "open_package"
        ),
        open_package_campaigns=len(
            {row.campaign_name for row in resolved_rows if row.resolution_kind == "open_package"}
        ),
    )

    return CVEResolutionSummary(
        generated_from={
            "campaign_cves": str(campaign_cves_path),
            "campaign_factual_structure": str(campaign_structure_path),
            "attack_bundle": str(attack_bundle_path),
            "rules": str(rules_path),
        },
        totals=totals,
        rows=resolved_rows,
    )


def csv_rows(summary: CVEResolutionSummary) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for row in summary.rows:
        rows.append(
            {
                "campaign_name": row.campaign_name,
                "campaign_id": row.campaign_id,
                "cve_id": row.cve_id,
                "resolution_kind": row.resolution_kind,
                "automatic_sut_support": str(row.automatic_sut_support),
                "ecosystem": row.ecosystem,
                "package_name": row.package_name,
                "install_channel": row.install_channel,
                "version_strategy": row.version_strategy,
                "candidate_versions": ";".join(row.candidate_versions),
                "linked_software_count": str(row.linked_software_count),
                "linked_software_ids": ";".join(row.linked_software_ids),
                "linked_software_names": ";".join(row.linked_software_names),
                "attck_binding_status": row.attck_binding_status,
                "binding_rationale": row.binding_rationale,
                "overlay_template": row.overlay_template,
                "overlay_summary": row.overlay_summary,
                "source_basis": row.source_basis,
                "evidence_sources": ";".join(row.evidence_sources),
                "notes": row.notes,
            }
        )
    return rows


def markdown_report(summary: CVEResolutionSummary) -> str:
    totals = summary.totals
    automatic_pip_pairs = sum(
        1 for row in summary.rows if row.automatic_sut_support and row.ecosystem == "pip"
    )
    automatic_apt_pairs = sum(
        1 for row in summary.rows if row.automatic_sut_support and row.ecosystem == "apt"
    )
    lines = [
        "# CVE Resolution Candidates",
        "",
        "This report is a deterministic downstream artifact extension. It does not",
        "infer exploits, rebuild vendor products automatically, or change the core",
        "paper claim about the current ATT&CK corpus.",
        "It is not an exhaustive crawl of the `apt` or `pip` ecosystems either:",
        "it only resolves the campaign-linked CVE slice already present in the",
        "current ATT&CK-based artifact and then applies curated, source-backed",
        "rules to that slice.",
        "",
        "## Summary",
        "",
        f"- CVE-positive campaigns: `{totals.total_cve_positive_campaigns}`",
        f"- Campaign/CVE pairs: `{totals.total_campaign_cve_pairs}`",
        f"- Automatically supported candidate pairs: `{totals.automatic_candidate_pairs}`",
        f"- Campaigns with any automatic candidate: `{totals.automatic_candidate_campaigns}`",
        f"- Direct ATT&CK target-product bindings: `{totals.direct_attck_binding_pairs}`",
        f"- Curated CVE-only bindings: `{totals.curated_only_pairs}`",
        f"- Appliance or enterprise-server pairs: `{totals.appliance_or_server_pairs}`",
        f"- Open-package pairs (`apt/pip`-style scope): `{totals.open_package_pairs}`",
        f"- Open-package campaigns (`apt/pip`-style scope): `{totals.open_package_campaigns}`",
        f"- Automatically supported `pip` pairs: `{automatic_pip_pairs}`",
        f"- Automatically supported `apt` pairs: `{automatic_apt_pairs}`",
        "",
        "## Interpretation",
        "",
        "The practical reading is conservative: campaign-linked CVEs are measurable,",
        "but ATT&CK software links usually name attacker tooling instead of the",
        "vulnerable target product. In the current public artifact, only one",
        "campaign/CVE pair resolves to an automatically supported open-package",
        "candidate: `ShadowRay / CVE-2023-48022 -> pip:ray`.",
        "The current public artifact therefore demonstrates a deterministic `pip`",
        "path, but no automatic `apt`-materialized campaign/CVE pair yet.",
        "",
        "## Scope Reduction Readout",
        "",
        (
            "If the downstream system is intentionally narrowed to installable open-package "
            "ecosystems such as `pip` or `apt`, the automation problem becomes much simpler, "
            "but the current ATT&CK-linked campaign/CVE coverage also collapses."
        ),
        "",
        (
            f"- Open-package scope covers `{totals.open_package_pairs}/{totals.total_campaign_cve_pairs}` "
            "campaign/CVE pairs in the current corpus slice."
        ),
        (
            f"- Open-package scope covers `{totals.open_package_campaigns}/{totals.total_cve_positive_campaigns}` "
            "CVE-positive campaigns in the current corpus slice."
        ),
        (
            "This makes the package-ecosystem direction a strong next-step simplifier, but "
            "not a faithful replacement for the broader SUT measurement problem addressed by "
            "the current paper."
        ),
        "",
        "## Rule Provenance",
        "",
        "Each pair-level rule is grounded in explicit source URLs shipped in",
        "`data/cve_resolution_rules.yml`. For the current automatic path, the rule",
        "combines public CVE metadata with package-ecosystem metadata rather than",
        "guessing a vulnerable target product online.",
        "",
        "## Pair-Level Resolution",
        "",
        "| Campaign | CVE | Kind | Auto | Ecosystem | Package | ATT&CK Binding | Linked ATT&CK Software | Overlay | Source Basis |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]

    for row in summary.rows:
        linked_names = ", ".join(row.linked_software_names) if row.linked_software_names else "--"
        overlay = row.overlay_template or "--"
        lines.append(
            f"| {row.campaign_name} | {row.cve_id} | {row.resolution_kind} | "
            f"{'yes' if row.automatic_sut_support else 'no'} | "
            f"{row.ecosystem or '--'} | {row.package_name or '--'} | "
            f"{row.attck_binding_status} | {linked_names} | {overlay} | "
            f"{row.source_basis or '--'} |"
        )

    auto_rows = [row for row in summary.rows if row.automatic_sut_support]
    lines.extend(["", "## Automatic-Path Source URLs", ""])
    if auto_rows:
        for row in auto_rows:
            lines.append(f"- `{row.campaign_name} / {row.cve_id}`")
            for source in row.evidence_sources:
                lines.append(f"  - `{source}`")
    else:
        lines.append("- None")

    lines.extend(
        [
            "",
            "## Source Paths",
            "",
            *(f"- `{name}`: `{path}`" for name, path in summary.generated_from.items()),
            "",
        ]
    )
    return "\n".join(lines)
