#!/usr/bin/env python3
"""
SUT Measurement Pipeline:
"Measuring System Under Test Requirements for APT Emulation Using MITRE ATT&CK"

Generates all TODO placeholder values for the Analysis section.
Reads STIX 2.x bundles (JSON) and MITRE FiGHT's native normalized YAML
snapshot directly - no external STIX libraries needed.

Usage:
    python3 sut_measurement_pipeline.py

Output:
    - results/todo_values.json          - all 28+ TODO values
    - results/todo_values_latex.tex     - LaTeX \newcommand definitions
    - results/figures_data.json         - data for TikZ figures
    - results/audit/                    - per-technique, per-campaign CSVs for audit

Maintainer note: anonymized for blind artifact release.
Date: 2026-03-05
Bundle version: ATT&CK v18.1 (Enterprise)
"""

import json
import os
import re
import csv
import sys
import math
import random
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path


def lf_dict_writer(*args, **kwargs):
    """Create a CSV writer with repository-stable LF line endings."""
    kwargs.setdefault('lineterminator', '\n')
    return csv.DictWriter(*args, **kwargs)


# Optional: numpy/scipy for Jaccard (fallback to pure Python)
try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False
    print("[WARN] numpy not found; using pure-Python Jaccard. Install with: pip3 install numpy")

# ─────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────
SCRIPT_DIR = Path(__file__).parent
ARTIFACT_ROOT = SCRIPT_DIR.parents[2]
SUT_CONFIGURATION_CORPUS = (
    ARTIFACT_ROOT / "release" / "experiments" / "sut_configuration" / "corpus.json"
)


def _sut_configuration_values() -> dict:
    """Manuscript values for the SUT-configuration provenance experiment.

    The experiment is frozen separately because collecting proposals needs local models.
    Its absence is not an error here: the measurement pipeline predates it and must still
    run without it, so the macros are simply not emitted.
    """
    if not SUT_CONFIGURATION_CORPUS.is_file():
        return {}
    corpus = json.loads(SUT_CONFIGURATION_CORPUS.read_text(encoding="utf-8"))
    stacks = set(corpus["distinct_service_stacks_per_campaign"].values())
    if len(stacks) != 1:
        raise ValueError(
            "distinct service stacks differ across campaigns; report them per campaign "
            f"instead of as one value: {corpus['distinct_service_stacks_per_campaign']}"
        )
    return {
        "sut_config_proposals": corpus["proposals"],
        "sut_config_values": corpus["total_value_occurrences"],
        "sut_config_cti_pct": f"{corpus['cti_evidenced_rate'] * 100:.1f}",
        "sut_config_proposer_pct": f"{corpus['proposer_introduced_rate'] * 100:.1f}",
        "sut_config_stacks": stacks.pop(),
    }
DATA_DIR = SCRIPT_DIR / "data"
RESULTS_DIR = SCRIPT_DIR / "results"
AUDIT_DIR = RESULTS_DIR / "audit"

ENTERPRISE_FILE = DATA_DIR / "enterprise-attack.json"
MOBILE_FILE = DATA_DIR / "mobile-attack.json"
ICS_FILE = DATA_DIR / "ics-attack.json"
CAPEC_FILE = DATA_DIR / "stix-capec.json"
FIGHT_FILE = DATA_DIR / "fight-3.1.0.normalized.json"

EXCLUDED_CAMPAIGN_ID = None    # Will be identified dynamically

# Jaccard threshold for SUT profile confusion
JACCARD_DELTA = 0.1

# CVE regex pattern
CVE_PATTERN = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)

# ─────────────────────────────────────────────────────────────────
# Tactic dependency and capability models
# Adapted from inNervoso operational model (run_campaign.py).
# Used for environment inference and campaign factual analysis.
# ─────────────────────────────────────────────────────────────────

# Each tactic lists which prior tactics typically must have occurred.
TACTIC_DEPENDENCIES = {
    "reconnaissance": [],
    "resource-development": [],
    "initial-access": [],
    "execution": ["initial-access"],
    "persistence": ["execution"],
    "privilege-escalation": ["execution"],
    "defense-evasion": [],
    "credential-access": ["execution", "discovery"],
    "discovery": ["initial-access", "execution"],
    "lateral-movement": ["discovery", "credential-access"],
    "collection": ["discovery", "lateral-movement"],
    "command-and-control": ["initial-access"],
    "exfiltration": ["collection"],
    "impact": ["lateral-movement", "collection", "privilege-escalation"],
}

# What each tactic provides when successfully executed.
TACTIC_PROVIDES = {
    "initial-access": ["initial_access", "foothold"],
    "execution": ["code_execution"],
    "persistence": ["persistent_access"],
    "privilege-escalation": ["privileged_access", "higher_privileges"],
    "defense-evasion": ["evasion_capability"],
    "credential-access": ["credentials", "password_hashes", "secrets"],
    "discovery": ["system_info", "network_info", "user_info"],
    "lateral-movement": ["lateral_capability", "remote_access"],
    "collection": ["collected_data"],
    "command-and-control": ["c2_channel"],
    "exfiltration": ["exfiltrated_data"],
    "impact": ["disruption"],
    "reconnaissance": ["target_intel"],
    "resource-development": ["resources", "infrastructure"],
}

# Technique-specific capabilities (supplements tactic-level provides).
TECHNIQUE_SPECIFIC_PROVIDES = {
    "T1078": ["valid_accounts"],
    "T1098": ["account_manipulation"],
    "T1136": ["new_account"],
    "T1003": ["password_hashes", "credentials"],
    "T1555": ["credentials_from_stores"],
    "T1087": ["account_discovery"],
    "T1482": ["domain_trust_discovery"],
    "T1018": ["remote_system_discovery"],
    "T1049": ["network_connections"],
    "T1057": ["process_discovery"],
    "T1082": ["system_info_discovery"],
    "T1016": ["network_config_discovery"],
    "T1033": ["user_discovery"],
    "T1071": ["c2_communication"],
    "T1572": ["protocol_tunneling"],
    "T1090": ["proxy_use"],
    "T1573": ["encrypted_channel"],
    "T1041": ["exfiltration_over_c2"],
    "T1048": ["exfiltration_over_alt_protocol"],
    "T1029": ["scheduled_exfiltration"],
}

# All 14 ATT&CK Enterprise tactics in kill-chain order.
def enterprise_tactic_order(all_objects):
    """Return tactic shortnames in the order of the pinned Enterprise matrix.

    Reading the order from the bundle keeps it correct across ATT&CK
    versions; v19 split defense-evasion into stealth and defense-impairment.
    """
    tactic_names = {
        obj['id']: obj['x_mitre_shortname']
        for obj in all_objects if obj.get('type') == 'x-mitre-tactic'
    }
    matrices = [
        obj for obj in all_objects
        if obj.get('type') == 'x-mitre-matrix' and not obj.get('revoked')
    ]
    if len(matrices) != 1:
        raise ValueError(f"expected one Enterprise matrix, found {len(matrices)}")
    return [tactic_names[ref] for ref in matrices[0]['tactic_refs']]


# ─────────────────────────────────────────────────────────────────
# Helper functions
# ─────────────────────────────────────────────────────────────────

def load_bundle(filepath):
    """Load a STIX 2.x bundle from JSON."""
    with open(filepath, 'r', encoding='utf-8') as f:
        bundle = json.load(f)
    return bundle['objects']


def is_deprecated_or_revoked(obj):
    """Check source-native retirement flags used by ATT&CK and CAPEC."""
    capec_status = str(obj.get('x_capec_status', '')).strip().casefold()
    return (
        obj.get('x_mitre_deprecated', False)
        or obj.get('revoked', False)
        or capec_status in {'deprecated', 'obsolete'}
    )


def index_objects_by_type(objects):
    """Index all STIX objects by type, excluding deprecated/revoked."""
    by_type = defaultdict(list)
    by_id = {}
    for obj in objects:
        if is_deprecated_or_revoked(obj):
            continue
        obj_type = obj.get('type', '')
        by_type[obj_type].append(obj)
        by_id[obj.get('id', '')] = obj
    return by_type, by_id


def build_relationship_index(relationships):
    """Build indices for relationship traversal."""
    # Forward: source_ref -> [(relationship_type, target_ref)]
    # Reverse: target_ref -> [(relationship_type, source_ref)]
    fwd = defaultdict(list)
    rev = defaultdict(list)
    by_type = defaultdict(list)
    for rel in relationships:
        src = rel.get('source_ref', '')
        tgt = rel.get('target_ref', '')
        rtype = rel.get('relationship_type', '')
        fwd[src].append((rtype, tgt, rel))
        rev[tgt].append((rtype, src, rel))
        by_type[rtype].append(rel)
    return fwd, rev, by_type


def count_relationships_with_active_endpoints(relationships, active_by_id):
    """Count relationships whose source and target both survived filtering."""
    return sum(
        1
        for rel in relationships
        if rel.get('source_ref') in active_by_id
        and rel.get('target_ref') in active_by_id
    )


def pct(count, total, decimals=1):
    """Compute percentage with rounding."""
    if total == 0:
        return 0.0
    val = (count / total) * 100
    if val < 1.0 and val > 0:
        return round(val, 2)  # More precision for < 1%
    return round(val, decimals)


def proportion_ci_wilson(count, total, z=1.96):
    """
    Wilson score interval (95% default) for binomial proportions, in percent.
    """
    if total <= 0:
        return (0.0, 0.0)
    p = count / total
    denom = 1 + (z * z) / total
    center = (p + (z * z) / (2 * total)) / denom
    margin = (z / denom) * math.sqrt((p * (1 - p) / total) + ((z * z) / (4 * total * total)))
    low = max(0.0, (center - margin) * 100)
    high = min(100.0, (center + margin) * 100)
    return (round(low, 1), round(high, 1))


def normalize_os_family(platform_label):
    """
    Map ATT&CK platform labels to coarse OS families.
    Returns one of: Windows, Linux, macOS, iOS, Android, BSD, ESXi, or None.
    """
    p = (platform_label or '').strip().lower()
    if not p:
        return None
    if 'windows' in p:
        return 'Windows'
    if 'linux' in p:
        return 'Linux'
    if 'macos' in p or 'mac os' in p:
        return 'macOS'
    if p == 'ios' or 'ios' in p:
        return 'iOS'
    if 'android' in p:
        return 'Android'
    if 'bsd' in p:
        return 'BSD'
    if 'esxi' in p:
        return 'ESXi'
    return None


# ─────────────────────────────────────────────────────────────────
# 1. Platform Coverage Analysis
# ─────────────────────────────────────────────────────────────────

def analyze_platform_coverage(techniques):
    """
    RQ1: Compute platform coverage metrics.
    Returns: (platform_count, platform_pct, sysreq_count, sysreq_pct)
    """
    total = len(techniques)
    with_platform = 0
    with_sys_req = 0
    platform_counts = Counter()

    for tech in techniques:
        platforms = tech.get('x_mitre_platforms', [])
        sys_reqs = tech.get('x_mitre_system_requirements', [])

        if platforms:
            with_platform += 1
            for p in platforms:
                platform_counts[p] += 1

        if sys_reqs:
            with_sys_req += 1

    return {
        'total_techniques': total,
        'with_platform': with_platform,
        'platform_pct': pct(with_platform, total),
        'with_system_requirements': with_sys_req,
        'system_requirements_pct': pct(with_sys_req, total),
        'platform_distribution': dict(platform_counts.most_common()),
    }


def analyze_domain_bundle(filepath, domain_name):
    """
    Analyze one bundle for Figure 1 metrics:
      - platform coverage over active attack-pattern objects
      - software-link coverage over active attack-pattern objects
      - CVE-link coverage over active attack-pattern objects
    """
    objects = load_bundle(filepath)
    by_type, by_id = index_objects_by_type(objects)
    relationships = by_type.get('relationship', [])
    rel_fwd, rel_rev, _ = build_relationship_index(relationships)

    techniques = by_type.get('attack-pattern', [])
    total = len(techniques)
    with_platform = sum(1 for t in techniques if t.get('x_mitre_platforms'))

    software_ids = {
        o['id'] for o in (by_type.get('malware', []) + by_type.get('tool', []))
    }
    software_link_counts = []
    with_software_link = 0
    cve_mention_counts = []
    with_cve_mention = 0

    for tech in techniques:
        tech_id = tech['id']
        linked_software = set()
        for rtype, tgt, _ in rel_fwd.get(tech_id, []):
            if rtype == 'uses' and tgt in software_ids:
                linked_software.add(tgt)
        for rtype, src, _ in rel_rev.get(tech_id, []):
            if rtype == 'uses' and src in software_ids:
                linked_software.add(src)

        sw_count = len(linked_software)
        software_link_counts.append(sw_count)
        if sw_count > 0:
            with_software_link += 1

        cve_structured, cve_freetext = extract_cves_from_object(tech)
        cve_count = len(cve_structured | cve_freetext)
        cve_mention_counts.append(cve_count)
        if cve_count > 0:
            with_cve_mention += 1

    sw_link_pct = pct(with_software_link, total)
    cve_link_pct = pct(with_cve_mention, total)

    software_link_counts_sorted = sorted(software_link_counts)
    cve_mention_counts_sorted = sorted(cve_mention_counts)
    if software_link_counts_sorted:
        mid = len(software_link_counts_sorted) // 2
        if len(software_link_counts_sorted) % 2 == 1:
            median_sw_links = software_link_counts_sorted[mid]
        else:
            median_sw_links = round(
                (software_link_counts_sorted[mid - 1] + software_link_counts_sorted[mid]) / 2, 2
            )
        p90_index = max(0, math.ceil(0.90 * len(software_link_counts_sorted)) - 1)
        p90_sw_links = software_link_counts_sorted[p90_index]
    else:
        median_sw_links = 0
        p90_sw_links = 0

    return {
        'domain': domain_name,
        'total_techniques': total,
        'with_platform': with_platform,
        'platform_pct': pct(with_platform, total),
        'software_link_pct': sw_link_pct,
        'cve_link_pct': cve_link_pct,
        'avg_software_links_per_attack_pattern': round(
            sum(software_link_counts) / total, 3
        ) if total else 0.0,
        'median_software_links_per_attack_pattern': median_sw_links,
        'p90_software_links_per_attack_pattern': p90_sw_links,
        'avg_cve_mentions_per_attack_pattern': round(
            sum(cve_mention_counts) / total, 3
        ) if total else 0.0,
        'num_relationships': len(relationships),
        'num_software': len(by_type.get('malware', [])) + len(by_type.get('tool', [])),
        'num_intrusion_sets': len(by_type.get('intrusion-set', [])),
        'num_campaigns': len(by_type.get('campaign', [])),
    }


def analyze_fight_snapshot(filepath, domain_name='FiGHT'):
    """Analyze the normalized native FiGHT YAML snapshot for Figure 1.

    FiGHT does not currently publish STIX.  Its adapter preserves the native
    ``platforms`` field, embedded technique--software associations, and CVE
    mentions recovered from the source text.  The returned keys intentionally
    match :func:`analyze_domain_bundle`, but ``source_schema`` prevents callers
    from treating the two encodings as semantically identical.
    """
    with open(filepath, 'r', encoding='utf-8') as handle:
        snapshot = json.load(handle)

    if snapshot.get('schema_version') != 'autosut.fight-normalized.v1':
        raise ValueError(
            f"unexpected FiGHT normalized schema in {filepath}: "
            f"{snapshot.get('schema_version')!r}"
        )
    techniques = snapshot.get('techniques')
    if not isinstance(techniques, list) or not techniques:
        raise ValueError(f"FiGHT snapshot has no techniques: {filepath}")

    declared_counts = snapshot.get('counts', {})
    expected_total = declared_counts.get('techniques')
    if expected_total != len(techniques):
        raise ValueError(
            f"FiGHT count contract mismatch: {expected_total!r} != {len(techniques)}"
        )

    software_counts = [len(t.get('software', [])) for t in techniques]
    cve_counts = [len(t.get('cves', [])) for t in techniques]
    with_platform = sum(bool(t.get('platforms')) for t in techniques)
    with_software = sum(count > 0 for count in software_counts)
    with_cve = sum(count > 0 for count in cve_counts)
    total = len(techniques)

    software_counts_sorted = sorted(software_counts)
    mid = total // 2
    if total % 2:
        median_software = software_counts_sorted[mid]
    else:
        median_software = round(
            (software_counts_sorted[mid - 1] + software_counts_sorted[mid]) / 2,
            2,
        )
    p90_index = max(0, math.ceil(0.90 * total) - 1)
    raw_counts = snapshot.get('raw_object_counts', {})

    return {
        'domain': domain_name,
        'source_schema': 'fight-native-yaml',
        'source_version': snapshot.get('source', {}).get('version'),
        'source_sha256': snapshot.get('source', {}).get('raw_sha256'),
        'total_techniques': total,
        'with_platform': with_platform,
        'platform_pct': pct(with_platform, total),
        'software_link_pct': pct(with_software, total),
        'cve_link_pct': pct(with_cve, total),
        'avg_software_links_per_attack_pattern': round(
            sum(software_counts) / total, 3
        ),
        'median_software_links_per_attack_pattern': median_software,
        'p90_software_links_per_attack_pattern': software_counts_sorted[p90_index],
        'avg_cve_mentions_per_attack_pattern': round(sum(cve_counts) / total, 3),
        'num_relationships': None,
        'num_software': raw_counts.get('software', 0),
        'num_intrusion_sets': raw_counts.get('groups', 0),
        'num_campaigns': raw_counts.get('campaigns', 0),
    }


# ─────────────────────────────────────────────────────────────────
# 2. Software Reference Analysis
# ─────────────────────────────────────────────────────────────────

def analyze_software_references(campaigns, intrusion_sets, software_objects,
                                rel_fwd, rel_rev, by_id, excluded_campaign_ids):
    """
    RQ1/RQ2: Software reference rate for campaigns and intrusion sets.
    Also measures version signal and CPE presence in software objects.
    """
    # Software IDs (malware + tool)
    software_ids = set(s['id'] for s in software_objects)
    software_by_id = {s['id']: s for s in software_objects}

    # --- Campaigns with software ---
    campaigns_with_software = 0
    campaign_software_details = []
    campaigns_with_platform_signal = 0
    campaigns_unknown_platform = 0
    campaign_platform_details = []
    campaign_os_family_counts = Counter()
    campaign_non_os_platform_counts = Counter()
    usable_campaigns = [c for c in campaigns if c['id'] not in excluded_campaign_ids]

    for camp in usable_campaigns:
        camp_id = camp['id']
        linked_software = set()
        # Direct: campaign -uses-> software
        for rtype, tgt, _ in rel_fwd.get(camp_id, []):
            if rtype == 'uses' and tgt in software_ids:
                linked_software.add(tgt)
        # Also check reverse: software -uses-> campaign (less common but possible)
        for rtype, src, _ in rel_rev.get(camp_id, []):
            if rtype == 'uses' and src in software_ids:
                linked_software.add(src)

        has_software = len(linked_software) > 0
        if has_software:
            campaigns_with_software += 1

        # Campaign-level platform inference from linked software only.
        raw_platforms = set()
        for sw_id in linked_software:
            sw_obj = software_by_id.get(sw_id, {})
            for p in sw_obj.get('x_mitre_platforms', []) or []:
                raw_platforms.add(p)

        os_families = set()
        non_os_platforms = set()
        for p in raw_platforms:
            fam = normalize_os_family(p)
            if fam is None:
                non_os_platforms.add(p)
            else:
                os_families.add(fam)

        platform_signal = len(raw_platforms) > 0
        if platform_signal:
            campaigns_with_platform_signal += 1
            for fam in os_families:
                campaign_os_family_counts[fam] += 1
            for p in non_os_platforms:
                campaign_non_os_platform_counts[p] += 1
        else:
            campaigns_unknown_platform += 1

        # Ablation: also gather technique-level platform tags so the analysis can
        # report how far campaign platform inference broadens when technique tags
        # are admitted alongside software tags.
        technique_platforms = set()
        for rtype, tgt, _ in rel_fwd.get(camp_id, []):
            if rtype == 'uses' and by_id.get(tgt, {}).get('type') == 'attack-pattern':
                technique_platforms.update(by_id[tgt].get('x_mitre_platforms', []) or [])
        combined_platforms = raw_platforms | technique_platforms
        combined_os_families = {normalize_os_family(p) for p in combined_platforms} - {None}

        unknown_reason = ''
        if not platform_signal:
            if has_software:
                unknown_reason = 'linked_software_without_platform'
            else:
                unknown_reason = 'no_linked_software'

        linked_software_ids = sorted(linked_software)
        campaign_software_details.append({
            'campaign_name': camp.get('name', 'unknown'),
            'campaign_id': camp_id,
            'software_count': len(linked_software),
            'software_ids': linked_software_ids,
        })
        campaign_platform_details.append({
            'campaign_name': camp.get('name', 'unknown'),
            'campaign_id': camp_id,
            'software_count': len(linked_software),
            'software_ids': linked_software_ids,
            'platform_signal': platform_signal,
            'os_families': sorted(os_families),
            'raw_platforms': sorted(raw_platforms),
            'non_os_platforms': sorted(non_os_platforms),
            'unknown_reason': unknown_reason,
            'combined_platform_signal': len(combined_platforms) > 0,
            'combined_os_families': sorted(combined_os_families),
        })

    # --- Intrusion sets with software ---
    is_with_software = 0
    is_software_details = []

    for iset in intrusion_sets:
        is_id = iset['id']
        linked_software = set()
        for rtype, tgt, _ in rel_fwd.get(is_id, []):
            if rtype == 'uses' and tgt in software_ids:
                linked_software.add(tgt)
        for rtype, src, _ in rel_rev.get(is_id, []):
            if rtype == 'uses' and src in software_ids:
                linked_software.add(src)

        has_software = len(linked_software) > 0
        if has_software:
            is_with_software += 1
        is_software_details.append({
            'is_name': iset.get('name', 'unknown'),
            'is_id': is_id,
            'software_count': len(linked_software),
        })

    # --- Version signal and CPE in software objects ---
    # Version signal: any version-like pattern in name, aliases, or external_references
    version_pattern = re.compile(
        r'(?:v?\d+\.\d+|\bversion\s+\d+|\b\d+\.\d+\.\d+)',
        re.IGNORECASE
    )

    def software_precision_flags(sw_obj):
        """Return precision flags for one malware/tool object."""
        name = sw_obj.get('name', '')
        aliases = sw_obj.get('aliases', []) or []
        ext_refs = sw_obj.get('external_references', []) or []

        has_version = False
        has_cpe = False

        if version_pattern.search(name):
            has_version = True

        for alias in aliases:
            if version_pattern.search(alias):
                has_version = True
                break

        for ref in ext_refs:
            ref_str = json.dumps(ref)
            if version_pattern.search(ref_str):
                has_version = True
            if 'cpe:' in ref_str.lower() or ref.get('source_name', '').lower() == 'cpe':
                has_cpe = True

        return {
            'has_version': has_version,
            'has_cpe': has_cpe,
            'has_precision_reference': has_version or has_cpe,
        }

    software_with_version = 0
    software_with_cpe = 0
    software_with_both = 0
    software_version_no_cpe = 0
    software_no_version_no_cpe = 0
    total_software = len(software_objects)
    software_precision_by_id = {}

    for sw in software_objects:
        flags = software_precision_flags(sw)
        has_version = flags['has_version']
        has_cpe = flags['has_cpe']
        software_precision_by_id[sw['id']] = flags

        if has_version:
            software_with_version += 1
        if has_cpe:
            software_with_cpe += 1
        if has_version and has_cpe:
            software_with_both += 1
        elif has_version:
            software_version_no_cpe += 1
        elif not has_version and not has_cpe:
            software_no_version_no_cpe += 1

    # Propagate precision-reference availability from linked software objects.
    # This does not establish that the campaign used the referenced version/CPE.
    for row in campaign_platform_details:
        linked_software_ids = row.get('software_ids', [])
        has_version_reference = any(
            software_precision_by_id.get(sw_id, {}).get('has_version', False)
            for sw_id in linked_software_ids
        )
        has_cpe_reference = any(
            software_precision_by_id.get(sw_id, {}).get('has_cpe', False)
            for sw_id in linked_software_ids
        )
        row['has_version_reference'] = has_version_reference
        row['has_cpe_reference'] = has_cpe_reference
        row['has_precision_reference'] = has_version_reference or has_cpe_reference

    n_usable = len(usable_campaigns)
    return {
        'campaigns_with_software': campaigns_with_software,
        'campaigns_with_software_pct': pct(campaigns_with_software, n_usable),
        'campaigns_with_platform_signal': campaigns_with_platform_signal,
        'campaigns_with_platform_signal_pct': pct(campaigns_with_platform_signal, n_usable),
        'campaigns_unknown_platform': campaigns_unknown_platform,
        'campaigns_unknown_platform_pct': pct(campaigns_unknown_platform, n_usable),
        'total_usable_campaigns': n_usable,
        'is_with_software': is_with_software,
        'is_with_software_pct': pct(is_with_software, len(intrusion_sets)),
        'total_intrusion_sets': len(intrusion_sets),
        'total_software': total_software,
        'software_with_version': software_with_version,
        'software_with_version_pct': pct(software_with_version, total_software),
        'software_with_cpe': software_with_cpe,
        'software_with_cpe_pct': pct(software_with_cpe, total_software),
        'software_with_both': software_with_both,
        'software_version_no_cpe': software_version_no_cpe,
        'software_no_version_no_cpe': software_no_version_no_cpe,
        'software_no_version_no_cpe_pct': pct(software_no_version_no_cpe, total_software),
        'campaign_details': campaign_software_details,
        'campaign_platform_details': campaign_platform_details,
        'campaign_unknown_platform_names': sorted(
            row['campaign_name'] for row in campaign_platform_details if not row['platform_signal']
        ),
        'campaign_os_family_counts': dict(campaign_os_family_counts.most_common()),
        'campaign_non_os_platform_counts': dict(campaign_non_os_platform_counts.most_common()),
        'is_details': is_software_details,
        'software_precision_by_id': software_precision_by_id,
    }


# ─────────────────────────────────────────────────────────────────
# 2b. Software Version Enrichment from Descriptions
# ─────────────────────────────────────────────────────────────────

def analyze_software_version_enrichment(software_objects):
    """
    Scan software description fields for version mentions absent from
    structured fields (name, aliases, external_references).

    This measures the 'enrichment headroom' - how many software objects
    that currently lack version signal could gain it from free-text
    description mining.
    """
    VERSION_RE = re.compile(
        r'(?:v?\d+\.\d+|\bversion\s+\d+|\b\d+\.\d+\.\d+)',
        re.IGNORECASE,
    )

    # Reuse the structured-field version detection from analyze_software_references
    def has_structured_version(sw_obj):
        """Check name, aliases, external_references for version patterns."""
        name = sw_obj.get('name', '')
        if VERSION_RE.search(name):
            return True
        for alias in (sw_obj.get('aliases', []) or []):
            if VERSION_RE.search(alias):
                return True
        for ref in (sw_obj.get('external_references', []) or []):
            if VERSION_RE.search(json.dumps(ref)):
                return True
        return False

    total = len(software_objects)
    baseline_has_version = 0      # count with structured version signal
    baseline_no_version = 0       # count without structured version signal
    desc_enriched_count = 0       # of those without, how many gain signal from description
    enriched_examples = []        # up to 10 examples for audit

    for sw in software_objects:
        if has_structured_version(sw):
            baseline_has_version += 1
            continue

        baseline_no_version += 1
        description = sw.get('description', '') or ''
        if VERSION_RE.search(description):
            desc_enriched_count += 1
            if len(enriched_examples) < 10:
                match = VERSION_RE.search(description)
                enriched_examples.append({
                    'name': sw.get('name', 'unknown'),
                    'id': sw['id'],
                    'matched_version': match.group(0) if match else '',
                    'description_snippet': description[:200],
                })

    enriched_total = baseline_has_version + desc_enriched_count
    gain_pp = round(pct(enriched_total, total) - pct(baseline_has_version, total), 1)

    return {
        'total_software': total,
        'baseline_has_version': baseline_has_version,
        'baseline_has_version_pct': pct(baseline_has_version, total),
        'baseline_no_version': baseline_no_version,
        'baseline_no_version_pct': pct(baseline_no_version, total),
        'desc_enriched_count': desc_enriched_count,
        'desc_enriched_pct': pct(desc_enriched_count, total),
        'enriched_total': enriched_total,
        'enriched_total_pct': pct(enriched_total, total),
        'gain_pp': gain_pp,
        'enriched_no_version': baseline_no_version - desc_enriched_count,
        'enriched_no_version_pct': pct(baseline_no_version - desc_enriched_count, total),
        'enriched_examples': enriched_examples,
    }


# ─────────────────────────────────────────────────────────────────
# 3. CVE / Vulnerability Analysis
# ─────────────────────────────────────────────────────────────────

def extract_cves_from_object(obj):
    """Extract all CVE identifiers from an object's text fields and references."""
    cves_structured = set()
    cves_freetext = set()

    # Check external_references for structured CVEs
    for ref in obj.get('external_references', []) or []:
        source = ref.get('source_name', '').lower()
        ext_id = ref.get('external_id', '')
        url = ref.get('url', '')

        if source == 'cve' or CVE_PATTERN.match(ext_id):
            match = CVE_PATTERN.search(ext_id)
            if match:
                cves_structured.add(match.group().upper())
        # Also check URL for CVE references
        if url:
            for m in CVE_PATTERN.finditer(url):
                cves_structured.add(m.group().upper())

    # Check description for free-text CVEs
    desc = obj.get('description', '')
    if desc:
        for m in CVE_PATTERN.finditer(desc):
            cve_id = m.group().upper()
            if cve_id not in cves_structured:
                cves_freetext.add(cve_id)

    return cves_structured, cves_freetext


def validate_cve_ids(cve_set):
    """
    Validate a set of CVE IDs against NVD format constraints.

    CVE format per MITRE/NVD specification:
    - CVE-YYYY-NNNN+ (year + at least 4 digits, no upper bound)
    - Year must be between 1999 and current year + 1
    - Sequence number must have at least 4 digits

    Returns a dict with validation results and a list of flagged CVEs
    (not rejected - some edge cases like CVE-2024-3400 are valid per spec).
    """
    STRICT_CVE_RE = re.compile(r'^CVE-(\d{4})-(\d{4,})$', re.IGNORECASE)
    current_year = datetime.now().year

    valid = []
    flagged = []

    for cve_id in sorted(cve_set):
        match = STRICT_CVE_RE.match(cve_id)
        if not match:
            flagged.append({
                'cve_id': cve_id,
                'reason': 'format_invalid',
                'detail': 'Does not match CVE-YYYY-NNNN+ pattern',
            })
            continue

        year = int(match.group(1))
        seq = match.group(2)
        seq_digits = len(seq)

        issues = []
        if year < 1999 or year > current_year + 1:
            issues.append(f'year_out_of_range ({year})')
        if seq_digits < 4:
            issues.append(f'sequence_too_short ({seq_digits} digits)')

        if issues:
            flagged.append({
                'cve_id': cve_id,
                'reason': ';'.join(issues),
                'detail': f'Year={year}, Seq={seq} ({seq_digits} digits)',
            })
        else:
            valid.append({
                'cve_id': cve_id,
                'year': year,
                'seq_digits': seq_digits,
            })

    return {
        'total': len(cve_set),
        'valid_count': len(valid),
        'flagged_count': len(flagged),
        'valid': valid,
        'flagged': flagged,
    }


def analyze_vulnerability_references(campaigns, intrusion_sets, software_objects,
                                      techniques, vulnerability_objects,
                                      rel_fwd, rel_rev, by_id, excluded_campaign_ids):
    """
    RQ1/RQ2: Vulnerability reference rate.
    Extract CVEs from structured fields and free text.
    """
    # Collect all CVEs across entire bundle
    all_cves_structured = set()
    all_cves_freetext = set()

    # Track CVEs by source type for the paper's CVE location figure
    cves_from_techniques = set()   # Illustrative examples in technique descriptions
    cves_from_software = set()     # From malware/tool objects (actionable)
    cves_from_campaigns = set()    # Direct campaign associations
    cves_from_is = set()           # Direct IS associations

    # Scan techniques (these are illustrative examples, noted separately)
    for obj in techniques:
        s, f = extract_cves_from_object(obj)
        cves_from_techniques.update(s | f)
        all_cves_structured.update(s)
        all_cves_freetext.update(f)

    # Scan software objects (actionable CVEs)
    for obj in software_objects:
        s, f = extract_cves_from_object(obj)
        cves_from_software.update(s | f)
        all_cves_structured.update(s)
        all_cves_freetext.update(f)

    # Scan campaigns
    for obj in campaigns:
        s, f = extract_cves_from_object(obj)
        cves_from_campaigns.update(s | f)
        all_cves_structured.update(s)
        all_cves_freetext.update(f)

    # Scan intrusion sets
    for obj in intrusion_sets:
        s, f = extract_cves_from_object(obj)
        cves_from_is.update(s | f)
        all_cves_structured.update(s)
        all_cves_freetext.update(f)

    # Scan vulnerability objects
    for obj in vulnerability_objects:
        s, f = extract_cves_from_object(obj)
        all_cves_structured.update(s)
        all_cves_freetext.update(f)

    # Scan relationship descriptions for CVEs
    # (relationships are not indexed by type in by_type due to separate processing)

    all_cves = all_cves_structured | all_cves_freetext
    only_freetext = all_cves_freetext - all_cves_structured

    # Actionable CVEs: those NOT only from technique examples
    actionable_cves = (cves_from_software | cves_from_campaigns | cves_from_is)
    technique_only_cves = cves_from_techniques - actionable_cves

    # --- Campaigns with CVE ---
    usable_campaigns = [c for c in campaigns if c['id'] not in excluded_campaign_ids]
    campaigns_with_cve_structured = 0
    campaigns_with_cve = 0
    campaign_cve_details = []

    for camp in usable_campaigns:
        camp_cves_structured = set()
        camp_cves = set()
        # Direct CVEs in campaign object
        s, f = extract_cves_from_object(camp)
        camp_cves_structured.update(s)
        camp_cves.update(s | f)

        # CVEs from linked software (malware/tool objects)
        # NOTE: We intentionally exclude CVEs from technique descriptions.
        # Technique descriptions mention CVEs as illustrative examples
        # (e.g., "Exploit Public-Facing Application" cites CVE-2016-6662
        # as a generic example), NOT as campaign-specific vulnerability usage.
        # Including them would inflate campaign CVE counts artificially.
        for rtype, tgt, _ in rel_fwd.get(camp['id'], []):
            if rtype == 'uses' and tgt in by_id:
                target_obj = by_id[tgt]
                if target_obj.get('type') in ('malware', 'tool'):
                    s2, f2 = extract_cves_from_object(target_obj)
                    camp_cves_structured.update(s2)
                    camp_cves.update(s2 | f2)

        if camp_cves_structured:
            campaigns_with_cve_structured += 1
        if camp_cves:
            campaigns_with_cve += 1
        campaign_cve_details.append({
            'campaign_name': camp.get('name', ''),
            'campaign_id': camp.get('id', ''),
            'cve_count_structured': len(camp_cves_structured),
            'cve_count': len(camp_cves),
            'cve_enrichment_gain_count': max(0, len(camp_cves) - len(camp_cves_structured)),
            'cves_structured': sorted(camp_cves_structured),
            'cves': sorted(camp_cves),
        })

    # --- Intrusion sets with CVE ---
    is_with_cve_structured = 0
    is_with_cve = 0
    is_cve_details = []

    for iset in intrusion_sets:
        is_cves_structured = set()
        is_cves = set()
        s, f = extract_cves_from_object(iset)
        is_cves_structured.update(s)
        is_cves.update(s | f)

        # CVEs from linked software (not techniques - see campaign note above)
        for rtype, tgt, _ in rel_fwd.get(iset['id'], []):
            if rtype == 'uses' and tgt in by_id:
                target_obj = by_id[tgt]
                if target_obj.get('type') in ('malware', 'tool'):
                    s2, f2 = extract_cves_from_object(target_obj)
                    is_cves_structured.update(s2)
                    is_cves.update(s2 | f2)

        if is_cves_structured:
            is_with_cve_structured += 1
        if is_cves:
            is_with_cve += 1
        is_cve_details.append({
            'is_name': iset.get('name', ''),
            'cve_count_structured': len(is_cves_structured),
            'cve_count': len(is_cves),
            'cve_enrichment_gain_count': max(0, len(is_cves) - len(is_cves_structured)),
            'cves_structured': sorted(is_cves_structured),
            'cves': sorted(is_cves),
        })

    n_usable = len(usable_campaigns)

    # For the paper: cve_unique_count reports CVEs carried by technique, software,
    # campaign, intrusion-set, and vulnerability objects. CVEs that appear only
    # inside 'uses' relationship (procedure-example) descriptions are scoped out
    # as illustrative context, consistent with the manuscript.
    # cve_from_freetext_pct reports the fraction found ONLY in object descriptions.
    # We also provide actionable_cve_count (excluding technique-example CVEs)
    # for the narrative that distinguishes actionable vs illustrative CVE refs.
    return {
        'cve_unique_count': len(all_cves),
        'cve_structured_count': len(all_cves_structured),
        'cve_freetext_only_count': len(only_freetext),
        'cve_from_freetext_pct': pct(len(only_freetext), len(all_cves)) if all_cves else 0,
        'actionable_cve_count': len(actionable_cves),
        'technique_only_cve_count': len(technique_only_cves),
        'cves_from_techniques': sorted(cves_from_techniques),
        'cves_from_software': sorted(cves_from_software),
        'cves_from_campaigns': sorted(cves_from_campaigns),
        'cves_from_is': sorted(cves_from_is),
        'campaigns_with_cve_structured': campaigns_with_cve_structured,
        'campaigns_with_cve_structured_pct': pct(campaigns_with_cve_structured, n_usable),
        'campaigns_with_cve': campaigns_with_cve,
        'campaigns_with_cve_pct': pct(campaigns_with_cve, n_usable),
        'campaigns_with_cve_enrichment_gain': max(0, campaigns_with_cve - campaigns_with_cve_structured),
        'campaigns_with_cve_enrichment_gain_pp': round(
            pct(campaigns_with_cve, n_usable) - pct(campaigns_with_cve_structured, n_usable), 1
        ),
        'is_with_cve_structured': is_with_cve_structured,
        'is_with_cve_structured_pct': pct(is_with_cve_structured, len(intrusion_sets)),
        'is_with_cve': is_with_cve,
        'is_with_cve_pct': pct(is_with_cve, len(intrusion_sets)),
        'is_with_cve_enrichment_gain': max(0, is_with_cve - is_with_cve_structured),
        'is_with_cve_enrichment_gain_pp': round(
            pct(is_with_cve, len(intrusion_sets)) - pct(is_with_cve_structured, len(intrusion_sets)), 1
        ),
        'all_cves': sorted(all_cves),
        'structured_cves': sorted(all_cves_structured),
        'freetext_only_cves': sorted(only_freetext),
        'actionable_cves': sorted(actionable_cves),
        'campaign_cve_details': campaign_cve_details,
        'is_cve_details': is_cve_details,
    }


# ─────────────────────────────────────────────────────────────────
# 4. Initial Access Analysis
# ─────────────────────────────────────────────────────────────────

def get_attack_external_id(obj):
    """Return ATT&CK external technique ID (e.g., T1566.001) when available."""
    for ref in obj.get('external_references', []) or []:
        if ref.get('source_name') == 'mitre-attack':
            return ref.get('external_id', '')
    return ''


def get_attack_reference_url(obj):
    """Return ATT&CK reference URL when present."""
    for ref in obj.get('external_references', []) or []:
        if ref.get('source_name') == 'mitre-attack':
            return ref.get('url', '')
    return ''


def analyze_initial_access(campaigns, techniques, rel_fwd, cve_results, excluded_campaign_ids):
    """
    Initial Access focused analysis:
      - campaigns using at least one Initial Access technique
      - social-interaction proxy via phishing/trusted-relationship techniques
      - overlap with campaign-level CVE evidence
    """
    # Initial Access technique set
    initial_access_ids = set()
    ext_id_by_tech = {}
    tech_name_by_id = {}
    for tech in techniques:
        tech_id = tech['id']
        ext_id_by_tech[tech_id] = get_attack_external_id(tech)
        tech_name_by_id[tech_id] = tech.get('name', '')
        for phase in tech.get('kill_chain_phases', []):
            if phase.get('kill_chain_name') == 'mitre-attack' and phase.get('phase_name') == 'initial-access':
                initial_access_ids.add(tech_id)
                break

    # Conservative social-interaction proxy:
    # - Phishing family (T1566.*)
    # - Trusted Relationship (T1199)
    social_proxy_ids = set()
    for tid in initial_access_ids:
        ext = ext_id_by_tech.get(tid, '')
        if ext.startswith('T1566') or ext == 'T1199':
            social_proxy_ids.add(tid)

    usable_campaigns = [c for c in campaigns if c['id'] not in excluded_campaign_ids]
    n_campaigns = len(usable_campaigns)

    # Map campaign id -> CVE count from existing vulnerability analysis.
    campaign_cve_count = {}
    for row in cve_results.get('campaign_cve_details', []):
        campaign_id = row.get('campaign_id')
        if campaign_id:
            campaign_cve_count[campaign_id] = int(row.get('cve_count', 0))

    campaigns_with_ia = 0
    campaigns_with_social_proxy = 0
    campaigns_with_ia_and_cve = 0
    campaign_rows = []
    ia_technique_counter = Counter()

    for camp in usable_campaigns:
        cid = camp['id']
        cname = camp.get('name', '')
        ia_tids = set()
        for rtype, tgt, _ in rel_fwd.get(cid, []):
            if rtype == 'uses' and tgt in initial_access_ids:
                ia_tids.add(tgt)

        has_ia = len(ia_tids) > 0
        has_social_proxy = len(ia_tids & social_proxy_ids) > 0
        cve_count = campaign_cve_count.get(cid, 0)
        has_cve = cve_count > 0

        if has_ia:
            campaigns_with_ia += 1
            for tid in ia_tids:
                ia_technique_counter[tech_name_by_id.get(tid, tid)] += 1
        if has_social_proxy:
            campaigns_with_social_proxy += 1
        if has_ia and has_cve:
            campaigns_with_ia_and_cve += 1

        campaign_rows.append({
            'campaign_name': cname,
            'campaign_id': cid,
            'has_initial_access': has_ia,
            'has_social_proxy': has_social_proxy,
            'campaign_cve_count': cve_count,
            'initial_access_technique_count': len(ia_tids),
            'initial_access_techniques': sorted(
                f"{ext_id_by_tech.get(tid, '')}:{tech_name_by_id.get(tid, tid)}"
                for tid in ia_tids
            ),
        })

    return {
        'initial_access_technique_count': len(initial_access_ids),
        'social_proxy_technique_count': len(social_proxy_ids),
        'campaigns_with_initial_access_count': campaigns_with_ia,
        'campaigns_with_initial_access_pct': pct(campaigns_with_ia, n_campaigns),
        'campaigns_with_social_initial_access_count': campaigns_with_social_proxy,
        'campaigns_with_social_initial_access_pct': pct(campaigns_with_social_proxy, n_campaigns),
        'campaigns_with_initial_access_and_cve_count': campaigns_with_ia_and_cve,
        'campaigns_with_initial_access_and_cve_pct': pct(campaigns_with_ia_and_cve, n_campaigns),
        'campaigns_with_initial_access_no_cve_count': campaigns_with_ia - campaigns_with_ia_and_cve,
        'campaigns_with_initial_access_no_cve_pct': pct(campaigns_with_ia - campaigns_with_ia_and_cve, n_campaigns),
        'top_initial_access_techniques': ia_technique_counter.most_common(),
        'campaign_rows': campaign_rows,
    }


def validate_campaign_profile_population(
    campaigns: list[dict], excluded_campaign_ids: set[str], report: dict,
) -> int:
    """Require profile rows to match the current eligible campaign inventory."""
    campaign_ids = {campaign['id'] for campaign in campaigns}
    if len(campaign_ids) != len(campaigns):
        raise ValueError("Campaign inventory contains duplicate IDs.")
    if not excluded_campaign_ids.issubset(campaign_ids):
        raise ValueError("Excluded campaign IDs are absent from the inventory.")
    expected_ids = campaign_ids - excluded_campaign_ids
    row_ids = [row['campaign_id'] for row in report['rows']]
    if len(set(row_ids)) != len(row_ids):
        raise ValueError("Campaign profile report contains duplicate IDs.")
    if set(row_ids) != expected_ids:
        raise ValueError("Campaign profile IDs differ from the eligible inventory.")
    if report['total_campaigns'] != len(expected_ids):
        raise ValueError("Campaign profile denominator differs from its inventory.")
    return len(expected_ids)


def analyze_campaign_profile_completeness(software_results, cve_results):
    """
    Operational SUT profile completeness at campaign level.

    T1 (coarse): has software linkage + platform signal.
    T2 (reference-enriched): T1 + (version/CPE reference in linked software
    OR campaign-level CVE).  Linked-software references are not campaign-version observations.
    T3 (CVE-associated): T1 + campaign-level CVE.  This records association,
    not a verified CVE-to-product/version binding or demonstrated exploitability.
    """
    rows = []
    campaigns_with_cve = {
        row.get('campaign_id')
        for row in cve_results.get('campaign_cve_details', [])
        if int(row.get('cve_count', 0)) > 0 and row.get('campaign_id')
    }
    total = int(software_results.get('total_usable_campaigns', 0))
    t1_count = 0
    t2_count = 0
    t3_count = 0

    for row in software_results.get('campaign_platform_details', []):
        campaign_id = row.get('campaign_id', '')
        has_software = int(row.get('software_count', 0)) > 0
        has_platform = bool(row.get('platform_signal', False))
        has_precision_reference = bool(row.get('has_precision_reference', False))
        has_campaign_cve = campaign_id in campaigns_with_cve

        t1 = has_software and has_platform
        t2 = t1 and (has_precision_reference or has_campaign_cve)
        t3 = t1 and has_campaign_cve

        if t1:
            t1_count += 1
        if t2:
            t2_count += 1
        if t3:
            t3_count += 1

        rows.append({
            'campaign_name': row.get('campaign_name', ''),
            'campaign_id': campaign_id,
            'has_software': has_software,
            'has_platform_signal': has_platform,
            'has_precision_reference': has_precision_reference,
            'has_campaign_cve': has_campaign_cve,
            'tier_t1_coarse': t1,
            'tier_t2_reference_enriched': t2,
            'tier_t3_cve_associated': t3,
        })

    return {
        'total_campaigns': total,
        'tier_t1_count': t1_count,
        'tier_t1_pct': pct(t1_count, total),
        'tier_t2_count': t2_count,
        'tier_t2_pct': pct(t2_count, total),
        'tier_t3_count': t3_count,
        'tier_t3_pct': pct(t3_count, total),
        'rows': rows,
    }


# ─────────────────────────────────────────────────────────────────
# 4b. Campaign Factual Structure (inNervoso consolidation)
# ─────────────────────────────────────────────────────────────────

def analyze_campaign_factual_structure(campaigns, techniques, rel_fwd, rel_rev,
                                       by_id, tactic_objects, excluded_campaign_ids,
                                       tactic_order):
    """
    Extract per-campaign structured facts from STIX data.

    For each campaign, computes:
    - technique_ids: ATT&CK technique IDs linked to this campaign
    - tactic_set: set of tactics covered (from technique kill_chain_phases)
    - software_ids: linked software objects
    - platform_signals: inferred platforms from linked software/techniques
    - has_initial_access / has_exfiltration: tactical bookends
    - technique_count, tactic_count

    Returns dict with aggregate metrics + per-campaign rows.
    Exports audit/campaign_factual_structure.csv.
    """
    usable_campaigns = [c for c in campaigns if c['id'] not in excluded_campaign_ids]
    rows = []

    all_technique_counts = []
    all_tactic_counts = []
    campaigns_with_ia = 0
    campaigns_with_exfil = 0
    campaigns_with_ia_and_exfil = 0
    campaigns_complete_killchain = 0  # ≥ 5 distinct tactics

    # Build technique lookup for quick access
    tech_by_id = {t['id']: t for t in techniques}

    for camp in usable_campaigns:
        camp_id = camp['id']
        camp_name = camp.get('name', 'unknown')

        # --- Linked techniques ---
        linked_tech_ids = set()
        for rtype, target_id, _ in rel_fwd.get(camp_id, []):
            target = by_id.get(target_id)
            if target and target.get('type') == 'attack-pattern':
                linked_tech_ids.add(target_id)
        # Also check reverse relationships
        for rtype, source_id, _ in rel_rev.get(camp_id, []):
            source = by_id.get(source_id)
            if source and source.get('type') == 'attack-pattern':
                linked_tech_ids.add(source_id)

        # Extract ATT&CK IDs and tactics
        technique_ext_ids = []
        tactic_set = set()
        platform_set = set()
        for tech_id in linked_tech_ids:
            tech = by_id.get(tech_id)
            if not tech:
                continue
            ext_id = get_attack_external_id(tech)
            if ext_id:
                technique_ext_ids.append(ext_id)
            # Tactics
            tech_tactics = get_technique_tactics(tech, tactic_objects)
            tactic_set.update(tech_tactics)
            # Platforms from technique
            for p in tech.get('x_mitre_platforms', []):
                fam = normalize_os_family(p)
                if fam:
                    platform_set.add(fam)

        # --- Linked software ---
        linked_sw_ids = set()
        for rtype, target_id, _ in rel_fwd.get(camp_id, []):
            target = by_id.get(target_id)
            if target and target.get('type') in ('tool', 'malware'):
                linked_sw_ids.add(target_id)
        for rtype, source_id, _ in rel_rev.get(camp_id, []):
            source = by_id.get(source_id)
            if source and source.get('type') in ('tool', 'malware'):
                linked_sw_ids.add(source_id)

        # Software-derived platforms
        for sw_id in linked_sw_ids:
            sw = by_id.get(sw_id)
            if sw:
                for p in sw.get('x_mitre_platforms', []):
                    fam = normalize_os_family(p)
                    if fam:
                        platform_set.add(fam)

        # --- CVEs ---
        cve_structured, cve_freetext = extract_cves_from_object(camp)
        cve_set = cve_structured | cve_freetext

        # --- Tactical bookends ---
        has_ia = 'initial-access' in tactic_set
        has_exfil = 'exfiltration' in tactic_set
        if has_ia:
            campaigns_with_ia += 1
        if has_exfil:
            campaigns_with_exfil += 1
        if has_ia and has_exfil:
            campaigns_with_ia_and_exfil += 1

        # --- Tactic coverage assessment ---
        n_tactics = len(tactic_set)
        n_techs = len(technique_ext_ids)
        all_technique_counts.append(n_techs)
        all_tactic_counts.append(n_tactics)
        if n_tactics >= 5:
            campaigns_complete_killchain += 1

        # Unknown tactics would make the order depend on set iteration.
        tactic_sequence = sorted(tactic_set, key=tactic_order.index)

        rows.append({
            'campaign_name': camp_name,
            'campaign_id': camp_id,
            'technique_count': n_techs,
            'technique_ids': ';'.join(sorted(technique_ext_ids)),
            'tactic_count': n_tactics,
            'tactic_sequence': ';'.join(tactic_sequence),
            'software_count': len(linked_sw_ids),
            'software_ids': ';'.join(sorted(
                get_attack_external_id(by_id[sid]) or sid for sid in linked_sw_ids if sid in by_id
            )),
            'cve_count': len(cve_set),
            'cve_ids': ';'.join(sorted(cve_set)),
            'platform_signals': ';'.join(sorted(platform_set)),
            'has_initial_access': has_ia,
            'has_exfiltration': has_exfil,
        })

    n_usable = len(usable_campaigns)
    mean_techs = round(sum(all_technique_counts) / max(n_usable, 1), 1)
    median_techs = round(sorted(all_technique_counts)[n_usable // 2], 1) if n_usable else 0
    mean_tactics = round(sum(all_tactic_counts) / max(n_usable, 1), 1)

    # --- Export audit CSV ---
    csv_path = AUDIT_DIR / 'campaign_factual_structure.csv'
    if rows:
        fieldnames = list(rows[0].keys())
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            writer = lf_dict_writer(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(sorted(rows, key=lambda r: r['campaign_name']))
        print(f"  [AUDIT] Wrote {csv_path.name} ({len(rows)} campaigns)")

    return {
        'total_campaigns': n_usable,
        'campaign_mean_technique_count': mean_techs,
        'campaign_median_technique_count': median_techs,
        'campaign_mean_tactic_coverage': mean_tactics,
        'campaigns_complete_killchain': campaigns_complete_killchain,
        'campaign_complete_killchain_pct': pct(campaigns_complete_killchain, n_usable),
        'campaigns_with_initial_access': campaigns_with_ia,
        'campaigns_with_exfiltration': campaigns_with_exfil,
        'campaigns_with_ia_and_exfil': campaigns_with_ia_and_exfil,
        'campaign_with_ia_and_exfil_pct': pct(campaigns_with_ia_and_exfil, n_usable),
        'rows': rows,
    }


# ─────────────────────────────────────────────────────────────────
# 4c. Environment Inference + IEIR (inNervoso consolidation)
# ─────────────────────────────────────────────────────────────────

# Regex for environment signals in description text
ENV_SIGNAL_RE = re.compile(
    r'\b(Windows|Linux|macOS|Ubuntu|Debian|CentOS|Red Hat|RHEL|'
    r'Active Directory|Exchange Server|IIS|Apache|Nginx|Docker|'
    r'Kubernetes|ESXi|vSphere|AWS|Azure|GCP|Citrix|VPN|RDP|SSH)\b',
    re.IGNORECASE
)

def infer_campaign_environment(campaign_fact_rows, software_objects, by_id,
                                rel_fwd, rel_rev):
    """
    Multi-signal environment inference for each campaign.

    Signal tiers (from least to most campaign-specific):
      Tier 1 (generic):    technique_platforms - x-mitre-platforms on linked
                           techniques. Lists which OS a technique CAN run on,
                           NOT which OS the campaign actually targeted. Nearly
                           universal and therefore low-discriminative.
      Tier 2 (specific):   software_platforms - platforms on campaign-linked
                           software. Reflects actual tools used -> campaign-
                           specific targeting evidence.
      Tier 3 (targeted):   description_mined - regex extraction from campaign
                           descriptions. Explicit targeting statements.
      Heuristic:           tactic_implied - tactic -> environment heuristic
                           (e.g. credential-access -> Windows domain).

    Metrics:
      IEIR = fraction of campaigns with ONLY Tier 1 (generic) signals —
             i.e., campaigns where the target environment cannot be narrowed
             beyond technique-level platform compatibility.
      ESR  = Environment Specificity Rate = fraction of campaigns with at
             least one campaign-specific signal (Tier 2+).
      Platform narrowing = mean reduction in OS family breadth when moving
             from generic to campaign-specific signals.

    Returns dict with aggregate metrics + per-campaign rows.
    Exports audit/environment_inference.csv.
    """
    rows = []
    n_campaign_specific = 0
    n_generic_only = 0
    n_no_signal = 0
    confidence_counts = Counter()
    signal_type_counts = Counter()
    narrowing_scores = []

    for fact_row in campaign_fact_rows:
        camp_id = fact_row['campaign_id']
        camp_name = fact_row['campaign_name']
        camp = by_id.get(camp_id, {})

        signals = {}  # signal_type -> set of OS families

        # --- Signal 1: technique platforms (explicit) ---
        tech_platforms = set()
        tech_ids_str = fact_row.get('technique_ids', '')
        for tech_stix_id, tech in by_id.items():
            if tech.get('type') != 'attack-pattern':
                continue
            ext_id = get_attack_external_id(tech)
            if ext_id and ext_id in tech_ids_str:
                for p in tech.get('x_mitre_platforms', []):
                    fam = normalize_os_family(p)
                    if fam:
                        tech_platforms.add(fam)
        if tech_platforms:
            signals['technique_platforms'] = tech_platforms

        # --- Signal 2: software platforms ---
        sw_platforms = set()
        sw_ids_str = fact_row.get('software_ids', '')
        for sw in software_objects:
            sw_ext = get_attack_external_id(sw)
            if sw_ext and sw_ext in sw_ids_str:
                for p in sw.get('x_mitre_platforms', []):
                    fam = normalize_os_family(p)
                    if fam:
                        sw_platforms.add(fam)
        if sw_platforms:
            signals['software_platforms'] = sw_platforms

        # --- Signal 3: tactic-implied environment ---
        tactic_implied = set()
        tactic_seq = fact_row.get('tactic_sequence', '')
        if 'credential-access' in tactic_seq or 'lateral-movement' in tactic_seq:
            tactic_implied.add('Windows')  # These tactics strongly indicate Windows domain
        if tactic_implied:
            signals['tactic_implied'] = tactic_implied

        # --- Signal 4: description-mined ---
        desc_signals = set()
        desc = camp.get('description', '')
        for match in ENV_SIGNAL_RE.finditer(desc):
            token = match.group(1)
            fam = normalize_os_family(token)
            if fam:
                desc_signals.add(fam)
            else:
                desc_signals.add(token)  # Keep non-OS signals (e.g., "Active Directory")
        if desc_signals:
            signals['description_mined'] = desc_signals

        # --- Aggregate ---
        all_os = set()
        for s in signals.values():
            all_os.update(s)

        # Tiered classification:
        # Tier 1 (generic):  technique_platforms - capability-level, not campaign-specific
        # Tier 2+ (specific): software_platforms, description_mined, tactic_implied
        has_generic = bool(signals.get('technique_platforms'))
        has_campaign_specific = bool(
            signals.get('software_platforms')
            or signals.get('description_mined')
            or signals.get('tactic_implied')
        )
        has_generic_only = has_generic and not has_campaign_specific
        has_no_signal = not signals

        # Platform narrowing: how much does campaign-specific evidence narrow
        # the generic technique-platform set?
        generic_os = signals.get('technique_platforms', set())
        specific_os = set()
        for k in ('software_platforms', 'description_mined', 'tactic_implied'):
            specific_os.update(signals.get(k, set()))
        if generic_os and specific_os:
            # Narrowing = 1 - |specific ∩ generic| / |generic|
            overlap = len(specific_os & generic_os)
            narrowing = 1.0 - overlap / len(generic_os)
        else:
            narrowing = 0.0
        narrowing_scores.append(narrowing)

        # Confidence based on campaign-specific signals (not just total count)
        n_campaign_specific_signals = sum(
            1 for k in ('software_platforms', 'description_mined', 'tactic_implied')
            if signals.get(k)
        )
        n_signals = len(signals)
        if n_campaign_specific_signals >= 2:
            confidence = 'high'
        elif n_campaign_specific_signals == 1:
            confidence = 'medium'
        elif has_generic:
            confidence = 'low'
        else:
            confidence = 'none'

        if has_campaign_specific:
            n_campaign_specific += 1
        if has_generic_only:
            n_generic_only += 1
        if has_no_signal:
            n_no_signal += 1
        confidence_counts[confidence] += 1
        for sig_type in signals:
            signal_type_counts[sig_type] += 1

        rows.append({
            'campaign_name': camp_name,
            'campaign_id': camp_id,
            'inferred_os': ';'.join(sorted(all_os)),
            'signal_sources': ';'.join(sorted(signals.keys())),
            'signal_count': n_signals,
            'confidence': confidence,
            'has_campaign_specific': has_campaign_specific,
            'has_generic_only': has_generic_only,
            'narrowing_score': round(narrowing, 3),
            'technique_platforms': ';'.join(sorted(signals.get('technique_platforms', set()))),
            'software_platforms': ';'.join(sorted(signals.get('software_platforms', set()))),
            'tactic_implied': ';'.join(sorted(signals.get('tactic_implied', set()))),
            'description_mined': ';'.join(sorted(signals.get('description_mined', set()))),
        })

    n_total = len(campaign_fact_rows)
    mean_narrowing = sum(narrowing_scores) / len(narrowing_scores) if narrowing_scores else 0.0

    # --- Export audit CSV ---
    csv_path = AUDIT_DIR / 'environment_inference.csv'
    if rows:
        fieldnames = list(rows[0].keys())
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            writer = lf_dict_writer(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(sorted(rows, key=lambda r: r['campaign_name']))
        print(f"  [AUDIT] Wrote {csv_path.name} ({len(rows)} campaigns)")

    return {
        'total_campaigns': n_total,
        'ieir_count': n_generic_only,
        'ieir_pct': pct(n_generic_only, n_total),
        'campaign_specific_count': n_campaign_specific,
        'campaign_specific_pct': pct(n_campaign_specific, n_total),
        'no_signal_count': n_no_signal,
        'no_signal_pct': pct(n_no_signal, n_total),
        'environment_high_confidence_count': confidence_counts.get('high', 0),
        'environment_high_confidence_pct': pct(confidence_counts.get('high', 0), n_total),
        'environment_medium_count': confidence_counts.get('medium', 0),
        'environment_medium_pct': pct(confidence_counts.get('medium', 0), n_total),
        'environment_low_count': confidence_counts.get('low', 0),
        'environment_low_pct': pct(confidence_counts.get('low', 0), n_total),
        'environment_none_count': confidence_counts.get('none', 0),
        'environment_none_pct': pct(confidence_counts.get('none', 0), n_total),
        'signal_type_breakdown': dict(signal_type_counts.most_common()),
        'mean_narrowing_score': round(mean_narrowing, 3),
        'rows': rows,
    }


# ─────────────────────────────────────────────────────────────────
# 4d. Evidence Convergence Analysis (inNervoso consolidation)
# ─────────────────────────────────────────────────────────────────

def analyze_evidence_convergence(campaign_fact_rows, env_inference_rows):
    """
    Measure how multiple evidence signals converge (or diverge) for each campaign.

    Compares:
    - Do technique platforms agree with software platforms?
    - Do all available signal sources point to the same OS families?

    Convergence rate = % campaigns where all signals agree.
    """
    rows = []
    n_convergent = 0
    n_divergent = 0
    n_assessable = 0
    n_assessable_convergent = 0
    n_assessable_divergent = 0
    all_signal_counts = []

    # Index env rows by campaign_id
    env_by_id = {r['campaign_id']: r for r in env_inference_rows}

    for fact_row in campaign_fact_rows:
        camp_id = fact_row['campaign_id']
        env_row = env_by_id.get(camp_id, {})

        # Get individual signal sets
        tech_plats = set(filter(None, env_row.get('technique_platforms', '').split(';')))
        sw_plats = set(filter(None, env_row.get('software_platforms', '').split(';')))
        tactic_imp = set(filter(None, env_row.get('tactic_implied', '').split(';')))
        desc_mined = set(filter(None, env_row.get('description_mined', '').split(';')))

        # Collect all non-empty signal sets (normalized to OS families only)
        signal_sets = []
        if tech_plats:
            signal_sets.append(('technique_platforms', tech_plats))
        if sw_plats:
            signal_sets.append(('software_platforms', sw_plats))
        if tactic_imp:
            signal_sets.append(('tactic_implied', tactic_imp))
        # description_mined may contain non-OS tokens, skip for convergence

        n_signals = len(signal_sets)
        all_signal_counts.append(n_signals)

        if n_signals <= 1:
            # Cannot assess convergence with 0-1 signals
            assessable = False
            converges = True  # trivially convergent
            divergence_detail = 'single_signal'
        else:
            assessable = True
            n_assessable += 1
            # Check: do all signal sets share at least one OS family?
            intersection = signal_sets[0][1]
            for _, sset in signal_sets[1:]:
                intersection = intersection & sset
            converges = len(intersection) > 0
            if converges:
                n_assessable_convergent += 1
                divergence_detail = ''
            else:
                n_assessable_divergent += 1
                # Build divergence description
                parts = [f"{name}={sorted(sset)}" for name, sset in signal_sets]
                divergence_detail = ' vs '.join(parts)

        if converges:
            n_convergent += 1
        else:
            n_divergent += 1

        rows.append({
            'campaign_name': fact_row['campaign_name'],
            'campaign_id': camp_id,
            'signals_count': n_signals,
            'convergence_assessable': assessable,
            'signals_agree': converges,
            'divergence_details': divergence_detail,
        })

    n_total = len(campaign_fact_rows)
    mean_signals = round(sum(all_signal_counts) / max(n_total, 1), 1)

    # --- Export audit CSV ---
    csv_path = AUDIT_DIR / 'evidence_convergence.csv'
    if rows:
        fieldnames = list(rows[0].keys())
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            writer = lf_dict_writer(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(sorted(rows, key=lambda r: r['campaign_name']))
        print(f"  [AUDIT] Wrote {csv_path.name} ({len(rows)} campaigns)")

    return {
        'total_campaigns': n_total,
        'convergence_count': n_convergent,
        'convergence_rate_pct': pct(n_convergent, n_total),
        'divergence_count': n_divergent,
        'divergence_pct': pct(n_divergent, n_total),
        'assessable_campaign_count': n_assessable,
        'assessable_convergence_count': n_assessable_convergent,
        'assessable_convergence_rate_pct': pct(
            n_assessable_convergent, n_assessable
        ),
        'assessable_divergence_count': n_assessable_divergent,
        'evidence_mean_signal_count': mean_signals,
        'rows': rows,
    }


# ─────────────────────────────────────────────────────────────────
# 5. SUT Compatibility Classification
# ─────────────────────────────────────────────────────────────────

# Tactic IDs that map to specific clusters
# These are based on MITRE ATT&CK Enterprise tactic x_mitre_shortname
LATERAL_MOVEMENT_TACTICS = {'lateral-movement'}
PRIVILEGE_ESCALATION_TACTICS = {'privilege-escalation'}
DEFENSE_EVASION_TACTICS = {'defense-evasion'}

# Keywords for infrastructure-dependent techniques
ID_PLATFORM_KEYWORDS = {
    'Windows Domain', 'Azure AD', 'Google Workspace',
    'Office 365', 'SaaS', 'IaaS', 'Identity Provider',
    'Entra ID',
}
LATERAL_SOFTWARE_KEYWORDS = (
    'active directory',
    'kerberos',
    'ldap',
    'domain',
)

# Keywords in technique name/description for kernel/boot interaction
KERNEL_BOOT_KEYWORDS = re.compile(
    r'boot|firmware|kernel|driver|rootkit|bios|uefi|mbr|vbr|bootkit',
    re.IGNORECASE
)

# Permissions indicating VMR
VMR_PERMISSIONS = {'Administrator', 'SYSTEM', 'root'}

# Name patterns that imply host-semantic or privileged execution.
VMR_NAME_PATTERNS = re.compile(
    r'process\s+inject|hook|dll\s+side|hijack|token\s+manipul|'
    r'access\s+token|credential\s+dump|lsass|sam\s+database|'
    r'registry|service\s+execut|scheduled\s+task|'
    r'windows\s+management\s+instrument|wmi|'
    r'exploitation\s+for\s+privilege',
    re.IGNORECASE
)

CONTAINER_COMPATIBLE_PLATFORMS = {'Containers', 'Linux'}

# These symbols are routing-policy labels produced by deterministic heuristics.
# They are not observations of a technique's minimum viable backend and must not
# be treated as validated ground truth until the manual adjudication packet is
# complete.  The historical names are retained because they are part of the
# public artifact interface.
COMPATIBILITY_POLICY_LABELS = ('CF', 'VMR', 'ID')
DEFAULT_COMPATIBILITY_ROUTING_LABEL = 'VMR'


def get_technique_tactics(technique, tactic_objects):
    """Get tactic shortnames for a technique via kill_chain_phases."""
    tactics = set()
    for phase in technique.get('kill_chain_phases', []):
        if phase.get('kill_chain_name') == 'mitre-attack':
            tactics.add(phase.get('phase_name', ''))
    return tactics


def classify_technique_compatibility_trace(
    technique,
    rel_fwd,
    by_id,
    default_class=DEFAULT_COMPATIBILITY_ROUTING_LABEL,
    container_rule='subset',
):
    """
    Assign a heuristic CF/VMR/ID routing-policy label (or UNRESOLVED).

    The returned label is a deterministic policy output, not an empirically
    established backend requirement or a validated ground-truth class.  The
    rule trace makes both explicit-rule and default-fallback assignments
    auditable.  ``container_rule='subset'`` is the published CF rule (every
    platform tag is container-compatible); ``'intersects'`` is the optimistic
    ablation (at least one tag is).
    """
    platforms = set(technique.get('x_mitre_platforms', []))
    permissions = set(technique.get('x_mitre_permissions_required', []) or [])
    name = technique.get('name', '')
    description = technique.get('description', '')
    tactics = set()
    for phase in technique.get('kill_chain_phases', []):
        if phase.get('kill_chain_name') == 'mitre-attack':
            tactics.add(phase.get('phase_name', ''))

    # Rule 1: ID from platform keywords.
    id_platform_hits = sorted(platforms & ID_PLATFORM_KEYWORDS)
    if id_platform_hits:
        return {
            'class': 'ID',
            'rule_id': 'R1_ID_PLATFORM_KEYWORD',
            'rule_desc': 'identity/domain/IaaS/SaaS platform cue',
            'evidence': ';'.join(id_platform_hits),
            'is_fallback': False,
        }

    # Rule 2/3: Lateral Movement handling.
    if 'lateral-movement' in tactics:
        tech_id = technique['id']
        for rtype, tgt, _ in rel_fwd.get(tech_id, []):
            if rtype == 'uses' and tgt in by_id:
                sw = by_id[tgt]
                sw_name = sw.get('name', '').lower()
                if any(kw in sw_name for kw in LATERAL_SOFTWARE_KEYWORDS):
                    return {
                        'class': 'ID',
                        'rule_id': 'R2_ID_LATERAL_SW_SIGNAL',
                        'rule_desc': 'lateral-movement AD/domain software cue',
                        'evidence': sw.get('name', ''),
                        'is_fallback': False,
                    }
        return {
            'class': 'ID',
            'rule_id': 'R3_ID_LATERAL_TACTIC',
            'rule_desc': 'lateral-movement tactic policy cue',
            'evidence': 'phase_name=lateral-movement',
            'is_fallback': False,
        }

    # Rule 4: VMR from kernel/boot signal.
    if KERNEL_BOOT_KEYWORDS.search(name) or KERNEL_BOOT_KEYWORDS.search(description[:200]):
        return {
            'class': 'VMR',
            'rule_id': 'R4_VMR_KERNEL_BOOT',
            'rule_desc': 'kernel/boot/firmware text cue',
            'evidence': name,
            'is_fallback': False,
        }

    # Rule 5: VMR from elevated permissions.
    if permissions & VMR_PERMISSIONS:
        return {
            'class': 'VMR',
            'rule_id': 'R5_VMR_PRIVILEGED_PERMISSION',
            'rule_desc': 'elevated/system permission cue',
            'evidence': ';'.join(sorted(permissions & VMR_PERMISSIONS)),
            'is_fallback': False,
        }

    # Rule 6: VMR from name pattern.
    if VMR_NAME_PATTERNS.search(name):
        return {
            'class': 'VMR',
            'rule_id': 'R6_VMR_NAME_PATTERN',
            'rule_desc': 'privileged or host-semantic name cue',
            'evidence': name,
            'is_fallback': False,
        }

    # Rule 7: CF from container-compatible platforms.
    if container_rule == 'subset':
        container_compatible = platforms.issubset(CONTAINER_COMPATIBLE_PLATFORMS)
    elif container_rule == 'intersects':
        container_compatible = bool(platforms & CONTAINER_COMPATIBLE_PLATFORMS)
    else:
        raise ValueError(f'unknown container rule: {container_rule}')
    if platforms and container_compatible:
        if 'privilege-escalation' in tactics or 'defense-evasion' in tactics:
            if permissions & VMR_PERMISSIONS:
                return {
                    'class': 'VMR',
                    'rule_id': 'R5_VMR_PRIVILEGED_PERMISSION',
                    'rule_desc': 'elevated/system permission cue',
                    'evidence': ';'.join(sorted(permissions & VMR_PERMISSIONS)),
                    'is_fallback': False,
                }
        return {
            'class': 'CF',
            'rule_id': 'R7_CF_CONTAINER_COMPATIBLE',
            'rule_desc': 'platform labels match configured CF cue set',
            'evidence': ';'.join(sorted(platforms)),
            'is_fallback': False,
        }

    # Rule 8: Fallback default.
    if default_class is None:
        return {
            'class': 'UNRESOLVED',
            'rule_id': 'R8_DEFAULT_UNRESOLVED',
            'rule_desc': 'no explicit rule fired; leave label unresolved',
            'evidence': '',
            'is_fallback': True,
        }
    return {
        'class': default_class,
        'rule_id': f'R8_DEFAULT_{default_class}',
        'rule_desc': 'no explicit rule fired; apply default policy label',
        'evidence': '',
        'is_fallback': True,
    }


def classify_technique_compatibility(
    technique,
    rel_fwd,
    by_id,
    default_class=DEFAULT_COMPATIBILITY_ROUTING_LABEL,
):
    """Backwards-compatible wrapper returning only the routing-policy label."""
    return classify_technique_compatibility_trace(
        technique, rel_fwd, by_id, default_class=default_class
    )['class']


def analyze_compatibility(
    techniques,
    rel_fwd,
    by_id,
    default_class=DEFAULT_COMPATIBILITY_ROUTING_LABEL,
    container_rule='subset',
):
    """
    RQ2: Apply the CF/VMR/ID routing policy to all techniques.

    Percentages named ``*_pct`` below are corpus-wide unless their name
    explicitly contains ``explicit_only``.  Keeping the denominator in the
    metric name prevents the former invalid subtraction of a corpus-wide
    coverage percentage from an explicit-only non-CF percentage.
    """
    classification = defaultdict(list)
    rule_counter = Counter()
    fallback_count = 0

    for tech in techniques:
        trace = classify_technique_compatibility_trace(
            tech, rel_fwd, by_id, default_class=default_class,
            container_rule=container_rule,
        )
        cls = trace['class']
        rule_counter[trace['rule_id']] += 1
        if trace['is_fallback']:
            fallback_count += 1

        attack_external_id = get_attack_external_id(tech)
        attack_url = get_attack_reference_url(tech)
        tactics = sorted(get_technique_tactics(tech, by_id))
        classification[cls].append({
            'id': tech['id'],
            'name': tech.get('name', ''),
            'external_id': attack_external_id,
            'attack_url': attack_url,
            'tactics': tactics,
            'platforms': tech.get('x_mitre_platforms', []),
            'permissions': tech.get('x_mitre_permissions_required', []),
            'class': cls,
            'routing_label': cls,
            'rule_id': trace['rule_id'],
            'rule_desc': trace['rule_desc'],
            'rule_evidence': trace['evidence'],
            'is_fallback': trace['is_fallback'],
        })

    total = len(techniques)
    cf_count = len(classification.get('CF', []))
    vmr_count = len(classification.get('VMR', []))
    id_count = len(classification.get('ID', []))
    unresolved_count = len(classification.get('UNRESOLVED', []))
    resolved_count = cf_count + vmr_count + id_count
    explicit_count = total - fallback_count
    vmr_explicit_count = sum(
        1 for row in classification.get('VMR', []) if not row.get('is_fallback')
    )
    vmr_fallback_count = sum(
        1 for row in classification.get('VMR', []) if row.get('is_fallback')
    )
    id_explicit_count = sum(
        1 for row in classification.get('ID', []) if not row.get('is_fallback')
    )
    explicit_non_cf_count = vmr_explicit_count + id_explicit_count
    final_non_cf_count = vmr_count + id_count

    return {
        'cf_count': cf_count,
        'cf_pct': pct(cf_count, total),
        'vmr_count': vmr_count,
        'vmr_pct': pct(vmr_count, total),
        'vmr_explicit_count': vmr_explicit_count,
        'vmr_explicit_pct': pct(vmr_explicit_count, total),
        'vmr_fallback_count': vmr_fallback_count,
        'vmr_fallback_pct': pct(vmr_fallback_count, total),
        'id_count': id_count,
        'id_pct': pct(id_count, total),
        'unresolved_count': unresolved_count,
        'unresolved_pct': pct(unresolved_count, total),
        'resolved_count': resolved_count,
        'resolved_pct': pct(resolved_count, total),
        'explicit_count': explicit_count,
        'explicit_pct': pct(explicit_count, total),
        'explicit_non_cf_count': explicit_non_cf_count,
        'explicit_non_cf_explicit_only_pct': pct(
            explicit_non_cf_count, explicit_count
        ),
        'explicit_non_cf_corpus_pct': pct(explicit_non_cf_count, total),
        'final_non_cf_count': final_non_cf_count,
        'final_non_cf_corpus_pct': pct(final_non_cf_count, total),
        'fallback_count': fallback_count,
        'fallback_pct': pct(fallback_count, total),
        'rule_counts': dict(sorted(rule_counter.items())),
        'total': total,
        'details': classification,
    }


def build_compatibility_rule_breakdown(compat_results):
    """
    Build per-class/per-rule breakdown table for auditability.
    """
    rows = []
    for cls_name in ['CF', 'VMR', 'ID', 'UNRESOLVED']:
        class_rows = compat_results['details'].get(cls_name, [])
        by_rule = Counter(r['rule_id'] for r in class_rows)
        total_cls = len(class_rows)
        for rule_id, count in sorted(by_rule.items()):
            pct_cls = pct(count, total_cls)
            pct_all = pct(count, compat_results['total'])
            sample = next((r for r in class_rows if r['rule_id'] == rule_id), None)
            rows.append({
                'class': cls_name,
                'rule_id': rule_id,
                'rule_desc': sample['rule_desc'] if sample else '',
                'count': count,
                'pct_within_class': pct_cls,
                'pct_all_techniques': pct_all,
            })
    return rows


def build_compatibility_by_tactic(compat_results):
    """
    Build tactic-level CF/VMR/ID distribution for exploratory figure evolution.
    Techniques can contribute to multiple tactics.
    """
    per_tactic = defaultdict(Counter)
    for cls_name in ['CF', 'VMR', 'ID']:
        for tech in compat_results['details'].get(cls_name, []):
            tactics = tech.get('tactics', []) or ['(none)']
            for tactic in tactics:
                per_tactic[tactic][cls_name] += 1

    rows = []
    for tactic, counts in per_tactic.items():
        total = sum(counts.values())
        rows.append({
            'tactic': tactic,
            'total': total,
            'cf_count': counts.get('CF', 0),
            'cf_pct': pct(counts.get('CF', 0), total),
            'vmr_count': counts.get('VMR', 0),
            'vmr_pct': pct(counts.get('VMR', 0), total),
            'id_count': counts.get('ID', 0),
            'id_pct': pct(counts.get('ID', 0), total),
            'non_cf_count': counts.get('VMR', 0) + counts.get('ID', 0),
            'non_cf_pct': pct(counts.get('VMR', 0) + counts.get('ID', 0), total),
        })
    rows.sort(key=lambda r: r['total'], reverse=True)
    return rows


def build_compatibility_validation_sample(compat_results, n_per_class=12, seed=42):
    """
    Build a stratified manual-validation sample for CF/VMR/ID outputs.
    Stratification first spreads picks across rule IDs, then fills by random.
    """
    rng = random.Random(seed)
    rows = []

    for cls_name in ['CF', 'VMR', 'ID']:
        class_rows = list(compat_results['details'].get(cls_name, []))
        if not class_rows:
            continue

        by_rule = defaultdict(list)
        for row in class_rows:
            by_rule[row['rule_id']].append(row)
        for rule_rows in by_rule.values():
            rng.shuffle(rule_rows)

        selected = []
        used_ids = set()

        # Pass 1: one row per rule ID (coverage across rules).
        for rule_id in sorted(by_rule.keys()):
            if len(selected) >= n_per_class:
                break
            candidate = next(
                (r for r in by_rule[rule_id] if r['id'] not in used_ids),
                None,
            )
            if candidate:
                selected.append(candidate)
                used_ids.add(candidate['id'])

        # Pass 2: fill remaining quota randomly from leftovers.
        leftovers = [r for r in class_rows if r['id'] not in used_ids]
        rng.shuffle(leftovers)
        for row in leftovers[:max(0, n_per_class - len(selected))]:
            selected.append(row)
            used_ids.add(row['id'])

        for row in selected:
            rows.append({
                'sample_class': cls_name,
                'technique_name': row['name'],
                'technique_stix_id': row['id'],
                'technique_external_id': row.get('external_id', ''),
                'attack_url': row.get('attack_url', ''),
                'tactics': ';'.join(row.get('tactics', []) or []),
                'platforms': ';'.join(row.get('platforms', []) or []),
                'permissions': ';'.join(row.get('permissions', []) or []),
                'policy_label': row['routing_label'],
                # Retained for backward compatibility with the submitted
                # adjudication packet and evaluator.
                'predicted_class': row['class'],
                'rule_id': row.get('rule_id', ''),
                'rule_desc': row.get('rule_desc', ''),
                'rule_evidence': row.get('rule_evidence', ''),
                'is_fallback': row.get('is_fallback', False),
                # Columns intentionally blank for human adjudication.
                'manual_expected_class': '',
                'manual_verdict_match': '',
                'manual_notes': '',
                'reviewer': '',
            })

    return rows


def merge_compatibility_manual_annotations(rows, existing_csv):
    """Preserve human adjudication when the deterministic sample is rebuilt."""
    existing_csv = Path(existing_csv)
    if not existing_csv.exists():
        return rows

    manual_fields = (
        'manual_expected_class',
        'manual_verdict_match',
        'manual_notes',
        'reviewer',
    )
    with existing_csv.open(newline='', encoding='utf-8') as f:
        existing_by_id = {
            row.get('technique_stix_id', ''): row
            for row in csv.DictReader(f)
            if row.get('technique_stix_id')
        }

    for row in rows:
        existing = existing_by_id.get(row.get('technique_stix_id', ''))
        if not existing:
            continue
        for field in manual_fields:
            row[field] = existing.get(field, '')
    return rows


def build_compatibility_denominator_summary(
    compat_results,
    manual_sample_size=0,
    manual_labels_completed=0,
):
    """Expose numerators, denominators, and scopes for routing-policy metrics."""
    total = compat_results['total']
    explicit = compat_results['explicit_count']
    rows = [
        {
            'metric': 'explicit_rule_assignment_coverage',
            'numerator': explicit,
            'denominator': total,
            'percentage': pct(explicit, total),
            'denominator_scope': 'corpus-wide',
            'interpretation': 'techniques assigned by an explicit heuristic rule',
        },
        {
            'metric': 'fallback_assignment_share',
            'numerator': compat_results['fallback_count'],
            'denominator': total,
            'percentage': pct(compat_results['fallback_count'], total),
            'denominator_scope': 'corpus-wide',
            'interpretation': 'techniques assigned only by the default routing policy',
        },
        {
            'metric': 'final_policy_label_coverage',
            'numerator': compat_results['resolved_count'],
            'denominator': total,
            'percentage': pct(compat_results['resolved_count'], total),
            'denominator_scope': 'corpus-wide',
            'interpretation': 'techniques carrying a policy label after fallback',
        },
        {
            'metric': 'explicit_non_cf_share',
            'numerator': compat_results['explicit_non_cf_count'],
            'denominator': explicit,
            'percentage': pct(compat_results['explicit_non_cf_count'], explicit),
            'denominator_scope': 'explicit-only',
            'interpretation': 'non-CF composition among explicit-rule assignments',
        },
        {
            'metric': 'explicit_non_cf_corpus_share',
            'numerator': compat_results['explicit_non_cf_count'],
            'denominator': total,
            'percentage': pct(compat_results['explicit_non_cf_count'], total),
            'denominator_scope': 'corpus-wide',
            'interpretation': 'explicit non-CF labels as a share of all techniques',
        },
        {
            'metric': 'final_non_cf_corpus_share',
            'numerator': compat_results['final_non_cf_count'],
            'denominator': total,
            'percentage': pct(compat_results['final_non_cf_count'], total),
            'denominator_scope': 'corpus-wide',
            'interpretation': 'non-CF policy labels after fallback',
        },
        {
            'metric': 'manual_label_completion',
            'numerator': manual_labels_completed,
            'denominator': manual_sample_size,
            'percentage': pct(manual_labels_completed, manual_sample_size),
            'denominator_scope': 'manual-validation-sample',
            'interpretation': 'independently adjudicated policy-label rows; not accuracy',
        },
    ]
    return rows


def analyze_compatibility_default_sensitivity(techniques, rel_fwd, by_id):
    """
    Sensitivity check for the compatibility routing policy under alternative
    fallback labels. The explicit rule body remains fixed; only the label
    assigned when no rule fires changes.
    """
    rows = []
    scenarios = [
        ('CF', 'CF'),
        ('VMR', 'VMR'),
        ('ID', 'ID'),
        ('UNRESOLVED', None),
    ]
    for label, default_class in scenarios:
        res = analyze_compatibility(
            techniques, rel_fwd, by_id, default_class=default_class
        )
        non_cf_count = res['vmr_count'] + res['id_count']
        # Corpus-wide and explicit-only shares answer different questions.
        # Compute each from counts, never by adding already-rounded percentages.
        non_cf_corpus_pct = pct(non_cf_count, res['total'])
        rows.append({
            'default_class': label,
            'cf_count': res['cf_count'],
            'cf_pct': res['cf_pct'],
            'vmr_count': res['vmr_count'],
            'vmr_pct': res['vmr_pct'],
            'id_count': res['id_count'],
            'id_pct': res['id_pct'],
            'unresolved_count': res['unresolved_count'],
            'unresolved_pct': res['unresolved_pct'],
            'resolved_count': res['resolved_count'],
            'resolved_pct': res['resolved_pct'],
            'non_cf_count': non_cf_count,
            'non_cf_pct': non_cf_corpus_pct,
            'non_cf_corpus_pct': non_cf_corpus_pct,
            'explicit_count': res['explicit_count'],
            'explicit_non_cf_count': res['explicit_non_cf_count'],
            'explicit_non_cf_explicit_only_pct': (
                res['explicit_non_cf_explicit_only_pct']
            ),
            'total': res['total'],
        })
    return rows


# ─────────────────────────────────────────────────────────────────
# 6. SUT Profile Specificity (Jaccard)
# ─────────────────────────────────────────────────────────────────

def build_sut_profiles(
    intrusion_sets, software_objects, rel_fwd, by_id,
    include_cve=False, platform_mode='none',
    include_compat_summary=False, compatibility_by_technique=None
):
    """
    Build binary SUT profile vectors for each intrusion set.
    Profile = set of software IDs (+ optionally CVE IDs, platform labels, compatibility summaries) linked to the IS.
    platform_mode: 'none' | 'raw' | 'family'
    """
    software_ids = set(s['id'] for s in software_objects)

    # Build universe of all possible features
    all_features = set()
    profiles = {}

    for iset in intrusion_sets:
        is_id = iset['id']
        profile = set()

        # Software linked to IS
        for rtype, tgt, _ in rel_fwd.get(is_id, []):
            if rtype == 'uses' and tgt in software_ids:
                profile.add(tgt)
                all_features.add(tgt)

        # Optionally add CVEs
        if include_cve:
            # Direct CVEs
            _, f = extract_cves_from_object(iset)
            s, _ = extract_cves_from_object(iset)
            cves = s | f

            # CVEs from linked software
            for rtype, tgt, _ in rel_fwd.get(is_id, []):
                if rtype == 'uses' and tgt in by_id:
                    obj = by_id[tgt]
                    if obj.get('type') in ('malware', 'tool'):
                        s2, f2 = extract_cves_from_object(obj)
                        cves.update(s2 | f2)

            for cve in cves:
                profile.add(f"CVE:{cve}")
                all_features.add(f"CVE:{cve}")

        # Optionally add platform labels from linked software objects
        if platform_mode in ('raw', 'family'):
            platforms = set()
            for rtype, tgt, _ in rel_fwd.get(is_id, []):
                if rtype == 'uses' and tgt in by_id:
                    obj = by_id[tgt]
                    if obj.get('type') in ('malware', 'tool'):
                        for p in obj.get('x_mitre_platforms', []) or []:
                            if platform_mode == 'raw':
                                platforms.add(p)
                            else:
                                fam = normalize_os_family(p)
                                if fam:
                                    platforms.add(fam)
            for p in platforms:
                feat = f"PLATFORM:{p}"
                profile.add(feat)
                all_features.add(feat)

        # Optionally add compatibility summary from IS-linked techniques.
        if include_compat_summary and compatibility_by_technique is not None:
            compat_counts = Counter()
            for rtype, tgt, _ in rel_fwd.get(is_id, []):
                if rtype == 'uses' and tgt in by_id:
                    obj = by_id[tgt]
                    if obj.get('type') == 'attack-pattern':
                        cls = compatibility_by_technique.get(tgt)
                        if cls:
                            compat_counts[cls] += 1
            if compat_counts:
                for cls in sorted(compat_counts.keys()):
                    feat = f"COMPAT_PRESENT:{cls}"
                    profile.add(feat)
                    all_features.add(feat)
                dominant_cls = max(
                    sorted(compat_counts.keys()),
                    key=lambda k: compat_counts[k],
                )
                dom_feat = f"COMPAT_DOMINANT:{dominant_cls}"
                profile.add(dom_feat)
                all_features.add(dom_feat)

        profiles[is_id] = profile

    return profiles, sorted(all_features)


def jaccard_distance(set_a, set_b):
    """Compute Jaccard distance between two sets."""
    if not set_a and not set_b:
        return 0.0  # Both empty -> identical
    union = set_a | set_b
    intersection = set_a & set_b
    if not union:
        return 0.0
    return 1.0 - len(intersection) / len(union)


def compute_confusion_from_profiles(profiles, delta):
    """
    Compute nearest-neighbor confusion over a dict is_id -> feature-set.
    Returns (confused_count, confusion_pct, nearest_distances).
    """
    is_ids = list(profiles.keys())
    n = len(is_ids)
    if n == 0:
        return 0, 0.0, []

    confused_count = 0
    nearest_distances = []
    for i in range(n):
        prof_i = profiles[is_ids[i]]
        min_dist = float('inf')
        for j in range(n):
            if i == j:
                continue
            prof_j = profiles[is_ids[j]]
            dist = jaccard_distance(prof_i, prof_j)
            if dist < min_dist:
                min_dist = dist
        if min_dist == float('inf'):
            min_dist = 1.0
        nearest_distances.append(min_dist)
        if min_dist <= delta:
            confused_count += 1
    return confused_count, pct(confused_count, n), nearest_distances


def compute_threshold_confusion_from_profiles(profiles, min_feature_count, delta):
    """Recompute nearest-neighbor confusion inside a cardinality-conditioned set.

    Filtering precomputed nearest-neighbor indicators is not equivalent to
    conditioning the comparison population: a row's former nearest neighbor
    may have been excluded.  This helper first selects the eligible profiles
    and then recomputes all nearest-neighbor distances within that population.
    """
    eligible = {
        profile_id: feature_set
        for profile_id, feature_set in profiles.items()
        if len(feature_set) >= min_feature_count
    }
    confused_count, confusion_pct, _ = compute_confusion_from_profiles(
        eligible, delta
    )
    sample_size = len(eligible)
    confusion_pct_raw = (
        100.0 * confused_count / sample_size if sample_size else 0.0
    )
    return {
        'min_software_count': min_feature_count,
        'sample_size': sample_size,
        'confused_count': confused_count,
        'confusion_pct': confusion_pct,
        'confusion_pct_raw': confusion_pct_raw,
    }


def analyze_min_evidence_threshold_profiles(profiles, threshold_delta):
    """Compute the k-threshold curve with comparisons recomputed per subset."""
    if not profiles:
        return {
            'curve': [],
            'k1_confusion_pct': 0.0,
            'k2_confusion_pct': 0.0,
            'k3_confusion_pct': 0.0,
            'k5_confusion_pct': 0.0,
            'k1_sample': 0,
            'k2_sample': 0,
            'k3_sample': 0,
            'k5_sample': 0,
        }

    max_k = max(len(feature_set) for feature_set in profiles.values())
    curve = []
    for k in range(1, max_k + 1):
        row = compute_threshold_confusion_from_profiles(
            profiles, k, threshold_delta
        )
        if row['sample_size']:
            row = dict(row)
            row.pop('confusion_pct_raw', None)
            curve.append(row)

    by_k = {row['min_software_count']: row for row in curve}
    return {
        'curve': curve,
        'k1_confusion_pct': by_k.get(1, {}).get('confusion_pct', 0.0),
        'k2_confusion_pct': by_k.get(2, {}).get('confusion_pct', 0.0),
        'k3_confusion_pct': by_k.get(3, {}).get('confusion_pct', 0.0),
        'k5_confusion_pct': by_k.get(5, {}).get('confusion_pct', 0.0),
        'k1_sample': by_k.get(1, {}).get('sample_size', 0),
        'k2_sample': by_k.get(2, {}).get('sample_size', 0),
        'k3_sample': by_k.get(3, {}).get('sample_size', 0),
        'k5_sample': by_k.get(5, {}).get('sample_size', 0),
    }


def analyze_profile_specificity(
    intrusion_sets, software_objects, rel_fwd, by_id, compatibility_by_technique=None
):
    """
    RQ3: SUT profile specificity analysis.
    Computes for software-only, software+CVE, software+platform, software+CVE+platform,
    software+OS-family, and software+compatibility-summary settings.
    """
    results = {}

    settings = [
        ('software_only', False, 'none', False),
        ('software_cve', True, 'none', False),
        ('software_platform', False, 'raw', False),
        ('software_cve_platform', True, 'raw', False),
        ('software_family_only', False, 'family', False),
        ('software_compat', False, 'none', True),
    ]
    for setting, include_cve, platform_mode, include_compat_summary in settings:
        profiles, features = build_sut_profiles(
            intrusion_sets, software_objects, rel_fwd, by_id,
            include_cve=include_cve,
            platform_mode=platform_mode,
            include_compat_summary=include_compat_summary,
            compatibility_by_technique=compatibility_by_technique,
        )

        is_ids = list(profiles.keys())
        n = len(is_ids)
        confused_count, confused_pct, nearest_distances = compute_confusion_from_profiles(
            profiles, JACCARD_DELTA
        )
        per_is_rows = []

        for i in range(n):
            min_dist = float('inf')
            prof_i = profiles[is_ids[i]]
            nearest_neighbor = ""

            for j in range(n):
                if i == j:
                    continue
                prof_j = profiles[is_ids[j]]
                dist = jaccard_distance(prof_i, prof_j)
                if dist < min_dist:
                    min_dist = dist
                    nearest_neighbor = is_ids[j]

            # Handle empty profiles: distance to any non-empty is 1.0
            # distance to another empty is 0.0
            if min_dist == float('inf'):
                min_dist = 1.0

            per_is_rows.append({
                'intrusion_set_id': is_ids[i],
                'feature_count': len(prof_i),
                'nearest_neighbor_id': nearest_neighbor,
                'nearest_distance': round(min_dist, 4),
                'confused': min_dist <= JACCARD_DELTA,
            })

        unique_count = n - confused_count
        unique_pct = pct(unique_count, n)

        results[setting] = {
            'unique_count': unique_count,
            'unique_pct': unique_pct,
            'confused_count': confused_count,
            'confused_pct': confused_pct,
            'total_is': n,
            'nearest_distances': nearest_distances,
            'num_features': len(features),
            'per_is_rows': per_is_rows,
        }

    return results


def analyze_technique_profile_specificity(intrusion_sets, techniques, rel_fwd, rel_rev, delta=JACCARD_DELTA):
    """
    Exploratory: nearest-neighbor specificity using behavior-only profiles
    (intrusion-set to linked attack-pattern techniques).
    """
    technique_ids = {t['id'] for t in techniques}
    profiles = {}
    for iset in intrusion_sets:
        is_id = iset['id']
        prof = set()
        for rtype, tgt, _ in rel_fwd.get(is_id, []):
            if rtype == 'uses' and tgt in technique_ids:
                prof.add(tgt)
        for rtype, src, _ in rel_rev.get(is_id, []):
            if rtype == 'uses' and src in technique_ids:
                prof.add(src)
        profiles[is_id] = prof

    is_ids = list(profiles.keys())
    n = len(is_ids)
    confused_count, confused_pct, nearest_distances = compute_confusion_from_profiles(
        profiles, delta
    )

    per_is_rows = []
    for i in range(n):
        prof_i = profiles[is_ids[i]]
        min_dist = float('inf')
        nearest_neighbor = ""
        for j in range(n):
            if i == j:
                continue
            prof_j = profiles[is_ids[j]]
            dist = jaccard_distance(prof_i, prof_j)
            if dist < min_dist:
                min_dist = dist
                nearest_neighbor = is_ids[j]
        if min_dist == float('inf'):
            min_dist = 1.0
        per_is_rows.append({
            'intrusion_set_id': is_ids[i],
            'feature_count': len(prof_i),
            'nearest_neighbor_id': nearest_neighbor,
            'nearest_distance': round(min_dist, 4),
            'confused': min_dist <= delta,
        })

    unique_count = n - confused_count
    threshold_results = analyze_min_evidence_threshold(per_is_rows, delta)
    return {
        'unique_count': unique_count,
        'unique_pct': pct(unique_count, n),
        'confused_count': confused_count,
        'confused_pct': confused_pct,
        'total_is': n,
        'nearest_distances': nearest_distances,
        'per_is_rows': per_is_rows,
        'feature_universe_size': len(technique_ids),
        'threshold': threshold_results,
    }


def _empirical_percentile(values, quantile):
    """Nearest-rank empirical percentile for a non-empty numeric sequence."""
    if not values:
        return 0.0
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, math.ceil(quantile * len(ordered)) - 1))
    return ordered[index]


def randomize_profiles_preserving_cardinality(profiles, feature_universe, rng):
    """Sample feature identities uniformly while fixing every profile size."""
    universe = sorted(set(feature_universe))
    randomized = {}
    for profile_id in sorted(profiles):
        cardinality = len(profiles[profile_id])
        if cardinality > len(universe):
            raise ValueError(
                f"profile {profile_id} has cardinality {cardinality}, "
                f"larger than the feature universe ({len(universe)})"
            )
        randomized[profile_id] = (
            set(rng.sample(universe, cardinality)) if cardinality else set()
        )
    return randomized


def _threshold_collapse_statistic(profiles, delta, lower_k=1, upper_k=2):
    """Return C(k>=lower)-C(k>=upper), recomputing each eligible population."""
    lower = compute_threshold_confusion_from_profiles(profiles, lower_k, delta)
    upper = compute_threshold_confusion_from_profiles(profiles, upper_k, delta)
    collapse_pp_raw = lower['confusion_pct_raw'] - upper['confusion_pct_raw']
    return lower, upper, collapse_pp_raw


def analyze_threshold_collapse_null_model(
    observed_profiles,
    feature_universe,
    delta=JACCARD_DELTA,
    lower_k=1,
    upper_k=2,
    n_iter=1000,
    seed=42,
):
    """Direct cardinality-preserving null for the conditioned k-threshold drop.

    Every simulated profile keeps its observed cardinality and the number of
    profiles is fixed.  Feature identities are sampled uniformly without
    replacement from the corpus software universe.  The tested statistic is
    C(k>=lower)-C(k>=upper), not the all-profile confusion rate.  The reported
    upper-tail probability uses the finite-Monte-Carlo plus-one correction.
    """
    if lower_k >= upper_k:
        raise ValueError("lower_k must be smaller than upper_k")
    if n_iter < 1:
        raise ValueError("n_iter must be positive")

    observed_global_count, observed_global_pct, _ = compute_confusion_from_profiles(
        observed_profiles, delta
    )
    observed_lower, observed_upper, observed_collapse_raw = (
        _threshold_collapse_statistic(
            observed_profiles, delta, lower_k=lower_k, upper_k=upper_k
        )
    )

    rng = random.Random(seed)
    global_samples = []
    collapse_samples_raw = []
    rows = []
    for idx in range(1, n_iter + 1):
        randomized_profiles = randomize_profiles_preserving_cardinality(
            observed_profiles, feature_universe, rng
        )
        global_count, global_pct, _ = compute_confusion_from_profiles(
            randomized_profiles, delta
        )
        lower, upper, collapse_raw = _threshold_collapse_statistic(
            randomized_profiles, delta, lower_k=lower_k, upper_k=upper_k
        )
        global_samples.append(global_pct)
        collapse_samples_raw.append(collapse_raw)
        rows.append({
            'iteration': idx,
            'global_confused_count': global_count,
            'global_confusion_pct': global_pct,
            'k1_sample_size': lower['sample_size'],
            'k1_confused_count': lower['confused_count'],
            'k1_confusion_pct': lower['confusion_pct'],
            'k2_sample_size': upper['sample_size'],
            'k2_confused_count': upper['confused_count'],
            'k2_confusion_pct': upper['confusion_pct'],
            'collapse_pp': round(collapse_raw, 4),
        })

    global_mean = sum(global_samples) / n_iter
    collapse_mean_raw = sum(collapse_samples_raw) / n_iter
    global_extreme = sum(
        value >= observed_global_pct for value in global_samples
    )
    collapse_extreme = sum(
        value >= observed_collapse_raw - 1e-12
        for value in collapse_samples_raw
    )
    collapse_p_value = (collapse_extreme + 1) / (n_iter + 1)

    return {
        'iterations': n_iter,
        'seed': seed,
        'feature_universe_size': len(set(feature_universe)),
        # Legacy all-profile diagnostic.  Retained for reproducibility, but it
        # is not the inferential test for the k>=1 to k>=2 observation.
        'observed_confused_count': observed_global_count,
        'observed_confusion_pct': observed_global_pct,
        'null_confusion_mean_pct': round(global_mean, 1),
        'null_confusion_p05_pct': round(_empirical_percentile(global_samples, 0.05), 1),
        'null_confusion_p50_pct': round(_empirical_percentile(global_samples, 0.50), 1),
        'null_confusion_p95_pct': round(_empirical_percentile(global_samples, 0.95), 1),
        'delta_observed_minus_null_mean_pp': round(
            observed_global_pct - global_mean, 1
        ),
        'p_value': round((global_extreme + 1) / (n_iter + 1), 3),
        # Direct threshold-conditioned statistic.
        'lower_k': lower_k,
        'upper_k': upper_k,
        'observed_k1_sample_size': observed_lower['sample_size'],
        'observed_k1_confused_count': observed_lower['confused_count'],
        'observed_k1_confusion_pct': observed_lower['confusion_pct'],
        'observed_k2_sample_size': observed_upper['sample_size'],
        'observed_k2_confused_count': observed_upper['confused_count'],
        'observed_k2_confusion_pct': observed_upper['confusion_pct'],
        'observed_collapse_pp': round(observed_collapse_raw, 1),
        'null_collapse_mean_pp': round(collapse_mean_raw, 1),
        'null_collapse_p05_pp': round(
            _empirical_percentile(collapse_samples_raw, 0.05), 1
        ),
        'null_collapse_p50_pp': round(
            _empirical_percentile(collapse_samples_raw, 0.50), 1
        ),
        'null_collapse_p95_pp': round(
            _empirical_percentile(collapse_samples_raw, 0.95), 1
        ),
        'collapse_extreme_iterations': collapse_extreme,
        'collapse_p_value': round(collapse_p_value, 3),
        'collapse_p_value_mc_se': round(
            math.sqrt(collapse_p_value * (1.0 - collapse_p_value) / (n_iter + 1)),
            3,
        ),
        'distribution_rows': rows,
    }


def analyze_sparsity_null_model(
    intrusion_sets, software_objects, rel_fwd, by_id,
    delta=JACCARD_DELTA, n_iter=1000, seed=42
):
    """Build software profiles and run the direct k-threshold null model."""
    observed_profiles, _ = build_sut_profiles(
        intrusion_sets, software_objects, rel_fwd, by_id,
        include_cve=False,
        platform_mode='none',
    )
    software_universe = [software['id'] for software in software_objects]
    return analyze_threshold_collapse_null_model(
        observed_profiles,
        software_universe,
        delta=delta,
        lower_k=1,
        upper_k=2,
        n_iter=n_iter,
        seed=seed,
    )


def _attempt_degree_preserving_edge_swaps(profile_sets, edges, rng, attempts):
    """Mutate a simple bipartite profile graph using degree-preserving swaps."""
    accepted = 0
    edge_count = len(edges)
    if edge_count < 2:
        return accepted
    for _ in range(attempts):
        first_index = rng.randrange(edge_count)
        second_index = rng.randrange(edge_count)
        if first_index == second_index:
            continue
        first_profile, first_feature = edges[first_index]
        second_profile, second_feature = edges[second_index]
        if first_profile == second_profile or first_feature == second_feature:
            continue
        if (
            second_feature in profile_sets[first_profile]
            or first_feature in profile_sets[second_profile]
        ):
            continue
        profile_sets[first_profile].remove(first_feature)
        profile_sets[first_profile].add(second_feature)
        profile_sets[second_profile].remove(second_feature)
        profile_sets[second_profile].add(first_feature)
        edges[first_index] = (first_profile, second_feature)
        edges[second_index] = (second_profile, first_feature)
        accepted += 1
    return accepted


def analyze_degree_preserving_threshold_sensitivity(
    observed_profiles,
    delta=JACCARD_DELTA,
    lower_k=1,
    upper_k=2,
    n_iter=1000,
    seed=43,
    burn_in_edge_multiples=50,
    thinning_edge_multiples=5,
):
    """Sensitivity null preserving profile sizes and software popularity.

    Double-edge swaps preserve both sides of the intrusion-set/software
    bipartite degree sequence.  This is a sensitivity analysis because samples
    come from a thinned Markov chain rather than independent uniform draws.
    """
    if n_iter < 1:
        raise ValueError("n_iter must be positive")
    profile_sets = {
        profile_id: set(observed_profiles[profile_id])
        for profile_id in sorted(observed_profiles)
    }
    edges = [
        (profile_id, feature_id)
        for profile_id in sorted(profile_sets)
        for feature_id in sorted(profile_sets[profile_id])
    ]
    edge_count = len(edges)
    rng = random.Random(seed)
    burn_attempts = burn_in_edge_multiples * edge_count
    between_sample_attempts = thinning_edge_multiples * edge_count
    accepted_total = _attempt_degree_preserving_edge_swaps(
        profile_sets, edges, rng, burn_attempts
    )

    _, _, observed_collapse_raw = _threshold_collapse_statistic(
        observed_profiles, delta, lower_k=lower_k, upper_k=upper_k
    )
    collapse_samples_raw = []
    rows = []
    for idx in range(1, n_iter + 1):
        accepted = _attempt_degree_preserving_edge_swaps(
            profile_sets, edges, rng, between_sample_attempts
        )
        accepted_total += accepted
        lower, upper, collapse_raw = _threshold_collapse_statistic(
            profile_sets, delta, lower_k=lower_k, upper_k=upper_k
        )
        collapse_samples_raw.append(collapse_raw)
        rows.append({
            'iteration': idx,
            'accepted_swaps': accepted,
            'k1_sample_size': lower['sample_size'],
            'k1_confused_count': lower['confused_count'],
            'k1_confusion_pct': lower['confusion_pct'],
            'k2_sample_size': upper['sample_size'],
            'k2_confused_count': upper['confused_count'],
            'k2_confusion_pct': upper['confusion_pct'],
            'collapse_pp': round(collapse_raw, 4),
        })

    total_attempts = burn_attempts + n_iter * between_sample_attempts
    extreme = sum(
        value >= observed_collapse_raw - 1e-12
        for value in collapse_samples_raw
    )
    collapse_p_value = (extreme + 1) / (n_iter + 1)
    return {
        'iterations': n_iter,
        'seed': seed,
        'edge_count': edge_count,
        'burn_in_attempts': burn_attempts,
        'between_sample_attempts': between_sample_attempts,
        'accepted_swap_rate': round(
            accepted_total / total_attempts, 4
        ) if total_attempts else 0.0,
        'observed_collapse_pp': round(observed_collapse_raw, 1),
        'null_collapse_mean_pp': round(
            sum(collapse_samples_raw) / n_iter, 1
        ),
        'null_collapse_p05_pp': round(
            _empirical_percentile(collapse_samples_raw, 0.05), 1
        ),
        'null_collapse_p50_pp': round(
            _empirical_percentile(collapse_samples_raw, 0.50), 1
        ),
        'null_collapse_p95_pp': round(
            _empirical_percentile(collapse_samples_raw, 0.95), 1
        ),
        'collapse_extreme_iterations': extreme,
        'collapse_p_value': round(collapse_p_value, 3),
        'collapse_p_value_mc_se': round(
            math.sqrt(collapse_p_value * (1.0 - collapse_p_value) / (n_iter + 1)),
            3,
        ),
        'distribution_rows': rows,
    }


def analyze_threshold_collapse_leave_one_out(
    observed_profiles, delta=JACCARD_DELTA, lower_k=1, upper_k=2
):
    """Deterministic influence analysis for the threshold-collapse statistic."""
    observed_lower, observed_upper, observed_collapse_raw = _threshold_collapse_statistic(
        observed_profiles, delta, lower_k=lower_k, upper_k=upper_k
    )
    rows = []
    influential_ids = []
    for omitted_id in sorted(observed_profiles):
        reduced = {
            profile_id: feature_set
            for profile_id, feature_set in observed_profiles.items()
            if profile_id != omitted_id
        }
        lower, upper, collapse_raw = _threshold_collapse_statistic(
            reduced, delta, lower_k=lower_k, upper_k=upper_k
        )
        change_raw = collapse_raw - observed_collapse_raw
        changes_confusion_counts = (
            lower['confused_count'] != observed_lower['confused_count']
            or upper['confused_count'] != observed_upper['confused_count']
        )
        changes_reported_collapse = (
            round(collapse_raw, 1) != round(observed_collapse_raw, 1)
        )
        influential = changes_confusion_counts
        if influential:
            influential_ids.append(omitted_id)
        rows.append({
            'omitted_profile_id': omitted_id,
            'omitted_feature_count': len(observed_profiles[omitted_id]),
            'collapse_pp': round(collapse_raw, 4),
            'change_from_full_pp': round(change_raw, 4),
            'changes_confusion_counts': changes_confusion_counts,
            'changes_reported_collapse': changes_reported_collapse,
        })

    influential_feature_sets = [
        observed_profiles[profile_id] for profile_id in influential_ids
    ]
    shared_features = (
        set.intersection(*influential_feature_sets)
        if influential_feature_sets else set()
    )
    return {
        'observed_collapse_pp': round(observed_collapse_raw, 1),
        'profile_count': len(observed_profiles),
        'influential_profile_count': len(influential_ids),
        'influential_profile_ids': influential_ids,
        'influential_shared_feature_ids': sorted(shared_features),
        'minimum_leave_one_out_collapse_pp': round(
            min((row['collapse_pp'] for row in rows), default=0.0), 1
        ),
        'maximum_leave_one_out_collapse_pp': round(
            max((row['collapse_pp'] for row in rows), default=0.0), 1
        ),
        'rows': rows,
    }


def analyze_min_evidence_threshold(per_is_rows, threshold_delta):
    """
    Compute confusion behavior for increasing minimum profile size.
    """
    if not per_is_rows:
        return {
            'curve': [],
            'k1_confusion_pct': 0.0,
            'k2_confusion_pct': 0.0,
            'k3_confusion_pct': 0.0,
            'k5_confusion_pct': 0.0,
            'k1_sample': 0,
            'k2_sample': 0,
            'k3_sample': 0,
            'k5_sample': 0,
        }

    max_k = max(row['feature_count'] for row in per_is_rows)
    curve = []
    for k in range(1, max_k + 1):
        subset = [row for row in per_is_rows if row['feature_count'] >= k]
        if not subset:
            continue
        confused = sum(1 for row in subset if row['nearest_distance'] <= threshold_delta)
        curve.append({
            'min_software_count': k,
            'sample_size': len(subset),
            'confused_count': confused,
            'confusion_pct': pct(confused, len(subset)),
        })

    by_k = {row['min_software_count']: row for row in curve}
    return {
        'curve': curve,
        'k1_confusion_pct': by_k.get(1, {}).get('confusion_pct', 0.0),
        'k2_confusion_pct': by_k.get(2, {}).get('confusion_pct', 0.0),
        'k3_confusion_pct': by_k.get(3, {}).get('confusion_pct', 0.0),
        'k5_confusion_pct': by_k.get(5, {}).get('confusion_pct', 0.0),
        'k1_sample': by_k.get(1, {}).get('sample_size', 0),
        'k2_sample': by_k.get(2, {}).get('sample_size', 0),
        'k3_sample': by_k.get(3, {}).get('sample_size', 0),
        'k5_sample': by_k.get(5, {}).get('sample_size', 0),
    }


def analyze_delta_sensitivity(per_is_rows, deltas):
    """
    Confusion sensitivity for multiple Jaccard thresholds using same IS set.
    """
    rows = []
    total = len(per_is_rows)
    for delta in deltas:
        confused = sum(1 for row in per_is_rows if row['nearest_distance'] <= delta)
        rows.append({
            'delta': delta,
            'sample_size': total,
            'confused_count': confused,
            'confusion_pct': pct(confused, total),
        })
    return rows


def bootstrap_confusion_ci(per_is_rows, delta, n_boot=5000, seed=42):
    """
    Descriptive indicator-resampling interval at a fixed delta.

    Sampling unit: the already-computed intrusion-set nearest-distance row.
    Neighbors are not recomputed after resampling, so this is an interval for
    the mean of fixed confusion indicators, not a bootstrap confidence
    interval for the dependent nearest-neighbor graph functional.  The direct
    threshold null and leave-one-out analysis carry the RQ3 robustness claim.
    """
    total = len(per_is_rows)
    if total == 0:
        return {
            'confusion_pct': 0.0,
            'unique_pct': 0.0,
            'confusion_ci_low': 0.0,
            'confusion_ci_high': 0.0,
            'unique_ci_low': 0.0,
            'unique_ci_high': 0.0,
            'bootstrap_summary_rows': [],
        }

    rng = random.Random(seed)
    confusion_samples = []
    unique_samples = []

    for _ in range(n_boot):
        sample = [per_is_rows[rng.randrange(total)] for _ in range(total)]
        confused = sum(1 for row in sample if row['nearest_distance'] <= delta)
        confusion_rate = 100.0 * confused / total
        unique_rate = 100.0 - confusion_rate
        confusion_samples.append(confusion_rate)
        unique_samples.append(unique_rate)

    confusion_samples.sort()
    unique_samples.sort()
    lo_idx = int(0.025 * n_boot)
    hi_idx = int(0.975 * n_boot) - 1
    if hi_idx < 0:
        hi_idx = 0

    point_confused = sum(1 for row in per_is_rows if row['nearest_distance'] <= delta)
    point_conf_pct = pct(point_confused, total)
    point_unique_pct = pct(total - point_confused, total)

    return {
        'confusion_pct': point_conf_pct,
        'unique_pct': point_unique_pct,
        'confusion_ci_low': round(confusion_samples[lo_idx], 1),
        'confusion_ci_high': round(confusion_samples[hi_idx], 1),
        'unique_ci_low': round(unique_samples[lo_idx], 1),
        'unique_ci_high': round(unique_samples[hi_idx], 1),
        'bootstrap_summary_rows': [
            {'stat': 'n_boot', 'confusion_pct': float(n_boot), 'unique_pct': float(n_boot)},
            {'stat': 'p01', 'confusion_pct': round(confusion_samples[int(0.01 * n_boot)], 4), 'unique_pct': round(unique_samples[int(0.01 * n_boot)], 4)},
            {'stat': 'p05', 'confusion_pct': round(confusion_samples[int(0.05 * n_boot)], 4), 'unique_pct': round(unique_samples[int(0.05 * n_boot)], 4)},
            {'stat': 'p50', 'confusion_pct': round(confusion_samples[int(0.50 * n_boot)], 4), 'unique_pct': round(unique_samples[int(0.50 * n_boot)], 4)},
            {'stat': 'p95', 'confusion_pct': round(confusion_samples[int(0.95 * n_boot)], 4), 'unique_pct': round(unique_samples[int(0.95 * n_boot)], 4)},
            {'stat': 'p99', 'confusion_pct': round(confusion_samples[int(0.99 * n_boot)], 4), 'unique_pct': round(unique_samples[int(0.99 * n_boot)], 4)},
        ],
    }


# ─────────────────────────────────────────────────────────────────
# 7. Exploratory correlation summaries (campaign-level)
# ─────────────────────────────────────────────────────────────────

def _mean(values):
    if not values:
        return 0.0
    return sum(values) / len(values)


def _median(values):
    if not values:
        return 0.0
    vals = sorted(values)
    n = len(vals)
    mid = n // 2
    if n % 2 == 1:
        return float(vals[mid])
    return (vals[mid - 1] + vals[mid]) / 2.0


def _pearson_corr(xs, ys):
    if not xs or not ys or len(xs) != len(ys):
        return 0.0
    mx = _mean(xs)
    my = _mean(ys)
    num = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    den_x = math.sqrt(sum((x - mx) ** 2 for x in xs))
    den_y = math.sqrt(sum((y - my) ** 2 for y in ys))
    if den_x == 0 or den_y == 0:
        return 0.0
    return num / (den_x * den_y)


def _rank_with_ties(values):
    """
    Average-tie ranking (1-indexed ranks).
    """
    indexed = sorted(enumerate(values), key=lambda it: it[1])
    ranks = [0.0] * len(values)
    i = 0
    while i < len(indexed):
        j = i
        while j + 1 < len(indexed) and indexed[j + 1][1] == indexed[i][1]:
            j += 1
        avg_rank = (i + j + 2) / 2.0
        for k in range(i, j + 1):
            ranks[indexed[k][0]] = avg_rank
        i = j + 1
    return ranks


def _spearman_corr(xs, ys):
    if not xs or not ys or len(xs) != len(ys):
        return 0.0
    rx = _rank_with_ties(xs)
    ry = _rank_with_ties(ys)
    return _pearson_corr(rx, ry)


def analyze_campaign_serendipity(
    software_results,
    cve_results,
    initial_access_results,
    profile_completeness,
):
    """
    Build reproducible campaign-level exploratory summaries to support
    narrative checks without overclaiming causality.
    """
    sw_by_campaign = {
        row['campaign_id']: int(row.get('software_count', 0))
        for row in software_results.get('campaign_details', [])
    }
    cve_by_campaign = {
        row['campaign_id']: int(row.get('cve_count', 0))
        for row in cve_results.get('campaign_cve_details', [])
    }
    ia_count_by_campaign = {
        row['campaign_id']: int(row.get('initial_access_technique_count', 0))
        for row in initial_access_results.get('campaign_rows', [])
    }
    ia_flag_by_campaign = {
        row['campaign_id']: int(bool(row.get('has_initial_access', False)))
        for row in initial_access_results.get('campaign_rows', [])
    }
    t2_by_campaign = {
        row['campaign_id']: int(bool(row.get('tier_t2_reference_enriched', False)))
        for row in profile_completeness.get('rows', [])
    }

    campaign_ids = sorted(sw_by_campaign.keys())
    sw_counts = [sw_by_campaign.get(cid, 0) for cid in campaign_ids]
    cve_counts = [cve_by_campaign.get(cid, 0) for cid in campaign_ids]
    ia_counts = [ia_count_by_campaign.get(cid, 0) for cid in campaign_ids]
    ia_flags = [ia_flag_by_campaign.get(cid, 0) for cid in campaign_ids]
    cve_flags = [1 if cve_by_campaign.get(cid, 0) > 0 else 0 for cid in campaign_ids]

    cve_pos_sw = [sw_by_campaign.get(cid, 0) for cid in campaign_ids if cve_by_campaign.get(cid, 0) > 0]
    cve_neg_sw = [sw_by_campaign.get(cid, 0) for cid in campaign_ids if cve_by_campaign.get(cid, 0) == 0]

    t2_and_cve = sum(
        1 for cid in campaign_ids
        if t2_by_campaign.get(cid, 0) == 1 and cve_by_campaign.get(cid, 0) > 0
    )
    t2_without_cve = sum(
        1 for cid in campaign_ids
        if t2_by_campaign.get(cid, 0) == 1 and cve_by_campaign.get(cid, 0) == 0
    )
    cve_without_t2 = sum(
        1 for cid in campaign_ids
        if t2_by_campaign.get(cid, 0) == 0 and cve_by_campaign.get(cid, 0) > 0
    )

    corr_rows = [
        {
            'metric': 'campaign_count',
            'value': len(campaign_ids),
            'note': 'Usable Enterprise campaigns after exclusions.',
        },
        {
            'metric': 'campaigns_with_cve_count',
            'value': sum(cve_flags),
            'note': 'Campaigns with at least one actionable CVE.',
        },
        {
            'metric': 'pearson_sw_count_vs_cve_count',
            'value': round(_pearson_corr(sw_counts, cve_counts), 4),
            'note': 'Linear association between linked software count and campaign CVE count.',
        },
        {
            'metric': 'spearman_sw_count_vs_cve_count',
            'value': round(_spearman_corr(sw_counts, cve_counts), 4),
            'note': 'Rank association between linked software count and campaign CVE count.',
        },
        {
            'metric': 'pearson_initial_access_count_vs_cve_count',
            'value': round(_pearson_corr(ia_counts, cve_counts), 4),
            'note': 'Linear association between IA-technique count and campaign CVE count.',
        },
        {
            'metric': 'spearman_initial_access_count_vs_cve_count',
            'value': round(_spearman_corr(ia_counts, cve_counts), 4),
            'note': 'Rank association between IA-technique count and campaign CVE count.',
        },
        {
            'metric': 'point_biserial_has_initial_access_vs_has_cve',
            'value': round(_pearson_corr(ia_flags, cve_flags), 4),
            'note': 'Binary association proxy: has-initial-access vs has-CVE.',
        },
        {
            'metric': 'mean_software_count_cve_positive_campaigns',
            'value': round(_mean(cve_pos_sw), 3),
            'note': 'Average linked software count among CVE-positive campaigns.',
        },
        {
            'metric': 'mean_software_count_cve_negative_campaigns',
            'value': round(_mean(cve_neg_sw), 3),
            'note': 'Average linked software count among CVE-negative campaigns.',
        },
        {
            'metric': 'median_software_count_cve_positive_campaigns',
            'value': round(_median(cve_pos_sw), 3),
            'note': 'Median linked software count among CVE-positive campaigns.',
        },
        {
            'metric': 'median_software_count_cve_negative_campaigns',
            'value': round(_median(cve_neg_sw), 3),
            'note': 'Median linked software count among CVE-negative campaigns.',
        },
        {
            'metric': 'tier_t2_and_cve_count',
            'value': t2_and_cve,
            'note': 'Campaigns that are T2 anchored and also have campaign CVE evidence.',
        },
        {
            'metric': 'tier_t2_without_cve_count',
            'value': t2_without_cve,
            'note': 'T2 campaigns anchored only by software precision (version/CPE) without campaign CVE.',
        },
        {
            'metric': 'cve_without_tier_t2_count',
            'value': cve_without_t2,
            'note': 'Campaigns with CVE evidence that still fail T2 anchor criteria.',
        },
    ]

    platform_rows = software_results.get('campaign_platform_details', [])
    with_platform_signal = [r for r in platform_rows if bool(r.get('platform_signal', False))]
    with_os_signal = [r for r in with_platform_signal if r.get('os_families')]
    unknown_platform = [r for r in platform_rows if not bool(r.get('platform_signal', False))]

    os_single = sum(1 for r in with_os_signal if len(r.get('os_families', [])) == 1)
    os_dual = sum(1 for r in with_os_signal if len(r.get('os_families', [])) == 2)
    os_triple = sum(1 for r in with_os_signal if len(r.get('os_families', [])) >= 3)

    # Platform-inference ablation: software-only versus software-plus-technique.
    ablation_technique_unknown = sum(
        1 for r in platform_rows if not r.get('combined_platform_signal', False))
    ablation_technique_single_os = sum(
        1 for r in platform_rows if len(r.get('combined_os_families', [])) == 1)
    ablation_technique_triple_os = sum(
        1 for r in platform_rows if len(r.get('combined_os_families', [])) >= 3)

    one_sw_with_os = [r for r in with_os_signal if int(r.get('software_count', 0)) == 1]
    one_sw_single = sum(1 for r in one_sw_with_os if len(r.get('os_families', [])) == 1)
    one_sw_triple = sum(1 for r in one_sw_with_os if len(r.get('os_families', [])) >= 3)

    non_os_only = [
        r for r in with_platform_signal
        if not r.get('os_families') and r.get('non_os_platforms')
    ]

    platform_quality_rows = [
        {
            'metric': 'campaigns_with_platform_signal_count',
            'value': len(with_platform_signal),
            'note': 'Campaigns with at least one software-derived platform tag.',
        },
        {
            'metric': 'campaigns_unknown_platform_count',
            'value': len(unknown_platform),
            'note': 'Campaigns with no software-derived platform signal.',
        },
        {
            'metric': 'campaigns_with_os_family_signal_count',
            'value': len(with_os_signal),
            'note': 'Campaigns with OS-family (Windows/Linux/macOS) signal.',
        },
        {
            'metric': 'campaigns_with_single_os_family_count',
            'value': os_single,
            'note': 'Campaigns with exactly one inferred OS family.',
        },
        {
            'metric': 'campaigns_with_dual_os_family_count',
            'value': os_dual,
            'note': 'Campaigns with two inferred OS families.',
        },
        {
            'metric': 'campaigns_with_triple_os_family_count',
            'value': os_triple,
            'note': 'Campaigns with Linux+Windows+macOS inferred families.',
        },
        {
            'metric': 'platform_ablation_technique_unknown_count',
            'value': ablation_technique_unknown,
            'note': 'Campaigns still platform-unknown when technique-level tags are admitted with software tags.',
        },
        {
            'metric': 'platform_ablation_technique_single_os_count',
            'value': ablation_technique_single_os,
            'note': 'Campaigns with a single inferred OS family under software-plus-technique tags.',
        },
        {
            'metric': 'platform_ablation_technique_triple_os_count',
            'value': ablation_technique_triple_os,
            'note': 'Campaigns with Linux+Windows+macOS under software-plus-technique tags.',
        },
        {
            'metric': 'one_software_campaigns_with_os_signal_count',
            'value': len(one_sw_with_os),
            'note': 'Campaigns whose platform inference is driven by exactly one linked software item.',
        },
        {
            'metric': 'one_software_campaigns_single_os_count',
            'value': one_sw_single,
            'note': 'One-software campaigns with single-OS inference.',
        },
        {
            'metric': 'one_software_campaigns_triple_os_count',
            'value': one_sw_triple,
            'note': 'One-software campaigns with Linux+Windows+macOS inference.',
        },
        {
            'metric': 'campaigns_with_non_os_only_platform_signal_count',
            'value': len(non_os_only),
            'note': 'Campaigns where platform evidence is only non-OS tags (e.g., Network Devices).',
        },
    ]

    return {
        'correlation_rows': corr_rows,
        'platform_quality_rows': platform_quality_rows,
    }


# ─────────────────────────────────────────────────────────────────
# 7. Cross-domain coverage (for Figure 1)
# ─────────────────────────────────────────────────────────────────

def analyze_cross_domain_coverage(file_by_domain):
    """
    Compute measured coverage for all local bundles.
    """
    results = {}
    for key, meta in file_by_domain.items():
        path = meta['path']
        name = meta['name']
        if path.exists():
            if meta.get('schema') == 'fight-native-yaml':
                results[key] = analyze_fight_snapshot(path, name)
            else:
                results[key] = analyze_domain_bundle(path, name)
        else:
            print(f"[WARN] {name} bundle not found at {path}")
    return results


# ─────────────────────────────────────────────────────────────────
# 8. Software coverage for cross-domain figure
# ─────────────────────────────────────────────────────────────────

def compute_software_link_rate(objects_by_type, rel_fwd, rel_rev):
    """Fraction of attack-patterns linked to at least one malware/tool."""
    techniques = objects_by_type.get('attack-pattern', [])
    software_ids = set()
    for s in objects_by_type.get('malware', []):
        software_ids.add(s['id'])
    for s in objects_by_type.get('tool', []):
        software_ids.add(s['id'])

    linked = 0
    for tech in techniques:
        for rtype, tgt, _ in rel_fwd.get(tech['id'], []):
            if rtype == 'uses' and tgt in software_ids:
                linked += 1
                break
        else:
            # ATT&CK and FiGHT commonly encode software -> uses -> technique.
            for rtype, src, _ in rel_rev.get(tech['id'], []):
                if rtype == 'uses' and src in software_ids:
                    linked += 1
                    break
    return pct(linked, len(techniques)) if techniques else 0.0


def compute_cve_link_rate_for_techniques(techniques):
    """Fraction of techniques with at least one CVE mention."""
    with_cve = 0
    for tech in techniques:
        s, f = extract_cves_from_object(tech)
        if s or f:
            with_cve += 1
    return pct(with_cve, len(techniques)) if techniques else 0.0


# ─────────────────────────────────────────────────────────────────
# Main Pipeline
# ─────────────────────────────────────────────────────────────────

def main():
    print("=" * 70)
    print("SUT Measurement Pipeline")
    print("=" * 70)

    # Create output directories
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    AUDIT_DIR.mkdir(parents=True, exist_ok=True)

    # ── Load Enterprise bundle ──
    print("\n[1/7] Loading Enterprise STIX bundle...")
    all_objects = load_bundle(ENTERPRISE_FILE)
    by_type, by_id = index_objects_by_type(all_objects)
    relationships = by_type.get('relationship', [])
    rel_fwd, rel_rev, rel_by_type = build_relationship_index(relationships)

    techniques = by_type.get('attack-pattern', [])
    campaigns = by_type.get('campaign', [])
    intrusion_sets = by_type.get('intrusion-set', [])
    malware = by_type.get('malware', [])
    tools = by_type.get('tool', [])
    software_objects = malware + tools
    vulnerability_objects = by_type.get('vulnerability', [])

    print(f"  Techniques: {len(techniques)}")
    print(f"  Campaigns: {len(campaigns)}")
    print(f"  Intrusion sets: {len(intrusion_sets)}")
    print(f"  Malware: {len(malware)}")
    print(f"  Tools: {len(tools)}")
    print(f"  Vulnerability objects: {len(vulnerability_objects)}")
    print(f"  Relationships: {len(relationships)}")

    # Identify excluded campaigns (no 'uses' relationships)
    excluded_campaign_ids = set()
    for camp in campaigns:
        has_uses = False
        for rtype, _, _ in rel_fwd.get(camp['id'], []):
            if rtype == 'uses':
                has_uses = True
                break
        if not has_uses:
            excluded_campaign_ids.add(camp['id'])
            print(f"  [EXCLUDED] Campaign '{camp.get('name', '')}' ({camp['id']}) - no 'uses' relationships")

    # ── Platform Coverage ──
    print("\n[2/7] Analyzing platform coverage (RQ1)...")
    platform_results = analyze_platform_coverage(techniques)
    print(f"  Platform coverage: {platform_results['with_platform']}/{platform_results['total_techniques']} "
          f"({platform_results['platform_pct']}%)")
    print(f"  System requirements: {platform_results['with_system_requirements']}/{platform_results['total_techniques']} "
          f"({platform_results['system_requirements_pct']}%)")

    # ── Software References ──
    print("\n[3/7] Analyzing software references (RQ1/RQ2)...")
    software_results = analyze_software_references(
        campaigns, intrusion_sets, software_objects,
        rel_fwd, rel_rev, by_id, excluded_campaign_ids
    )
    print(f"  Campaigns with software: {software_results['campaigns_with_software']}/{software_results['total_usable_campaigns']} "
          f"({software_results['campaigns_with_software_pct']}%)")
    print(f"  Campaigns with software-derived platform signal: {software_results['campaigns_with_platform_signal']}/{software_results['total_usable_campaigns']} "
          f"({software_results['campaigns_with_platform_signal_pct']}%)")
    print(f"  Campaigns with unknown platform (software-only rule): {software_results['campaigns_unknown_platform']}/{software_results['total_usable_campaigns']} "
          f"({software_results['campaigns_unknown_platform_pct']}%)")
    print(f"  Unknown-platform campaigns: {software_results['campaign_unknown_platform_names']}")
    print(f"  IS with software: {software_results['is_with_software']}/{software_results['total_intrusion_sets']} "
          f"({software_results['is_with_software_pct']}%)")
    print(f"  Software with version signal: {software_results['software_with_version']}/{software_results['total_software']} "
          f"({software_results['software_with_version_pct']}%)")
    print(f"  Software with CPE: {software_results['software_with_cpe']}/{software_results['total_software']} "
          f"({software_results['software_with_cpe_pct']}%)")

    # ── Software Version Enrichment from Descriptions ──
    print("\n[3b/7] Analyzing software version enrichment from descriptions...")
    version_enrichment = analyze_software_version_enrichment(software_objects)
    print(f"  Baseline version signal: {version_enrichment['baseline_has_version']}/{version_enrichment['total_software']} "
          f"({version_enrichment['baseline_has_version_pct']}%)")
    print(f"  Description-enriched gains: +{version_enrichment['desc_enriched_count']} software objects "
          f"({version_enrichment['desc_enriched_pct']}%)")
    print(f"  Enriched total: {version_enrichment['enriched_total']}/{version_enrichment['total_software']} "
          f"({version_enrichment['enriched_total_pct']}%), gain +{version_enrichment['gain_pp']} pp")
    print(f"  Remaining without version (post-enrichment): {version_enrichment['enriched_no_version']}/{version_enrichment['total_software']} "
          f"({version_enrichment['enriched_no_version_pct']}%)")
    if version_enrichment['enriched_examples']:
        print(f"  Examples: {', '.join(e['name'] + ' (' + e['matched_version'] + ')' for e in version_enrichment['enriched_examples'][:5])}")

    # ── Vulnerability References ──
    print("\n[4/7] Analyzing vulnerability references (RQ1/RQ2)...")
    cve_results = analyze_vulnerability_references(
        campaigns, intrusion_sets, software_objects,
        techniques, vulnerability_objects,
        rel_fwd, rel_rev, by_id, excluded_campaign_ids
    )
    print(f"  Unique CVEs (all sources): {cve_results['cve_unique_count']}")
    print(f"  Structured CVEs: {cve_results['cve_structured_count']}")
    print(f"  Free-text only CVEs: {cve_results['cve_freetext_only_count']}")
    print(f"  CVE from free text: {cve_results['cve_from_freetext_pct']}%")
    print(
        "  Environment-associated CVEs (software/campaign/IS): "
        f"{cve_results['actionable_cve_count']}"
    )
    print(f"  Technique-example-only CVEs: {cve_results['technique_only_cve_count']}")
    print(f"  CVEs from techniques (examples): {cve_results['cves_from_techniques']}")
    print(f"  CVEs from software: {cve_results['cves_from_software']}")
    print(f"  CVEs from campaigns: {cve_results['cves_from_campaigns']}")
    print(f"  CVEs from intrusion sets: {cve_results['cves_from_is']}")
    print(
        "  Campaign CVE coverage (structured-only -> enriched): "
        f"{cve_results['campaigns_with_cve_structured']}/{software_results['total_usable_campaigns']} "
        f"({cve_results['campaigns_with_cve_structured_pct']}%) -> "
        f"{cve_results['campaigns_with_cve']}/{software_results['total_usable_campaigns']} "
        f"({cve_results['campaigns_with_cve_pct']}%), "
        f"gain +{cve_results['campaigns_with_cve_enrichment_gain']} "
        f"(+{cve_results['campaigns_with_cve_enrichment_gain_pp']} pp)"
    )
    print(
        "  Intrusion-set CVE coverage (structured-only -> enriched): "
        f"{cve_results['is_with_cve_structured']}/{software_results['total_intrusion_sets']} "
        f"({cve_results['is_with_cve_structured_pct']}%) -> "
        f"{cve_results['is_with_cve']}/{software_results['total_intrusion_sets']} "
        f"({cve_results['is_with_cve_pct']}%), "
        f"gain +{cve_results['is_with_cve_enrichment_gain']} "
        f"(+{cve_results['is_with_cve_enrichment_gain_pp']} pp)"
    )
    print(f"  Campaigns with CVE: {cve_results['campaigns_with_cve']}/{software_results['total_usable_campaigns']} "
          f"({cve_results['campaigns_with_cve_pct']}%)")
    print(f"  IS with CVE: {cve_results['is_with_cve']}/{software_results['total_intrusion_sets']} "
          f"({cve_results['is_with_cve_pct']}%)")

    # ── CVE NVD-format validation ──
    print("\n[4b/7] Validating CVE IDs against NVD format...")
    cve_validation = validate_cve_ids(set(cve_results['all_cves']))
    print(f"  Valid: {cve_validation['valid_count']}/{cve_validation['total']}")
    if cve_validation['flagged']:
        print(f"  Flagged: {cve_validation['flagged_count']}")
        for f_cve in cve_validation['flagged']:
            print(f"    {f_cve['cve_id']}: {f_cve['reason']} - {f_cve['detail']}")
    else:
        print("  All CVE IDs pass NVD format validation.")
    # Export validation audit CSV
    with open(AUDIT_DIR / 'cve_validation.csv', 'w', newline='') as f:
        writer = lf_dict_writer(f, fieldnames=['cve_id', 'status', 'reason', 'detail'])
        writer.writeheader()
        for v in cve_validation['valid']:
            writer.writerow({
                'cve_id': v['cve_id'], 'status': 'valid',
                'reason': '', 'detail': f"Year={v['year']}, Digits={v['seq_digits']}"
            })
        for fl in cve_validation['flagged']:
            writer.writerow({
                'cve_id': fl['cve_id'], 'status': 'flagged',
                'reason': fl['reason'], 'detail': fl['detail']
            })
    print(f"  OK CVE validation audit saved to {AUDIT_DIR / 'cve_validation.csv'}")

    # ── Campaign-level profile completeness ──
    profile_completeness = analyze_campaign_profile_completeness(
        software_results, cve_results
    )
    profile_population_count = validate_campaign_profile_population(
        campaigns, excluded_campaign_ids, profile_completeness
    )
    print("  Campaign SUT profile completeness tiers:")
    print(f"    T1 (coarse: software+platform): {profile_completeness['tier_t1_count']}/{profile_completeness['total_campaigns']} "
          f"({profile_completeness['tier_t1_pct']}%)")
    print(f"    T2 (reference-enriched: T1 + version/CPE reference or campaign CVE): {profile_completeness['tier_t2_count']}/{profile_completeness['total_campaigns']} "
          f"({profile_completeness['tier_t2_pct']}%)")
    print(f"    T3 (CVE-associated: T1 + campaign CVE): {profile_completeness['tier_t3_count']}/{profile_completeness['total_campaigns']} "
          f"({profile_completeness['tier_t3_pct']}%)")

    # ── Campaign Factual Structure (inNervoso consolidation) ──
    print("\n[4c/7] Analyzing campaign factual structure...")
    # Build tactic objects index for get_technique_tactics()
    tactic_objects = [o for o in all_objects if o.get('type') == 'x-mitre-tactic']
    campaign_factual = analyze_campaign_factual_structure(
        campaigns, techniques, rel_fwd, rel_rev, by_id, tactic_objects,
        excluded_campaign_ids, enterprise_tactic_order(all_objects)
    )
    print(f"  Mean techniques/campaign: {campaign_factual['campaign_mean_technique_count']}")
    print(f"  Mean tactic coverage/campaign: {campaign_factual['campaign_mean_tactic_coverage']}")
    print(f"  Campaigns with ≥5 tactics (complete kill-chain): "
          f"{campaign_factual['campaigns_complete_killchain']}/{campaign_factual['total_campaigns']} "
          f"({campaign_factual['campaign_complete_killchain_pct']}%)")
    print(f"  Campaigns with both IA and exfiltration: "
          f"{campaign_factual['campaigns_with_ia_and_exfil']}/{campaign_factual['total_campaigns']} "
          f"({campaign_factual['campaign_with_ia_and_exfil_pct']}%)")

    # ── Environment Inference + IEIR ──
    print("\n[4d/7] Inferring campaign environments (IEIR)...")
    software_objects_list = by_type.get('tool', []) + by_type.get('malware', [])
    env_inference = infer_campaign_environment(
        campaign_factual['rows'], software_objects_list, by_id, rel_fwd, rel_rev
    )
    print(f"  Campaigns with campaign-specific signal: {env_inference['campaign_specific_count']}/{env_inference['total_campaigns']} "
          f"({env_inference['campaign_specific_pct']}%)")
    print(f"  IEIR (implicit-only): {env_inference['ieir_count']}/{env_inference['total_campaigns']} "
          f"({env_inference['ieir_pct']}%)")
    print(f"  Confidence: high={env_inference['environment_high_confidence_pct']}%, "
          f"medium={env_inference['environment_medium_pct']}%, "
          f"low={env_inference['environment_low_pct']}%, "
          f"none={env_inference['environment_none_pct']}%")
    print(f"  Signal sources: {env_inference['signal_type_breakdown']}")

    # ── Evidence Convergence ──
    print("\n[4e/7] Analyzing evidence convergence...")
    evidence_convergence = analyze_evidence_convergence(
        campaign_factual['rows'], env_inference['rows']
    )
    print(
        "  Assessable convergence (>=2 signals): "
        f"{evidence_convergence['assessable_convergence_count']}/"
        f"{evidence_convergence['assessable_campaign_count']} "
        f"({evidence_convergence['assessable_convergence_rate_pct']}%)"
    )
    print(
        "  Assessable divergence: "
        f"{evidence_convergence['assessable_divergence_count']}"
    )
    print(f"  Mean signal count/campaign: {evidence_convergence['evidence_mean_signal_count']}")

    # ── Initial Access analysis ──
    print("\n[5/7] Analyzing Initial Access signals...")
    initial_access_results = analyze_initial_access(
        campaigns, techniques, rel_fwd, cve_results, excluded_campaign_ids
    )
    print(f"  Initial Access techniques: {initial_access_results['initial_access_technique_count']}")
    print(f"  Campaigns with Initial Access: {initial_access_results['campaigns_with_initial_access_count']}/{software_results['total_usable_campaigns']} "
          f"({initial_access_results['campaigns_with_initial_access_pct']}%)")
    print(f"  Campaigns with social-interaction IA proxy: {initial_access_results['campaigns_with_social_initial_access_count']}/{software_results['total_usable_campaigns']} "
          f"({initial_access_results['campaigns_with_social_initial_access_pct']}%)")
    print(f"  Campaigns with IA and CVE evidence: {initial_access_results['campaigns_with_initial_access_and_cve_count']}/{software_results['total_usable_campaigns']} "
          f"({initial_access_results['campaigns_with_initial_access_and_cve_pct']}%)")
    print(f"  Campaigns with IA and no CVE evidence: {initial_access_results['campaigns_with_initial_access_no_cve_count']}/{software_results['total_usable_campaigns']} "
          f"({initial_access_results['campaigns_with_initial_access_no_cve_pct']}%)")

    # ── Compatibility Classification ──
    print("\n[6/7] Applying compatibility routing policy (RQ2)...")
    compat_results = analyze_compatibility(techniques, rel_fwd, by_id)
    print(f"  CF: {compat_results['cf_count']} ({compat_results['cf_pct']}%)")
    print(f"  VMR: {compat_results['vmr_count']} ({compat_results['vmr_pct']}%)")
    print(f"  ID: {compat_results['id_count']} ({compat_results['id_pct']}%)")
    print(f"  Total: {compat_results['cf_count'] + compat_results['vmr_count'] + compat_results['id_count']}")
    print(
        f"  Explicit-rule assignments: {compat_results['explicit_count']}/{compat_results['total']} "
        f"({compat_results['explicit_pct']}%), fallback assignments: "
        f"{compat_results['fallback_count']}/{compat_results['total']} ({compat_results['fallback_pct']}%)"
    )
    compatibility_rule_breakdown = build_compatibility_rule_breakdown(compat_results)
    compatibility_by_tactic = build_compatibility_by_tactic(compat_results)
    compatibility_validation_sample = build_compatibility_validation_sample(
        compat_results, n_per_class=12, seed=42
    )
    compatibility_validation_sample = merge_compatibility_manual_annotations(
        compatibility_validation_sample,
        AUDIT_DIR / 'compatibility_validation_sample.csv',
    )
    manual_labels_completed = sum(
        1
        for row in compatibility_validation_sample
        if str(row.get('manual_expected_class', '')).strip().upper()
        in COMPATIBILITY_POLICY_LABELS
    )
    compatibility_denominator_summary = build_compatibility_denominator_summary(
        compat_results,
        manual_sample_size=len(compatibility_validation_sample),
        manual_labels_completed=manual_labels_completed,
    )
    print(
        "  Compatibility validation sample prepared: "
        f"{len(compatibility_validation_sample)} techniques "
        f"(stratified by policy label and rule ID; "
        f"{manual_labels_completed}/{len(compatibility_validation_sample)} "
        "manual labels complete)."
    )
    compatibility_sensitivity = analyze_compatibility_default_sensitivity(
        techniques, rel_fwd, by_id
    )
    non_cf_values = [
        row['non_cf_pct']
        for row in compatibility_sensitivity
        if row['default_class'] in {'CF', 'VMR', 'ID'}
    ]
    unresolved_scenario = next(
        row for row in compatibility_sensitivity if row['default_class'] == 'UNRESOLVED'
    )
    print("  Compatibility default sensitivity (non-CF share):")
    for row in compatibility_sensitivity:
        print(
            f"    default={row['default_class']}: overall non-CF={row['non_cf_pct']}%, "
            f"explicit-only non-CF={row['explicit_non_cf_explicit_only_pct']}%, "
            f"unresolved={row['unresolved_pct']}% "
            f"(CF={row['cf_pct']}%, VMR={row['vmr_pct']}%, ID={row['id_pct']}%)"
        )
    compatibility_by_technique = {}
    for cls_name, cls_list in compat_results['details'].items():
        for tech in cls_list:
            compatibility_by_technique[tech['id']] = cls_name

    # ── Profile Specificity ──
    print("\n[7/7] Computing SUT profile specificity (RQ3)...")
    specificity_results = analyze_profile_specificity(
        intrusion_sets, software_objects, rel_fwd, by_id, compatibility_by_technique
    )
    sw_only = specificity_results['software_only']
    sw_cve = specificity_results['software_cve']
    sw_platform = specificity_results['software_platform']
    sw_cve_platform = specificity_results['software_cve_platform']
    sw_family_only = specificity_results['software_family_only']
    sw_compat = specificity_results['software_compat']
    print(f"  Software-only unique profiles: {sw_only['unique_count']}/{sw_only['total_is']} "
          f"({sw_only['unique_pct']}%)")
    print(f"  Software+CVE unique profiles: {sw_cve['unique_count']}/{sw_cve['total_is']} "
          f"({sw_cve['unique_pct']}%)")
    print(f"  Software+CVE confused: {sw_cve['confused_count']}/{sw_cve['total_is']} "
          f"({sw_cve['confused_pct']}%)")
    print(f"  Software+platform unique profiles: {sw_platform['unique_count']}/{sw_platform['total_is']} "
          f"({sw_platform['unique_pct']}%)")
    print(f"  Software+platform confused: {sw_platform['confused_count']}/{sw_platform['total_is']} "
          f"({sw_platform['confused_pct']}%)")
    print(f"  Software+CVE+platform unique profiles: {sw_cve_platform['unique_count']}/{sw_cve_platform['total_is']} "
          f"({sw_cve_platform['unique_pct']}%)")
    print(f"  Software+CVE+platform confused: {sw_cve_platform['confused_count']}/{sw_cve_platform['total_is']} "
          f"({sw_cve_platform['confused_pct']}%)")
    print(f"  Software+OS-family unique profiles: {sw_family_only['unique_count']}/{sw_family_only['total_is']} "
          f"({sw_family_only['unique_pct']}%)")
    print(f"  Software+OS-family confused: {sw_family_only['confused_count']}/{sw_family_only['total_is']} "
          f"({sw_family_only['confused_pct']}%)")
    print(f"  Software+compat unique profiles: {sw_compat['unique_count']}/{sw_compat['total_is']} "
          f"({sw_compat['unique_pct']}%)")
    print(f"  Software+compat confused: {sw_compat['confused_count']}/{sw_compat['total_is']} "
          f"({sw_compat['confused_pct']}%)")

    software_only_profiles, _ = build_sut_profiles(
        intrusion_sets,
        software_objects,
        rel_fwd,
        by_id,
        include_cve=False,
        platform_mode='none',
    )
    threshold_results = analyze_min_evidence_threshold_profiles(
        software_only_profiles,
        JACCARD_DELTA,
    )
    delta_sensitivity = analyze_delta_sensitivity(
        specificity_results['software_only']['per_is_rows'],
        [0.05, 0.10, 0.15, 0.20, 0.30],
    )
    bootstrap_results = bootstrap_confusion_ci(
        specificity_results['software_only']['per_is_rows'],
        JACCARD_DELTA,
        n_boot=5000,
        seed=42,
    )
    null_model_results = analyze_sparsity_null_model(
        intrusion_sets, software_objects, rel_fwd, by_id,
        delta=JACCARD_DELTA,
        n_iter=1000,
        seed=42,
    )
    degree_null_results = analyze_degree_preserving_threshold_sensitivity(
        software_only_profiles,
        delta=JACCARD_DELTA,
        lower_k=1,
        upper_k=2,
        n_iter=1000,
        seed=43,
    )
    threshold_influence = analyze_threshold_collapse_leave_one_out(
        software_only_profiles,
        delta=JACCARD_DELTA,
        lower_k=1,
        upper_k=2,
    )
    print("  Confusion by minimum software count:")
    print(f"    k>=1: {threshold_results['k1_confusion_pct']}%")
    print(f"    k>=2: {threshold_results['k2_confusion_pct']}% (n={threshold_results['k2_sample']})")
    print(f"    k>=3: {threshold_results['k3_confusion_pct']}% (n={threshold_results['k3_sample']})")
    print(f"    k>=5: {threshold_results['k5_confusion_pct']}% (n={threshold_results['k5_sample']})")
    print("  Delta sensitivity (software-only):")
    for row in delta_sensitivity:
        print(f"    delta={row['delta']:.2f}: {row['confusion_pct']}% (n={row['sample_size']})")
    print(
        "  Fixed-indicator resampling (descriptive; delta=0.10): "
        f"confusion {bootstrap_results['confusion_pct']}% "
        f"[{bootstrap_results['confusion_ci_low']}, {bootstrap_results['confusion_ci_high']}]"
    )
    print(
        "  Legacy all-profile null diagnostic (cardinality-preserving): "
        f"mean confusion {null_model_results['null_confusion_mean_pct']}% "
        f"[p05={null_model_results['null_confusion_p05_pct']}%, "
        f"p95={null_model_results['null_confusion_p95_pct']}%], "
        f"observed={null_model_results['observed_confusion_pct']}%, "
        f"p-value={null_model_results['p_value']}"
    )
    print(
        "  Direct threshold-collapse null (row cardinalities fixed): "
        f"observed drop={null_model_results['observed_collapse_pp']} pp, "
        f"null mean={null_model_results['null_collapse_mean_pp']} pp "
        f"[p05={null_model_results['null_collapse_p05_pp']} pp, "
        f"p95={null_model_results['null_collapse_p95_pp']} pp], "
        f"upper-tail Monte Carlo p={null_model_results['collapse_p_value']} "
        f"(MC SE={null_model_results['collapse_p_value_mc_se']})"
    )
    print(
        "  Degree-preserving threshold sensitivity: "
        f"null mean={degree_null_results['null_collapse_mean_pp']} pp "
        f"[p05={degree_null_results['null_collapse_p05_pp']} pp, "
        f"p95={degree_null_results['null_collapse_p95_pp']} pp], "
        f"upper-tail Monte Carlo p={degree_null_results['collapse_p_value']} "
        f"(MC SE={degree_null_results['collapse_p_value_mc_se']})"
    )
    print(
        "  Leave-one-out threshold influence: "
        f"{threshold_influence['influential_profile_count']}/"
        f"{threshold_influence['profile_count']} profiles change the statistic; "
        f"range={threshold_influence['minimum_leave_one_out_collapse_pp']}--"
        f"{threshold_influence['maximum_leave_one_out_collapse_pp']} pp"
    )
    behavior_specificity = analyze_technique_profile_specificity(
        intrusion_sets, techniques, rel_fwd, rel_rev, delta=JACCARD_DELTA
    )
    print(
        "  Exploratory behavior-profile confusion (technique-only): "
        f"{behavior_specificity['confused_count']}/{behavior_specificity['total_is']} "
        f"({behavior_specificity['confused_pct']}%) at delta={JACCARD_DELTA}"
    )
    print(
        "  Exploratory behavior-profile thresholds: "
        f"k>=1 {behavior_specificity['threshold']['k1_confusion_pct']}%, "
        f"k>=2 {behavior_specificity['threshold']['k2_confusion_pct']}%, "
        f"k>=3 {behavior_specificity['threshold']['k3_confusion_pct']}%"
    )
    serendipity_results = analyze_campaign_serendipity(
        software_results, cve_results, initial_access_results, profile_completeness
    )
    corr_lookup = {
        row['metric']: row['value']
        for row in serendipity_results['correlation_rows']
    }
    platform_lookup = {
        row['metric']: row['value']
        for row in serendipity_results['platform_quality_rows']
    }
    print("  Exploratory campaign-level associations:")
    print(
        "    corr(sw_count, cve_count): "
        f"pearson={corr_lookup.get('pearson_sw_count_vs_cve_count', 0)}, "
        f"spearman={corr_lookup.get('spearman_sw_count_vs_cve_count', 0)}"
    )
    print(
        "    corr(initial_access_count, cve_count): "
        f"pearson={corr_lookup.get('pearson_initial_access_count_vs_cve_count', 0)}, "
        f"spearman={corr_lookup.get('spearman_initial_access_count_vs_cve_count', 0)}"
    )
    print(
        "    corr(has_initial_access, has_cve): "
        f"{corr_lookup.get('point_biserial_has_initial_access_vs_has_cve', 0)}"
    )
    print("  Platform-inference quality (software-only campaign signal):")
    print(
        f"    with_os_signal={platform_lookup.get('campaigns_with_os_family_signal_count', 0)}, "
        f"single={platform_lookup.get('campaigns_with_single_os_family_count', 0)}, "
        f"dual={platform_lookup.get('campaigns_with_dual_os_family_count', 0)}, "
        f"triple={platform_lookup.get('campaigns_with_triple_os_family_count', 0)}"
    )
    print(
        "    one-software campaigns: "
        f"single_os={platform_lookup.get('one_software_campaigns_single_os_count', 0)}, "
        f"triple_os={platform_lookup.get('one_software_campaigns_triple_os_count', 0)}"
    )

    # ── Cross-domain coverage ──
    print("\n[8/8] Computing cross-domain coverage...")
    cross_domain = analyze_cross_domain_coverage({
        'enterprise': {'name': 'Enterprise', 'path': ENTERPRISE_FILE},
        'mobile': {'name': 'Mobile', 'path': MOBILE_FILE},
        'ics': {'name': 'ICS', 'path': ICS_FILE},
        'capec': {'name': 'CAPEC', 'path': CAPEC_FILE},
        'fight': {
            'name': 'FiGHT',
            'path': FIGHT_FILE,
            'schema': 'fight-native-yaml',
        },
    })
    for domain, data in cross_domain.items():
        print(
            f"  {data.get('domain', domain)}: "
            f"platform={data.get('platform_pct', 'N/A')}%, "
            f"software-link={data.get('software_link_pct', 'N/A')}%, "
            f"CVE-link={data.get('cve_link_pct', 'N/A')}%"
        )

    # ==============================================================
    # Assemble TODO values
    # ==============================================================
    raw_attack_patterns = [
        obj for obj in all_objects if obj.get('type') == 'attack-pattern'
    ]
    raw_intrusion_sets = [
        obj for obj in all_objects if obj.get('type') == 'intrusion-set'
    ]
    raw_malware = [obj for obj in all_objects if obj.get('type') == 'malware']
    raw_tools = [obj for obj in all_objects if obj.get('type') == 'tool']
    raw_relationships = [
        obj for obj in all_objects if obj.get('type') == 'relationship'
    ]
    active_relationship_count = count_relationships_with_active_endpoints(
        raw_relationships, by_id
    )
    raw_tactics = [obj for obj in all_objects if obj.get('type') == 'x-mitre-tactic']
    deprecated_attack_patterns = [
        obj for obj in raw_attack_patterns if is_deprecated_or_revoked(obj)
    ]

    todo_values = {
        # Raw bundle counts used directly in the manuscript dataset framing
        'enterprise_total_attack_pattern_count': len(raw_attack_patterns),
        'enterprise_deprecated_attack_pattern_count': len(deprecated_attack_patterns),
        'enterprise_total_intrusion_set_count': len(raw_intrusion_sets),
        'enterprise_total_malware_count': len(raw_malware),
        'enterprise_total_tool_count': len(raw_tools),
        'enterprise_total_software_count': len(raw_malware) + len(raw_tools),
        'enterprise_total_relationship_count': len(raw_relationships),
        'enterprise_active_relationship_count': active_relationship_count,
        'enterprise_tactic_count': len(raw_tactics),

        # RQ1 Platform
        'enterprise_platform_count': platform_results['with_platform'],
        'enterprise_platform_pct': platform_results['platform_pct'],
        'enterprise_system_requirements_count': platform_results['with_system_requirements'],
        'enterprise_system_requirements_pct': platform_results['system_requirements_pct'],
        'mobile_platform_pct': cross_domain.get('mobile', {}).get('platform_pct', 'N/A'),
        'ics_platform_percentage': cross_domain.get('ics', {}).get('platform_pct', 'N/A'),
        'capec_platform_percentage': cross_domain.get('capec', {}).get('platform_pct', 'N/A'),
        'fight_platform_percentage': cross_domain.get('fight', {}).get('platform_pct', 'N/A'),
        'fight_technique_count': cross_domain.get('fight', {}).get('total_techniques', 'N/A'),
        'fight_campaign_count': cross_domain.get('fight', {}).get('num_campaigns', 'N/A'),
        'fight_group_count': cross_domain.get('fight', {}).get('num_intrusion_sets', 'N/A'),
        'fight_software_count': cross_domain.get('fight', {}).get('num_software', 'N/A'),
        'fight_software_link_percentage': cross_domain.get('fight', {}).get('software_link_pct', 'N/A'),
        'fight_cve_signal_percentage': cross_domain.get('fight', {}).get('cve_link_pct', 'N/A'),
        'enterprise_active_technique_count': cross_domain.get('enterprise', {}).get('total_techniques', 'N/A'),
        'mobile_active_technique_count': cross_domain.get('mobile', {}).get('total_techniques', 'N/A'),
        'ics_active_technique_count': cross_domain.get('ics', {}).get('total_techniques', 'N/A'),
        'capec_active_attack_pattern_count': cross_domain.get('capec', {}).get('total_techniques', 'N/A'),

        # Figure 1 (cross-corpus coverage)
        'enterprise_software_link_pct': cross_domain.get('enterprise', {}).get('software_link_pct', 'N/A'),
        'enterprise_cve_link_pct': cross_domain.get('enterprise', {}).get('cve_link_pct', 'N/A'),
        'mobile_software_link_pct': cross_domain.get('mobile', {}).get('software_link_pct', 'N/A'),
        'mobile_cve_link_pct': cross_domain.get('mobile', {}).get('cve_link_pct', 'N/A'),
        'ics_software_link_pct': cross_domain.get('ics', {}).get('software_link_pct', 'N/A'),
        'ics_cve_link_pct': cross_domain.get('ics', {}).get('cve_link_pct', 'N/A'),
        'capec_software_link_pct': cross_domain.get('capec', {}).get('software_link_pct', 'N/A'),
        'capec_cve_link_pct': cross_domain.get('capec', {}).get('cve_link_pct', 'N/A'),
        'fight_software_link_pct': cross_domain.get('fight', {}).get('software_link_pct', 'N/A'),
        'fight_cve_link_pct': cross_domain.get('fight', {}).get('cve_link_pct', 'N/A'),

        # RQ1/RQ2 Software
        'enterprise_campaigns_with_software_count': software_results['campaigns_with_software'],
        'enterprise_campaigns_with_software_percentage': software_results['campaigns_with_software_pct'],
        'enterprise_campaigns_with_software_ci_low': proportion_ci_wilson(
            software_results['campaigns_with_software'],
            software_results['total_usable_campaigns'],
        )[0],
        'enterprise_campaigns_with_software_ci_high': proportion_ci_wilson(
            software_results['campaigns_with_software'],
            software_results['total_usable_campaigns'],
        )[1],
        'enterprise_active_campaign_count': software_results['total_usable_campaigns'],
        'enterprise_campaigns_with_platform_signal_count': software_results['campaigns_with_platform_signal'],
        'enterprise_campaigns_with_platform_signal_pct': software_results['campaigns_with_platform_signal_pct'],
        'enterprise_campaigns_platform_unknown_count': software_results['campaigns_unknown_platform'],
        'enterprise_campaigns_platform_unknown_pct': software_results['campaigns_unknown_platform_pct'],
        'campaign_os_windows_count': software_results['campaign_os_family_counts'].get('Windows', 0),
        'campaign_os_linux_count': software_results['campaign_os_family_counts'].get('Linux', 0),
        'campaign_os_macos_count': software_results['campaign_os_family_counts'].get('macOS', 0),
        'campaign_os_windows_pct_signal': pct(
            software_results['campaign_os_family_counts'].get('Windows', 0),
            software_results['campaigns_with_platform_signal'],
        ),
        'campaign_os_linux_pct_signal': pct(
            software_results['campaign_os_family_counts'].get('Linux', 0),
            software_results['campaigns_with_platform_signal'],
        ),
        'campaign_os_macos_pct_signal': pct(
            software_results['campaign_os_family_counts'].get('macOS', 0),
            software_results['campaigns_with_platform_signal'],
        ),
        'campaign_os_windows_pct_total': pct(
            software_results['campaign_os_family_counts'].get('Windows', 0),
            software_results['total_usable_campaigns'],
        ),
        'campaign_os_linux_pct_total': pct(
            software_results['campaign_os_family_counts'].get('Linux', 0),
            software_results['total_usable_campaigns'],
        ),
        'campaign_os_macos_pct_total': pct(
            software_results['campaign_os_family_counts'].get('macOS', 0),
            software_results['total_usable_campaigns'],
        ),
        'campaign_sut_tier_coarse_count': profile_completeness['tier_t1_count'],
        'campaign_sut_tier_coarse_pct': profile_completeness['tier_t1_pct'],
        'campaign_sut_tier_reference_enriched_count': profile_completeness['tier_t2_count'],
        'campaign_sut_tier_reference_enriched_pct': profile_completeness['tier_t2_pct'],
        'campaign_sut_tier_cve_associated_count': profile_completeness['tier_t3_count'],
        'campaign_sut_tier_cve_associated_pct': profile_completeness['tier_t3_pct'],
        'enterprise_intrusion_sets_with_software_count': software_results['is_with_software'],
        'enterprise_intrusion_sets_with_software_percentage': software_results['is_with_software_pct'],
        'enterprise_active_intrusion_set_count': software_results['total_intrusion_sets'],
        'enterprise_active_software_count': software_results['total_software'],
        'enterprise_active_malware_count': len(malware),
        'enterprise_active_tool_count': len(tools),
        'software_with_version_signal_count': software_results['software_with_version'],
        'software_with_version_signal_percentage': software_results['software_with_version_pct'],
        'software_with_version_signal_ci_low': proportion_ci_wilson(
            software_results['software_with_version'],
            software_results['total_software'],
        )[0],
        'software_with_version_signal_ci_high': proportion_ci_wilson(
            software_results['software_with_version'],
            software_results['total_software'],
        )[1],
        'software_with_cpe_count': software_results['software_with_cpe'],
        'software_with_cpe_percentage': software_results['software_with_cpe_pct'],
        'software_no_version_no_cpe_count': software_results['software_no_version_no_cpe'],
        'software_no_version_no_cpe_percentage': software_results['software_no_version_no_cpe_pct'],
        # Version enrichment from descriptions
        'software_version_enrichment_gain_count': version_enrichment['desc_enriched_count'],
        'software_version_enrichment_gain_pct': version_enrichment['desc_enriched_pct'],
        'software_version_enriched_total': version_enrichment['enriched_total'],
        'software_version_enriched_total_pct': version_enrichment['enriched_total_pct'],
        'software_version_enrichment_gain_pp': version_enrichment['gain_pp'],
        'software_version_enriched_no_version_pct': version_enrichment['enriched_no_version_pct'],
        'software_version_enriched_no_version_count': (
            software_results['total_software'] - version_enrichment['enriched_total']
        ),

        # RQ1/RQ2 CVE
        'cve_unique_count': cve_results['cve_unique_count'],
        'cve_structured_count': cve_results['cve_structured_count'],
        'cve_freetext_only_count': cve_results['cve_freetext_only_count'],
        'cve_from_freetext_pct': cve_results['cve_from_freetext_pct'],
        'cve_actionable_count': cve_results['actionable_cve_count'],
        'cve_environment_associated_count': cve_results['actionable_cve_count'],
        'cve_environment_associated_percentage': pct(
            cve_results['actionable_cve_count'], cve_results['cve_unique_count']
        ),
        'cve_technique_only_count': cve_results['technique_only_cve_count'],
        'campaign_linked_cve_count': len(cve_results['cves_from_campaigns']),
        'campaign_linked_cve_environment_percentage': pct(
            len(cve_results['cves_from_campaigns']),
            cve_results['actionable_cve_count'],
        ),
        'ent_campaigns_with_cve_structured_count': cve_results['campaigns_with_cve_structured'],
        'ent_campaigns_with_cve_structured_pct': cve_results['campaigns_with_cve_structured_pct'],
        'ent_campaigns_with_cve_enrichment_gain_count': cve_results['campaigns_with_cve_enrichment_gain'],
        'ent_campaigns_with_cve_enrichment_gain_pp': cve_results['campaigns_with_cve_enrichment_gain_pp'],
        'ent_campaigns_with_cve_count': cve_results['campaigns_with_cve'],
        'ent_campaigns_with_cve_pct': cve_results['campaigns_with_cve_pct'],
        'ent_campaigns_with_cve_ci_low': proportion_ci_wilson(
            cve_results['campaigns_with_cve'],
            software_results['total_usable_campaigns'],
        )[0],
        'ent_campaigns_with_cve_ci_high': proportion_ci_wilson(
            cve_results['campaigns_with_cve'],
            software_results['total_usable_campaigns'],
        )[1],
        'ent_intrusion_sets_with_cve_structured_count': cve_results['is_with_cve_structured'],
        'ent_intrusion_sets_with_cve_structured_pct': cve_results['is_with_cve_structured_pct'],
        'ent_intrusion_sets_with_cve_enrichment_gain_count': cve_results['is_with_cve_enrichment_gain'],
        'ent_intrusion_sets_with_cve_enrichment_gain_pp': cve_results['is_with_cve_enrichment_gain_pp'],
        'ent_intrusion_sets_with_cve_count': cve_results['is_with_cve'],
        'ent_intrusion_sets_with_cve_pct': cve_results['is_with_cve_pct'],

        # Initial Access
        'initial_access_technique_count': initial_access_results['initial_access_technique_count'],
        'campaigns_with_initial_access_count': initial_access_results['campaigns_with_initial_access_count'],
        'campaigns_with_initial_access_pct': initial_access_results['campaigns_with_initial_access_pct'],
        'campaigns_with_initial_access_ci_low': proportion_ci_wilson(
            initial_access_results['campaigns_with_initial_access_count'],
            software_results['total_usable_campaigns'],
        )[0],
        'campaigns_with_initial_access_ci_high': proportion_ci_wilson(
            initial_access_results['campaigns_with_initial_access_count'],
            software_results['total_usable_campaigns'],
        )[1],
        'campaigns_with_social_initial_access_count': initial_access_results['campaigns_with_social_initial_access_count'],
        'campaigns_with_social_initial_access_pct': initial_access_results['campaigns_with_social_initial_access_pct'],
        'campaigns_with_initial_access_and_cve_count': initial_access_results['campaigns_with_initial_access_and_cve_count'],
        'campaigns_with_initial_access_and_cve_pct': initial_access_results['campaigns_with_initial_access_and_cve_pct'],
        'campaigns_with_initial_access_no_cve_count': initial_access_results['campaigns_with_initial_access_no_cve_count'],
        'campaigns_with_initial_access_no_cve_pct': initial_access_results['campaigns_with_initial_access_no_cve_pct'],
        'campaigns_with_initial_access_no_cve_conditional_pct': pct(
            initial_access_results['campaigns_with_initial_access_no_cve_count'],
            initial_access_results['campaigns_with_initial_access_count'],
        ),

        # RQ2 Compatibility
        'compatibility_container_feasible_count': compat_results['cf_count'],
        'compatibility_container_feasible_percentage': compat_results['cf_pct'],
        'compatibility_vm_required_count': compat_results['vmr_count'],
        'compatibility_vm_required_percentage': compat_results['vmr_pct'],
        'compatibility_vmr_explicit_count': compat_results['vmr_explicit_count'],
        'compatibility_vmr_explicit_percentage': compat_results['vmr_explicit_pct'],
        'compatibility_vmr_fallback_count': compat_results['vmr_fallback_count'],
        'compatibility_vmr_fallback_percentage': compat_results['vmr_fallback_pct'],
        'compatibility_infrastructure_dependent_count': compat_results['id_count'],
        'compatibility_infrastructure_dependent_percentage': compat_results['id_pct'],
        'compatibility_explicit_assignment_count': compat_results['explicit_count'],
        'compatibility_explicit_assignment_percentage': compat_results['explicit_pct'],
        'compatibility_fallback_assignment_count': compat_results['fallback_count'],
        'compatibility_fallback_assignment_percentage': compat_results['fallback_pct'],
        'compatibility_assignment_coverage_before_fallback_percentage': (
            compat_results['explicit_pct']
        ),
        'compatibility_assignment_coverage_after_fallback_percentage': (
            compat_results['resolved_pct']
        ),
        'compatibility_assignment_coverage_gain_pp': compat_results['fallback_pct'],
        'compatibility_explicit_non_cf_count': compat_results['explicit_non_cf_count'],
        'compatibility_explicit_non_cf_percentage': (
            compat_results['explicit_non_cf_explicit_only_pct']
        ),
        'compatibility_explicit_non_cf_corpus_percentage': (
            compat_results['explicit_non_cf_corpus_pct']
        ),
        'compatibility_final_non_cf_count': compat_results['final_non_cf_count'],
        'compatibility_final_non_cf_corpus_percentage': (
            compat_results['final_non_cf_corpus_pct']
        ),
        'compatibility_non_cf_floor_percentage': min(non_cf_values),
        'compatibility_non_cf_ceiling_percentage': max(non_cf_values),
        'compatibility_non_cf_baseline_percentage': (
            compat_results['final_non_cf_corpus_pct']
        ),
        # Backwards-compatible aliases.  The first two expose their denominator
        # in the canonical keys above.  The former 58.9 pp value was invalid:
        # it subtracted corpus-wide assignment coverage (32.7%) from an
        # explicit-only non-CF share (91.6%).  Resolution gain now means the
        # corpus-wide assignment-coverage gain from applying the fallback.
        'compatibility_rule_coverage_percentage': unresolved_scenario['resolved_pct'],
        'compatibility_non_cf_resolved_percentage': (
            unresolved_scenario['explicit_non_cf_explicit_only_pct']
        ),
        'compatibility_resolution_gain_pp': compat_results['fallback_pct'],
        'compatibility_validation_sample_size': len(compatibility_validation_sample),

        # RQ3 Specificity
        'sut_profile_unique_software_percentage': sw_only['unique_pct'],
        'sut_profile_unique_software_cve_percentage': sw_cve['unique_pct'],
        'sut_profile_unique_software_platform_percentage': sw_platform['unique_pct'],
        'sut_profile_unique_software_cve_platform_percentage': sw_cve_platform['unique_pct'],
        'sut_profile_unique_software_family_only_percentage': sw_family_only['unique_pct'],
        'sut_profile_unique_software_compat_percentage': sw_compat['unique_pct'],
        'sut_profile_confusion_software_percentage': sw_only['confused_pct'],
        'sut_profile_confusion_software_count': sw_only['confused_count'],
        'sut_profile_confusion_software_cve_percentage': sw_cve['confused_pct'],
        'sut_profile_confusion_software_platform_percentage': sw_platform['confused_pct'],
        'sut_profile_confusion_software_cve_platform_percentage': sw_cve_platform['confused_pct'],
        'sut_profile_confusion_software_family_only_percentage': sw_family_only['confused_pct'],
        'sut_profile_confusion_software_compat_percentage': sw_compat['confused_pct'],
        'sut_profile_confusion_software_compat_count': sw_compat['confused_count'],
        'sut_profile_confusion_software_cve_ci_low': proportion_ci_wilson(
            sw_cve['confused_count'],
            sw_cve['total_is'],
        )[0],
        'sut_profile_confusion_software_cve_ci_high': proportion_ci_wilson(
            sw_cve['confused_count'],
            sw_cve['total_is'],
        )[1],
        'threshold_k_one_confusion_pct': threshold_results['k1_confusion_pct'],
        'threshold_k_two_confusion_pct': threshold_results['k2_confusion_pct'],
        'threshold_k_three_confusion_pct': threshold_results['k3_confusion_pct'],
        'threshold_k_five_confusion_pct': threshold_results['k5_confusion_pct'],
        'threshold_k_one_sample': threshold_results['k1_sample'],
        'threshold_k_two_sample': threshold_results['k2_sample'],
        'threshold_k_three_sample': threshold_results['k3_sample'],
        'threshold_k_five_sample': threshold_results['k5_sample'],
        'delta_zero_zero_five_confusion_pct': next(
            (row['confusion_pct'] for row in delta_sensitivity if abs(row['delta'] - 0.05) < 1e-9),
            0.0,
        ),
        'delta_zero_ten_confusion_pct': next(
            (row['confusion_pct'] for row in delta_sensitivity if abs(row['delta'] - 0.10) < 1e-9),
            0.0,
        ),
        'delta_zero_fifteen_confusion_pct': next(
            (row['confusion_pct'] for row in delta_sensitivity if abs(row['delta'] - 0.15) < 1e-9),
            0.0,
        ),
        'delta_zero_twenty_confusion_pct': next(
            (row['confusion_pct'] for row in delta_sensitivity if abs(row['delta'] - 0.20) < 1e-9),
            0.0,
        ),
        'delta_zero_thirty_confusion_pct': next(
            (row['confusion_pct'] for row in delta_sensitivity if abs(row['delta'] - 0.30) < 1e-9),
            0.0,
        ),
        'bootstrap_confusion_pct': bootstrap_results['confusion_pct'],
        'bootstrap_confusion_ci_low': bootstrap_results['confusion_ci_low'],
        'bootstrap_confusion_ci_high': bootstrap_results['confusion_ci_high'],
        'bootstrap_unique_pct': bootstrap_results['unique_pct'],
        'bootstrap_unique_ci_low': bootstrap_results['unique_ci_low'],
        'bootstrap_unique_ci_high': bootstrap_results['unique_ci_high'],
        'null_model_iterations': null_model_results['iterations'],
        'null_model_observed_confusion_pct': null_model_results['observed_confusion_pct'],
        'null_model_confusion_mean_pct': null_model_results['null_confusion_mean_pct'],
        'null_model_confusion_plow_pct': null_model_results['null_confusion_p05_pct'],
        'null_model_confusion_phigh_pct': null_model_results['null_confusion_p95_pct'],
        'null_model_observed_minus_mean_pp': null_model_results['delta_observed_minus_null_mean_pp'],
        'null_model_p_value': null_model_results['p_value'],
        'threshold_collapse_observed_pp': null_model_results['observed_collapse_pp'],
        'threshold_collapse_k_one_confused_count': (
            null_model_results['observed_k1_confused_count']
        ),
        'threshold_collapse_k_two_confused_count': (
            null_model_results['observed_k2_confused_count']
        ),
        'threshold_collapse_null_mean_pp': null_model_results['null_collapse_mean_pp'],
        'threshold_collapse_null_plow_pp': null_model_results['null_collapse_p05_pp'],
        'threshold_collapse_null_pmedian_pp': null_model_results['null_collapse_p50_pp'],
        'threshold_collapse_null_phigh_pp': null_model_results['null_collapse_p95_pp'],
        'threshold_collapse_null_p_value': null_model_results['collapse_p_value'],
        'threshold_collapse_null_p_value_mc_se': (
            null_model_results['collapse_p_value_mc_se']
        ),
        'threshold_collapse_degree_null_mean_pp': (
            degree_null_results['null_collapse_mean_pp']
        ),
        'threshold_collapse_degree_null_plow_pp': (
            degree_null_results['null_collapse_p05_pp']
        ),
        'threshold_collapse_degree_null_phigh_pp': (
            degree_null_results['null_collapse_p95_pp']
        ),
        'threshold_collapse_degree_null_p_value': (
            degree_null_results['collapse_p_value']
        ),
        'threshold_collapse_degree_null_p_value_mc_se': (
            degree_null_results['collapse_p_value_mc_se']
        ),
        'threshold_collapse_influential_profile_count': (
            threshold_influence['influential_profile_count']
        ),
        'threshold_collapse_leave_one_out_min_pp': (
            threshold_influence['minimum_leave_one_out_collapse_pp']
        ),
        'threshold_collapse_leave_one_out_max_pp': (
            threshold_influence['maximum_leave_one_out_collapse_pp']
        ),
        'software_profile_empty_count': sum(
            len(profile) == 0 for profile in software_only_profiles.values()
        ),
        'software_profile_singleton_count': sum(
            len(profile) == 1 for profile in software_only_profiles.values()
        ),
        'software_profile_empty_confused_count': sum(
            row['feature_count'] == 0 and row['confused']
            for row in specificity_results['software_only']['per_is_rows']
        ),
        'software_profile_singleton_confused_count': sum(
            row['feature_count'] == 1 and row['confused']
            for row in specificity_results['software_only']['per_is_rows']
        ),

        # Campaign Factual Structure (inNervoso consolidation)
        'campaign_mean_technique_count': campaign_factual['campaign_mean_technique_count'],
        'campaign_median_technique_count': campaign_factual['campaign_median_technique_count'],
        'campaign_mean_tactic_coverage': campaign_factual['campaign_mean_tactic_coverage'],
        'campaign_complete_killchain_count': campaign_factual['campaigns_complete_killchain'],
        'campaign_complete_killchain_pct': campaign_factual['campaign_complete_killchain_pct'],
        'campaign_with_ia_and_exfil_count': campaign_factual['campaigns_with_ia_and_exfil'],
        'campaign_with_ia_and_exfil_pct': campaign_factual['campaign_with_ia_and_exfil_pct'],

        # Environment Inference + IEIR
        'ieir_count': env_inference['ieir_count'],
        'ieir_pct': env_inference['ieir_pct'],
        'environment_campaign_specific_count': env_inference['campaign_specific_count'],
        'environment_campaign_specific_pct': env_inference['campaign_specific_pct'],
        'environment_high_confidence_pct': env_inference['environment_high_confidence_pct'],
        'environment_medium_pct': env_inference['environment_medium_pct'],
        'environment_low_pct': env_inference['environment_low_pct'],
        'environment_none_pct': env_inference['environment_none_pct'],
        'campaigns_with_os_family_signal_count': platform_lookup.get(
            'campaigns_with_os_family_signal_count',
            0,
        ),
        'campaigns_with_single_os_family_count': platform_lookup.get(
            'campaigns_with_single_os_family_count',
            0,
        ),
        'campaigns_with_dual_os_family_count': platform_lookup.get(
            'campaigns_with_dual_os_family_count',
            0,
        ),
        'campaigns_with_triple_os_family_count': platform_lookup.get(
            'campaigns_with_triple_os_family_count',
            0,
        ),
        'platform_ablation_technique_unknown_count': platform_lookup.get(
            'platform_ablation_technique_unknown_count',
            0,
        ),
        'platform_ablation_technique_single_os_count': platform_lookup.get(
            'platform_ablation_technique_single_os_count',
            0,
        ),
        'platform_ablation_technique_triple_os_count': platform_lookup.get(
            'platform_ablation_technique_triple_os_count',
            0,
        ),
        'one_software_campaigns_with_os_signal_count': platform_lookup.get(
            'one_software_campaigns_with_os_signal_count',
            0,
        ),
        'one_software_campaigns_single_os_count': platform_lookup.get(
            'one_software_campaigns_single_os_count',
            0,
        ),
        'one_software_campaigns_triple_os_count': platform_lookup.get(
            'one_software_campaigns_triple_os_count',
            0,
        ),
        'campaigns_with_non_os_only_platform_signal_count': platform_lookup.get(
            'campaigns_with_non_os_only_platform_signal_count',
            0,
        ),

        # Evidence Convergence
        'evidence_convergence_count': evidence_convergence['convergence_count'],
        'evidence_convergence_rate_pct': evidence_convergence['convergence_rate_pct'],
        'evidence_divergence_count': evidence_convergence['divergence_count'],
        'evidence_convergence_assessable_count': (
            evidence_convergence['assessable_campaign_count']
        ),
        'evidence_convergence_assessable_convergent_count': (
            evidence_convergence['assessable_convergence_count']
        ),
        'evidence_convergence_assessable_rate_pct': (
            evidence_convergence['assessable_convergence_rate_pct']
        ),
        'evidence_convergence_assessable_divergence_count': (
            evidence_convergence['assessable_divergence_count']
        ),
        'evidence_mean_signal_count': evidence_convergence['evidence_mean_signal_count'],
    }

    # ==============================================================
    # Macro completeness and manuscript coverage checks
    # ==============================================================
    unresolved_values = {
        k: v for k, v in todo_values.items()
        if isinstance(v, str) and v.strip().upper() in {'', 'N/A', 'TODO', 'TBD'}
    }
    if unresolved_values:
        sample = ", ".join(f"{k}={v}" for k, v in list(unresolved_values.items())[:8])
        raise RuntimeError(
            "Unresolved metric values found in todo_values; "
            f"pipeline output is not fully operational: {sample}"
        )

    # Manuscript coupling is explicit. Integrated runs compute coverage against
    # the selected paper, but the LaTeX output remains the complete measured
    # macro set. This keeps artifact bytes independent of paper location and
    # prevents an opt-in sync from dropping macros used by included templates.
    explicit_paper_dir = os.environ.get("PAPER_DIR", "").strip()
    if explicit_paper_dir:
        paper_main_tex = Path(explicit_paper_dir).expanduser().resolve() / "main.tex"
        if not paper_main_tex.is_file():
            raise RuntimeError(
                f"Explicit PAPER_DIR has no main.tex: {paper_main_tex.parent}"
            )
    else:
        paper_main_tex = Path("/nonexistent/main.tex")
    write_keys = list(todo_values.keys())
    macro_coverage = {
        'generated_macro_count': len(todo_values),
        'manuscript_macro_count': 0,
        'unused_generated_macro_count': 0,
        'unused_generated_macros': [],
    }
    if paper_main_tex.exists():
        main_text = paper_main_tex.read_text(encoding='utf-8')
        used_macros = set(re.findall(r'\\([A-Za-z][A-Za-z0-9]+)', main_text))
        generated_name_to_key = {k.replace('_', ''): k for k in todo_values.keys()}
        order = {k: idx for idx, k in enumerate(todo_values.keys())}
        used_write_keys = sorted(
            {generated_name_to_key[name] for name in used_macros if name in generated_name_to_key},
            key=lambda k: order[k],
        )
        unused = [k for k in todo_values.keys() if k not in set(used_write_keys)]
        macro_coverage = {
            'generated_macro_count': len(todo_values),
            'manuscript_macro_count': len(used_write_keys),
            'unused_generated_macro_count': len(unused),
            'unused_generated_macros': unused,
        }
        print(
            "  Macro coverage: "
            f"{len(used_write_keys)} used in manuscript, {len(unused)} generated-only metrics in JSON/audit."
        )
    else:
        print("  Standalone macro export: no explicit PAPER_DIR; exporting all generated macros.")
    with open(RESULTS_DIR / 'macro_coverage.json', 'w', encoding='utf-8') as f:
        json.dump(macro_coverage, f, indent=2)

    # ── Merge SUT-configuration provenance, measured by a separate frozen experiment ──
    for key, value in _sut_configuration_values().items():
        todo_values[key] = value
        if key not in write_keys:
            write_keys.append(key)

    # ── Save TODO values as JSON ──
    with open(RESULTS_DIR / 'todo_values.json', 'w') as f:
        json.dump(todo_values, f, indent=2)
    print(f"\nOK TODO values saved to {RESULTS_DIR / 'todo_values.json'}")

    # ── Save as LaTeX newcommands ──
    with open(RESULTS_DIR / 'todo_values_latex.tex', 'w') as f:
        f.write("% Auto-generated extracted values\n")
        f.write("% Bundle: ATT&CK Enterprise v19.2\n\n")
        for key in write_keys:
            val = todo_values[key]
            latex_key = key.replace('_', '')
            f.write(f"\\newcommand{{\\{latex_key}}}{{{val}}}\n")
    print(f"OK LaTeX commands saved to {RESULTS_DIR / 'todo_values_latex.tex'}")

    # ── Save figure data ──
    figure_data = {
        'coverage_chart': {
            'enterprise': {
                'platform': cross_domain.get('enterprise', {}).get('platform_pct', 0),
                'software_link': cross_domain.get('enterprise', {}).get('software_link_pct', 0),
                'cve_link': cross_domain.get('enterprise', {}).get('cve_link_pct', 0),
                'attack_pattern_n': cross_domain.get('enterprise', {}).get('total_techniques', 0),
            },
            'mobile': {
                'platform': cross_domain.get('mobile', {}).get('platform_pct', 0),
                'software_link': cross_domain.get('mobile', {}).get('software_link_pct', 0),
                'cve_link': cross_domain.get('mobile', {}).get('cve_link_pct', 0),
                'attack_pattern_n': cross_domain.get('mobile', {}).get('total_techniques', 0),
            },
            'ics': {
                'platform': cross_domain.get('ics', {}).get('platform_pct', 0),
                'software_link': cross_domain.get('ics', {}).get('software_link_pct', 0),
                'cve_link': cross_domain.get('ics', {}).get('cve_link_pct', 0),
                'attack_pattern_n': cross_domain.get('ics', {}).get('total_techniques', 0),
            },
            'capec': {
                'platform': cross_domain.get('capec', {}).get('platform_pct', 0),
                'software_link': cross_domain.get('capec', {}).get('software_link_pct', 0),
                'cve_link': cross_domain.get('capec', {}).get('cve_link_pct', 0),
                'attack_pattern_n': cross_domain.get('capec', {}).get('total_techniques', 0),
            },
            'fight': {
                'platform': cross_domain.get('fight', {}).get('platform_pct', 0),
                'software_link': cross_domain.get('fight', {}).get('software_link_pct', 0),
                'cve_link': cross_domain.get('fight', {}).get('cve_link_pct', 0),
                'attack_pattern_n': cross_domain.get('fight', {}).get('total_techniques', 0),
            },
        },
        'coverage_density': {
            key: {
                'attack_pattern_n': val.get('total_techniques', 0),
                'avg_software_links_per_attack_pattern': val.get(
                    'avg_software_links_per_attack_pattern', 0.0
                ),
                'median_software_links_per_attack_pattern': val.get(
                    'median_software_links_per_attack_pattern', 0.0
                ),
                'p90_software_links_per_attack_pattern': val.get(
                    'p90_software_links_per_attack_pattern', 0.0
                ),
                'avg_cve_mentions_per_attack_pattern': val.get(
                    'avg_cve_mentions_per_attack_pattern', 0.0
                ),
            }
            for key, val in cross_domain.items()
        },
        'software_specificity': {
            'total_software': software_results['total_software'],
            'no_version_no_cpe': software_results['total_software'] - software_results['software_with_version'] - software_results['software_with_cpe'] + min(software_results['software_with_version'], software_results['software_with_cpe']),
            'version_no_cpe': software_results['software_with_version'] - min(software_results['software_with_version'], software_results['software_with_cpe']),
            'with_cpe': software_results['software_with_cpe'],
            'no_version_no_cpe_pct': 0,  # Will compute
            'version_no_cpe_pct': 0,
            'with_cpe_pct': 0,
        },
        'campaign_tier_collapse': {
            'total_campaigns': profile_completeness['total_campaigns'],
            't1_count': profile_completeness['tier_t1_count'],
            't1_pct': profile_completeness['tier_t1_pct'],
            't2_count': profile_completeness['tier_t2_count'],
            't2_pct': profile_completeness['tier_t2_pct'],
            't3_count': profile_completeness['tier_t3_count'],
            't3_pct': profile_completeness['tier_t3_pct'],
        },
        'cve_location': {
            'structured_count': cve_results['cve_structured_count'],
            'freetext_only_count': cve_results['cve_freetext_only_count'],
            'total': cve_results['cve_unique_count'],
        },
        'cve_operational_funnel': {
            'detected_unique_cves': cve_results['cve_unique_count'],
            'actionable_cves': cve_results['actionable_cve_count'],
            'environment_associated_cves': cve_results['actionable_cve_count'],
            'campaign_linked_cves': len(cve_results['cves_from_campaigns']),
            'campaigns_with_cve': cve_results['campaigns_with_cve'],
            'total_campaigns': software_results['total_usable_campaigns'],
        },
        'jaccard_cdf': {
            'software_only_distances': specificity_results['software_only']['nearest_distances'],
            'software_cve_distances': specificity_results['software_cve']['nearest_distances'],
            'software_platform_distances': specificity_results['software_platform']['nearest_distances'],
            'software_cve_platform_distances': specificity_results['software_cve_platform']['nearest_distances'],
            'software_family_only_distances': specificity_results['software_family_only']['nearest_distances'],
            'software_compat_distances': specificity_results['software_compat']['nearest_distances'],
            'delta_threshold': JACCARD_DELTA,
        },
        'compatibility_table': {
            'cf': compat_results['cf_count'],
            'vmr': compat_results['vmr_count'],
            'vmr_explicit': compat_results['vmr_explicit_count'],
            'vmr_fallback': compat_results['vmr_fallback_count'],
            'id': compat_results['id_count'],
            'total': compat_results['total'],
            'cf_pct': compat_results['cf_pct'],
            'vmr_pct': compat_results['vmr_pct'],
            'vmr_explicit_pct': compat_results['vmr_explicit_pct'],
            'vmr_fallback_pct': compat_results['vmr_fallback_pct'],
            'id_pct': compat_results['id_pct'],
            'non_cf_floor_pct': min(non_cf_values) if non_cf_values else 0.0,
            'non_cf_ceiling_pct': max(non_cf_values) if non_cf_values else 0.0,
            'explicit_non_cf_explicit_only_pct': (
                compat_results['explicit_non_cf_explicit_only_pct']
            ),
            'explicit_assignment_corpus_pct': compat_results['explicit_pct'],
            'fallback_assignment_corpus_pct': compat_results['fallback_pct'],
            'final_assignment_corpus_pct': compat_results['resolved_pct'],
            'final_non_cf_corpus_pct': compat_results['final_non_cf_corpus_pct'],
        },
        'compatibility_by_tactic': compatibility_by_tactic,
        'ablation_summary': {
            'software_only': {
                'unique_pct': sw_only['unique_pct'],
                'confused_pct': sw_only['confused_pct'],
            },
            'software_cve': {
                'unique_pct': sw_cve['unique_pct'],
                'confused_pct': sw_cve['confused_pct'],
            },
            'software_platform': {
                'unique_pct': sw_platform['unique_pct'],
                'confused_pct': sw_platform['confused_pct'],
            },
            'software_cve_platform': {
                'unique_pct': sw_cve_platform['unique_pct'],
                'confused_pct': sw_cve_platform['confused_pct'],
            },
            'software_family_only': {
                'unique_pct': sw_family_only['unique_pct'],
                'confused_pct': sw_family_only['confused_pct'],
            },
            'software_compat': {
                'unique_pct': sw_compat['unique_pct'],
                'confused_pct': sw_compat['confused_pct'],
            },
        },
        'threshold_confusion': {
            'k_values': [1, 2, 3],
            'confusion_pct': [
                threshold_results['k1_confusion_pct'],
                threshold_results['k2_confusion_pct'],
                threshold_results['k3_confusion_pct'],
            ],
            'sample_sizes': [
                threshold_results['k1_sample'],
                threshold_results['k2_sample'],
                threshold_results['k3_sample'],
            ],
            'baseline_all_is_confusion_pct': sw_only['confused_pct'],
            'baseline_all_is_sample_size': sw_only['total_is'],
        },
        'threshold_collapse_null': {
            'observed_collapse_pp': null_model_results['observed_collapse_pp'],
            'cardinality_null_mean_pp': null_model_results['null_collapse_mean_pp'],
            'cardinality_null_p05_pp': null_model_results['null_collapse_p05_pp'],
            'cardinality_null_p95_pp': null_model_results['null_collapse_p95_pp'],
            'cardinality_null_p_value': null_model_results['collapse_p_value'],
            'cardinality_null_p_value_mc_se': (
                null_model_results['collapse_p_value_mc_se']
            ),
            'degree_null_mean_pp': degree_null_results['null_collapse_mean_pp'],
            'degree_null_p05_pp': degree_null_results['null_collapse_p05_pp'],
            'degree_null_p95_pp': degree_null_results['null_collapse_p95_pp'],
            'degree_null_p_value': degree_null_results['collapse_p_value'],
            'degree_null_p_value_mc_se': (
                degree_null_results['collapse_p_value_mc_se']
            ),
            'leave_one_out_influential_profiles': (
                threshold_influence['influential_profile_count']
            ),
            'leave_one_out_min_pp': (
                threshold_influence['minimum_leave_one_out_collapse_pp']
            ),
            'leave_one_out_max_pp': (
                threshold_influence['maximum_leave_one_out_collapse_pp']
            ),
        },
        'behavior_profile_specificity': {
            'unique_pct': behavior_specificity['unique_pct'],
            'confused_pct': behavior_specificity['confused_pct'],
            'total_is': behavior_specificity['total_is'],
            'feature_universe_size': behavior_specificity['feature_universe_size'],
        },
        'technique_threshold_confusion': {
            'k_values': [1, 2, 3],
            'confusion_pct': [
                behavior_specificity['threshold']['k1_confusion_pct'],
                behavior_specificity['threshold']['k2_confusion_pct'],
                behavior_specificity['threshold']['k3_confusion_pct'],
            ],
            'sample_sizes': [
                behavior_specificity['threshold']['k1_sample'],
                behavior_specificity['threshold']['k2_sample'],
                behavior_specificity['threshold']['k3_sample'],
            ],
            'baseline_all_is_confusion_pct': behavior_specificity['confused_pct'],
            'baseline_all_is_sample_size': behavior_specificity['total_is'],
        },
    }

    # Ensure software-specificity segments are sourced from the same counters
    # used for manuscript macros (single source of truth).
    total_sw = figure_data['software_specificity']['total_software']
    version_only = software_results['software_version_no_cpe']
    cpe_any = software_results['software_with_cpe']
    neither = software_results['software_no_version_no_cpe']

    figure_data['software_specificity']['no_version_no_cpe'] = neither
    figure_data['software_specificity']['version_no_cpe'] = version_only
    figure_data['software_specificity']['with_cpe'] = cpe_any
    figure_data['software_specificity']['no_version_no_cpe_pct'] = pct(neither, total_sw)
    figure_data['software_specificity']['version_no_cpe_pct'] = pct(version_only, total_sw)
    figure_data['software_specificity']['with_cpe_pct'] = pct(cpe_any, total_sw)

    # Add description-enrichment data for Figure 2 before/after comparison
    figure_data['software_specificity']['desc_enriched_count'] = version_enrichment['desc_enriched_count']
    figure_data['software_specificity']['desc_enriched_pct'] = version_enrichment['desc_enriched_pct']
    figure_data['software_specificity']['enriched_total'] = version_enrichment['enriched_total']
    figure_data['software_specificity']['enriched_total_pct'] = version_enrichment['enriched_total_pct']
    figure_data['software_specificity']['enriched_no_version_pct'] = version_enrichment['enriched_no_version_pct']
    figure_data['software_specificity']['gain_pp'] = version_enrichment['gain_pp']

    # ── Campaign factual structure + environment inference figure data ──
    # Tactic coverage heatmap data
    figure_data['campaign_tactic_coverage'] = {
        'campaigns': [],
        'tactic_order': enterprise_tactic_order(all_objects),
    }
    for row in campaign_factual['rows']:
        tactics_present = set(row.get('tactic_sequence', '').split(';'))
        figure_data['campaign_tactic_coverage']['campaigns'].append({
            'name': row['campaign_name'],
            'tactics': {
                tactic: int(tactic in tactics_present)
                for tactic in figure_data['campaign_tactic_coverage']['tactic_order']
            },
            'technique_count': row['technique_count'],
            'tactic_count': row['tactic_count'],
        })

    # IEIR breakdown data
    figure_data['ieir_breakdown'] = {
        'total': env_inference['total_campaigns'],
        'campaign_specific': env_inference['campaign_specific_count'],
        'generic_only': env_inference['ieir_count'],
        'no_signal': env_inference['environment_none_count'],
        'campaign_specific_pct': env_inference['campaign_specific_pct'],
        'ieir_pct': env_inference['ieir_pct'],
        'none_pct': env_inference['environment_none_pct'],
        'confidence_breakdown': {
            'high': env_inference['environment_high_confidence_pct'],
            'medium': env_inference['environment_medium_pct'],
            'low': env_inference['environment_low_pct'],
            'none': env_inference['environment_none_pct'],
        },
    }

    # Evidence convergence data
    figure_data['evidence_convergence'] = {
        'total': evidence_convergence['assessable_campaign_count'],
        'convergent': evidence_convergence['assessable_convergence_count'],
        'divergent': evidence_convergence['assessable_divergence_count'],
        'convergence_rate_pct': evidence_convergence['assessable_convergence_rate_pct'],
        'mean_signal_count': evidence_convergence['evidence_mean_signal_count'],
    }

    with open(RESULTS_DIR / 'figures_data.json', 'w') as f:
        # Convert numpy types to native Python for JSON serialization
        json.dump(figure_data, f, indent=2, default=float)
    print(f"OK Figure data saved to {RESULTS_DIR / 'figures_data.json'}")

    # ── Save audit CSVs ──
    # Campaign software details
    with open(AUDIT_DIR / 'campaign_software.csv', 'w', newline='') as f:
        writer = lf_dict_writer(f, fieldnames=['campaign_name', 'campaign_id', 'software_count'])
        writer.writeheader()
        for row in software_results['campaign_details']:
            writer.writerow({k: row[k] for k in ['campaign_name', 'campaign_id', 'software_count']})

    # Software version enrichment from descriptions (audit trail)
    if version_enrichment['enriched_examples']:
        with open(AUDIT_DIR / 'software_version_enrichment.csv', 'w', newline='') as f:
            writer = lf_dict_writer(
                f,
                fieldnames=['name', 'id', 'matched_version', 'description_snippet']
            )
            writer.writeheader()
            for row in version_enrichment['enriched_examples']:
                writer.writerow(row)
        print(f"OK Version enrichment audit saved to {AUDIT_DIR / 'software_version_enrichment.csv'}")

    # Campaign platform inference details (software-only)
    with open(AUDIT_DIR / 'campaign_platforms_software_only.csv', 'w', newline='') as f:
        writer = lf_dict_writer(
            f,
            fieldnames=[
                'campaign_name', 'campaign_id', 'software_count', 'platform_signal',
                'os_families', 'raw_platforms', 'non_os_platforms', 'unknown_reason'
            ]
        )
        writer.writeheader()
        for row in software_results['campaign_platform_details']:
            writer.writerow({
                'campaign_name': row['campaign_name'],
                'campaign_id': row['campaign_id'],
                'software_count': row['software_count'],
                'platform_signal': row['platform_signal'],
                'os_families': ';'.join(row['os_families']),
                'raw_platforms': ';'.join(row['raw_platforms']),
                'non_os_platforms': ';'.join(row['non_os_platforms']),
                'unknown_reason': row['unknown_reason'],
            })

    # Campaign OS family aggregate counts (multi-label over campaigns)
    with open(AUDIT_DIR / 'campaign_os_family_counts.csv', 'w', newline='') as f:
        writer = lf_dict_writer(f, fieldnames=['os_family', 'campaign_count'])
        writer.writeheader()
        for fam, count in software_results['campaign_os_family_counts'].items():
            writer.writerow({'os_family': fam, 'campaign_count': count})

    # Campaign non-OS platform aggregate counts
    with open(AUDIT_DIR / 'campaign_non_os_platform_counts.csv', 'w', newline='') as f:
        writer = lf_dict_writer(f, fieldnames=['platform_label', 'campaign_count'])
        writer.writeheader()
        for label, count in software_results['campaign_non_os_platform_counts'].items():
            writer.writerow({'platform_label': label, 'campaign_count': count})

    # Campaigns with unknown platform signal under software-only inference
    with open(AUDIT_DIR / 'campaign_platform_unknown.csv', 'w', newline='') as f:
        writer = lf_dict_writer(f, fieldnames=['campaign_name'])
        writer.writeheader()
        for name in software_results['campaign_unknown_platform_names']:
            writer.writerow({'campaign_name': name})

    # Campaign CVE details
    with open(AUDIT_DIR / 'campaign_cves.csv', 'w', newline='') as f:
        writer = lf_dict_writer(
            f,
            fieldnames=[
                'campaign_name',
                'campaign_id',
                'cve_count_structured',
                'cve_count',
                'cve_enrichment_gain_count',
                'cves_structured',
                'cves',
            ],
        )
        writer.writeheader()
        for row in cve_results['campaign_cve_details']:
            writer.writerow({
                'campaign_name': row['campaign_name'],
                'campaign_id': row.get('campaign_id', ''),
                'cve_count_structured': row.get('cve_count_structured', 0),
                'cve_count': row['cve_count'],
                'cve_enrichment_gain_count': row.get('cve_enrichment_gain_count', 0),
                'cves_structured': ';'.join(row.get('cves_structured', [])),
                'cves': ';'.join(row.get('cves', [])),
            })

    # Campaign-linked CVE year distribution (exploratory)
    campaign_cve_year_counter = Counter()
    for row in cve_results['campaign_cve_details']:
        for cve in row.get('cves', []):
            m = re.match(r'CVE-(\d{4})-\d{4,7}', cve, re.IGNORECASE)
            if m:
                campaign_cve_year_counter[m.group(1)] += 1
    with open(AUDIT_DIR / 'campaign_cve_year_distribution.csv', 'w', newline='') as f:
        writer = lf_dict_writer(f, fieldnames=['cve_year', 'count'])
        writer.writeheader()
        for year, count in sorted(campaign_cve_year_counter.items()):
            writer.writerow({'cve_year': year, 'count': count})

    # Campaign-level SUT profile completeness tiers
    with open(AUDIT_DIR / 'campaign_profile_completeness.csv', 'w', newline='') as f:
        writer = lf_dict_writer(
            f,
            fieldnames=[
                'campaign_name', 'campaign_id', 'has_software', 'has_platform_signal',
                'has_precision_reference', 'has_campaign_cve', 'tier_t1_coarse',
                'tier_t2_reference_enriched', 'tier_t3_cve_associated'
            ]
        )
        writer.writeheader()
        for row in profile_completeness['rows']:
            writer.writerow(row)

    # IS CVE details
    with open(AUDIT_DIR / 'is_cves.csv', 'w', newline='') as f:
        writer = lf_dict_writer(
            f,
            fieldnames=[
                'is_name',
                'cve_count_structured',
                'cve_count',
                'cve_enrichment_gain_count',
                'cves_structured',
                'cves',
            ],
        )
        writer.writeheader()
        for row in cve_results['is_cve_details']:
            writer.writerow({
                'is_name': row['is_name'],
                'cve_count_structured': row.get('cve_count_structured', 0),
                'cve_count': row['cve_count'],
                'cve_enrichment_gain_count': row.get('cve_enrichment_gain_count', 0),
                'cves_structured': ';'.join(row.get('cves_structured', [])),
                'cves': ';'.join(row.get('cves', [])),
            })

    # Initial Access campaign details
    with open(AUDIT_DIR / 'initial_access_campaigns.csv', 'w', newline='') as f:
        writer = lf_dict_writer(
            f,
            fieldnames=[
                'campaign_name', 'campaign_id', 'has_initial_access', 'has_social_proxy',
                'campaign_cve_count', 'initial_access_technique_count', 'initial_access_techniques'
            ]
        )
        writer.writeheader()
        for row in initial_access_results['campaign_rows']:
            writer.writerow({
                'campaign_name': row['campaign_name'],
                'campaign_id': row['campaign_id'],
                'has_initial_access': row['has_initial_access'],
                'has_social_proxy': row['has_social_proxy'],
                'campaign_cve_count': row['campaign_cve_count'],
                'initial_access_technique_count': row['initial_access_technique_count'],
                'initial_access_techniques': ';'.join(row['initial_access_techniques']),
            })

    # Initial Access technique frequency across campaigns
    with open(AUDIT_DIR / 'initial_access_techniques.csv', 'w', newline='') as f:
        writer = lf_dict_writer(f, fieldnames=['technique_name', 'campaign_count'])
        writer.writeheader()
        for name, count in initial_access_results['top_initial_access_techniques']:
            writer.writerow({'technique_name': name, 'campaign_count': count})

    # Technique compatibility routing-policy labels
    with open(AUDIT_DIR / 'technique_compatibility.csv', 'w', newline='') as f:
        writer = lf_dict_writer(
            f,
            fieldnames=[
                'name', 'id', 'external_id', 'attack_url', 'routing_label',
                'class', 'tactics',
                'platforms', 'permissions', 'rule_id', 'rule_desc',
                'rule_evidence', 'is_fallback'
            ]
        )
        writer.writeheader()
        for cls_name, cls_list in compat_results['details'].items():
            for tech in cls_list:
                writer.writerow({
                    'name': tech['name'],
                    'id': tech['id'],
                    'external_id': tech.get('external_id', ''),
                    'attack_url': tech.get('attack_url', ''),
                    'routing_label': tech['routing_label'],
                    'class': tech['class'],
                    'tactics': ';'.join(tech.get('tactics', []) or []),
                    'platforms': ';'.join(tech['platforms'] or []),
                    'permissions': ';'.join(tech['permissions'] or []),
                    'rule_id': tech.get('rule_id', ''),
                    'rule_desc': tech.get('rule_desc', ''),
                    'rule_evidence': tech.get('rule_evidence', ''),
                    'is_fallback': tech.get('is_fallback', False),
                })

    # Rule-level breakdown for compatibility assignments
    with open(AUDIT_DIR / 'compatibility_rule_breakdown.csv', 'w', newline='') as f:
        writer = lf_dict_writer(
            f,
            fieldnames=[
                'class', 'rule_id', 'rule_desc', 'count',
                'pct_within_class', 'pct_all_techniques'
            ]
        )
        writer.writeheader()
        for row in compatibility_rule_breakdown:
            writer.writerow(row)

    # Stratified sample for manual validation of compatibility labels
    with open(AUDIT_DIR / 'compatibility_validation_sample.csv', 'w', newline='') as f:
        writer = lf_dict_writer(
            f,
            fieldnames=[
                'sample_class', 'technique_name', 'technique_stix_id',
                'technique_external_id', 'attack_url', 'tactics', 'platforms',
                'permissions', 'policy_label', 'predicted_class', 'rule_id', 'rule_desc',
                'rule_evidence', 'is_fallback', 'manual_expected_class',
                'manual_verdict_match', 'manual_notes', 'reviewer'
            ]
        )
        writer.writeheader()
        for row in compatibility_validation_sample:
            writer.writerow(row)

    # Denominator contract for every percentage used in the compatibility
    # analysis.  This is the audit surface that prevents explicit-only and
    # corpus-wide metrics from being combined arithmetically.
    with open(AUDIT_DIR / 'compatibility_denominator_summary.csv', 'w', newline='') as f:
        writer = lf_dict_writer(
            f,
            fieldnames=[
                'metric', 'numerator', 'denominator', 'percentage',
                'denominator_scope', 'interpretation'
            ]
        )
        writer.writeheader()
        for row in compatibility_denominator_summary:
            writer.writerow(row)

    # Compatibility sensitivity under alternative defaults
    with open(AUDIT_DIR / 'compatibility_default_sensitivity.csv', 'w', newline='') as f:
        writer = lf_dict_writer(
            f,
            fieldnames=[
                'default_class', 'cf_count', 'cf_pct', 'vmr_count', 'vmr_pct',
                'id_count', 'id_pct', 'unresolved_count', 'unresolved_pct',
                'resolved_count', 'resolved_pct', 'non_cf_count', 'non_cf_pct',
                'non_cf_corpus_pct', 'explicit_count', 'explicit_non_cf_count',
                'explicit_non_cf_explicit_only_pct', 'total'
            ]
        )
        writer.writeheader()
        for row in compatibility_sensitivity:
            writer.writerow(row)

    # Compatibility distribution by tactic (exploratory)
    with open(AUDIT_DIR / 'compatibility_by_tactic.csv', 'w', newline='') as f:
        writer = lf_dict_writer(
            f,
            fieldnames=[
                'tactic', 'total', 'cf_count', 'cf_pct',
                'vmr_count', 'vmr_pct', 'id_count', 'id_pct',
                'non_cf_count', 'non_cf_pct',
            ]
        )
        writer.writeheader()
        for row in compatibility_by_tactic:
            writer.writerow(row)

    # IS software details
    with open(AUDIT_DIR / 'is_software.csv', 'w', newline='') as f:
        writer = lf_dict_writer(f, fieldnames=['is_name', 'is_id', 'software_count'])
        writer.writeheader()
        for row in software_results['is_details']:
            writer.writerow(row)

    # Per-IS nearest-neighbor specificity rows (software-only)
    with open(AUDIT_DIR / 'profile_specificity_software_only.csv', 'w', newline='') as f:
        writer = lf_dict_writer(
            f,
            fieldnames=['intrusion_set_id', 'feature_count', 'nearest_neighbor_id', 'nearest_distance', 'confused']
        )
        writer.writeheader()
        for row in specificity_results['software_only']['per_is_rows']:
            writer.writerow(row)

    # Per-IS nearest-neighbor specificity rows (technique-only behavior profiles, exploratory)
    with open(AUDIT_DIR / 'profile_specificity_technique_only.csv', 'w', newline='') as f:
        writer = lf_dict_writer(
            f,
            fieldnames=['intrusion_set_id', 'feature_count', 'nearest_neighbor_id', 'nearest_distance', 'confused']
        )
        writer.writeheader()
        for row in behavior_specificity['per_is_rows']:
            writer.writerow(row)

    # Profile specificity ablation summary at delta=0.10
    with open(AUDIT_DIR / 'profile_ablation_summary.csv', 'w', newline='') as f:
        writer = lf_dict_writer(
            f,
            fieldnames=['setting', 'unique_count', 'unique_pct', 'confused_count', 'confused_pct', 'total_is', 'num_features']
        )
        writer.writeheader()
        for setting in [
            'software_only',
            'software_cve',
            'software_platform',
            'software_cve_platform',
            'software_family_only',
            'software_compat',
        ]:
            row = specificity_results[setting]
            writer.writerow({
                'setting': setting,
                'unique_count': row['unique_count'],
                'unique_pct': row['unique_pct'],
                'confused_count': row['confused_count'],
                'confused_pct': row['confused_pct'],
                'total_is': row['total_is'],
                'num_features': row['num_features'],
            })

    # Confusion curve by minimum software evidence threshold
    with open(AUDIT_DIR / 'evidence_threshold_curve.csv', 'w', newline='') as f:
        writer = lf_dict_writer(
            f,
            fieldnames=['min_software_count', 'sample_size', 'confused_count', 'confusion_pct']
        )
        writer.writeheader()
        for row in threshold_results['curve']:
            writer.writerow(row)

    # Confusion curve by minimum technique evidence threshold (exploratory)
    with open(AUDIT_DIR / 'evidence_threshold_curve_technique_profile.csv', 'w', newline='') as f:
        writer = lf_dict_writer(
            f,
            fieldnames=['min_technique_count', 'sample_size', 'confused_count', 'confusion_pct']
        )
        writer.writeheader()
        for row in behavior_specificity['threshold']['curve']:
            writer.writerow({
                'min_technique_count': row['min_software_count'],
                'sample_size': row['sample_size'],
                'confused_count': row['confused_count'],
                'confusion_pct': row['confusion_pct'],
            })

    # Confusion sensitivity across multiple Jaccard deltas
    with open(AUDIT_DIR / 'delta_sensitivity.csv', 'w', newline='') as f:
        writer = lf_dict_writer(
            f,
            fieldnames=['delta', 'sample_size', 'confused_count', 'confusion_pct']
        )
        writer.writeheader()
        for row in delta_sensitivity:
            writer.writerow(row)

    # Descriptive resampling of fixed nearest-neighbor indicators at delta=0.10.
    # This file is retained for continuity; it is not the threshold-null test.
    with open(AUDIT_DIR / 'bootstrap_confusion_distribution.csv', 'w', newline='') as f:
        writer = lf_dict_writer(
            f,
            fieldnames=['stat', 'confusion_pct', 'unique_pct']
        )
        writer.writeheader()
        for row in bootstrap_results['bootstrap_summary_rows']:
            writer.writerow(row)

    # Cardinality-preserving null.  The global columns are retained as a
    # diagnostic; collapse_pp is the direct k>=1 to k>=2 test statistic.
    with open(AUDIT_DIR / 'null_model_confusion_distribution.csv', 'w', newline='') as f:
        writer = lf_dict_writer(
            f,
            fieldnames=[
                'iteration', 'global_confused_count', 'global_confusion_pct',
                'k1_sample_size', 'k1_confused_count', 'k1_confusion_pct',
                'k2_sample_size', 'k2_confused_count', 'k2_confusion_pct',
                'collapse_pp',
            ]
        )
        writer.writeheader()
        for row in null_model_results['distribution_rows']:
            writer.writerow(row)

    # Degree-preserving sensitivity: fixes both profile cardinalities and
    # observed software popularity through bipartite double-edge swaps.
    with open(
        AUDIT_DIR / 'threshold_collapse_degree_null_distribution.csv',
        'w',
        newline='',
    ) as f:
        writer = lf_dict_writer(
            f,
            fieldnames=[
                'iteration', 'accepted_swaps',
                'k1_sample_size', 'k1_confused_count', 'k1_confusion_pct',
                'k2_sample_size', 'k2_confused_count', 'k2_confusion_pct',
                'collapse_pp',
            ],
        )
        writer.writeheader()
        for row in degree_null_results['distribution_rows']:
            writer.writerow(row)

    # Deterministic influence surface for the descriptive collapse.
    with open(
        AUDIT_DIR / 'threshold_collapse_leave_one_out.csv',
        'w',
        newline='',
    ) as f:
        writer = lf_dict_writer(
            f,
            fieldnames=[
                'omitted_profile_id', 'omitted_feature_count', 'collapse_pp',
                'change_from_full_pp', 'changes_confusion_counts',
                'changes_reported_collapse',
            ],
        )
        writer.writeheader()
        for row in threshold_influence['rows']:
            writer.writerow(row)

    # Platform distribution
    with open(AUDIT_DIR / 'platform_distribution.csv', 'w', newline='') as f:
        writer = lf_dict_writer(f, fieldnames=['platform', 'technique_count'])
        writer.writeheader()
        for platform, count in sorted(platform_results['platform_distribution'].items(),
                                       key=lambda x: -x[1]):
            writer.writerow({'platform': platform, 'technique_count': count})

    # All CVEs found
    with open(AUDIT_DIR / 'all_cves.csv', 'w', newline='') as f:
        writer = lf_dict_writer(f, fieldnames=['cve_id', 'source'])
        writer.writeheader()
        for cve in sorted(cve_results['structured_cves']):
            writer.writerow({'cve_id': cve, 'source': 'structured'})
        for cve in sorted(cve_results['freetext_only_cves']):
            writer.writerow({'cve_id': cve, 'source': 'freetext_only'})

    # Technique-level CVE mention density by ATT&CK tactic (exploratory).
    tactic_technique_count = Counter()
    tactic_with_cve_mention_count = Counter()
    tactic_total_cve_mentions = Counter()
    for tech in techniques:
        cves_structured, cves_freetext = extract_cves_from_object(tech)
        cve_mentions = cves_structured | cves_freetext
        tactics = get_technique_tactics(tech, by_id)
        for tactic in tactics:
            tactic_technique_count[tactic] += 1
            if cve_mentions:
                tactic_with_cve_mention_count[tactic] += 1
                tactic_total_cve_mentions[tactic] += len(cve_mentions)

    with open(AUDIT_DIR / 'cve_mentions_by_tactic.csv', 'w', newline='') as f:
        writer = lf_dict_writer(
            f,
            fieldnames=[
                'tactic',
                'technique_count',
                'techniques_with_any_cve_mention',
                'techniques_with_any_cve_pct',
                'total_cve_mentions',
            ],
        )
        writer.writeheader()
        for tactic, total in sorted(tactic_technique_count.items(), key=lambda x: -x[1]):
            with_cve = tactic_with_cve_mention_count.get(tactic, 0)
            writer.writerow({
                'tactic': tactic,
                'technique_count': total,
                'techniques_with_any_cve_mention': with_cve,
                'techniques_with_any_cve_pct': pct(with_cve, total),
                'total_cve_mentions': tactic_total_cve_mentions.get(tactic, 0),
            })

    # Cross-domain coverage plus evidence density (exploratory).
    with open(AUDIT_DIR / 'cross_domain_coverage_density.csv', 'w', newline='') as f:
        writer = lf_dict_writer(
            f,
            fieldnames=[
                'domain',
                'attack_pattern_n',
                'platform_pct',
                'software_link_pct',
                'cve_link_pct',
                'avg_software_links_per_attack_pattern',
                'median_software_links_per_attack_pattern',
                'p90_software_links_per_attack_pattern',
                'avg_cve_mentions_per_attack_pattern',
            ],
        )
        writer.writeheader()
        for domain in ['enterprise', 'mobile', 'ics', 'capec', 'fight']:
            row = cross_domain.get(domain, {})
            writer.writerow({
                'domain': domain,
                'attack_pattern_n': row.get('total_techniques', 0),
                'platform_pct': row.get('platform_pct', 0),
                'software_link_pct': row.get('software_link_pct', 0),
                'cve_link_pct': row.get('cve_link_pct', 0),
                'avg_software_links_per_attack_pattern': row.get(
                    'avg_software_links_per_attack_pattern', 0.0
                ),
                'median_software_links_per_attack_pattern': row.get(
                    'median_software_links_per_attack_pattern', 0.0
                ),
                'p90_software_links_per_attack_pattern': row.get(
                    'p90_software_links_per_attack_pattern', 0.0
                ),
                'avg_cve_mentions_per_attack_pattern': row.get(
                    'avg_cve_mentions_per_attack_pattern', 0.0
                ),
            })

    # Campaign-level exploratory correlation summaries.
    with open(AUDIT_DIR / 'campaign_correlation_summary.csv', 'w', newline='') as f:
        writer = lf_dict_writer(
            f,
            fieldnames=['metric', 'value', 'note'],
        )
        writer.writeheader()
        for row in serendipity_results['correlation_rows']:
            writer.writerow(row)

    # Campaign-level platform inference quality checks (software-derived signal only).
    with open(AUDIT_DIR / 'platform_inference_quality_summary.csv', 'w', newline='') as f:
        writer = lf_dict_writer(
            f,
            fieldnames=['metric', 'value', 'note'],
        )
        writer.writeheader()
        for row in serendipity_results['platform_quality_rows']:
            writer.writerow(row)

    print(f"OK Audit CSVs saved to {AUDIT_DIR}")

    # ── Print summary ──
    print("\n" + "=" * 70)
    print("SUMMARY: Extracted Values")
    print("=" * 70)
    for key, val in todo_values.items():
        print(f"  \\TODO{{{key}}} = {val}")

    print("\n" + "=" * 70)
    print("VALIDATION CHECKS")
    print("=" * 70)
    cf_vmr_id_sum = compat_results['cf_count'] + compat_results['vmr_count'] + compat_results['id_count']
    print(f"  CF + VMR + ID = {cf_vmr_id_sum} (should be {len(techniques)})")
    pct_sum = compat_results['cf_pct'] + compat_results['vmr_pct'] + compat_results['id_pct']
    print(f"  CF% + VMR% + ID% = {pct_sum}% (should be ~100%)")
    print(f"  Usable campaigns: {profile_population_count} (exact profile inventory verified)")
    print(f"  Excluded campaigns: {excluded_campaign_ids}")

    return todo_values


if __name__ == '__main__':
    todo_values = main()
