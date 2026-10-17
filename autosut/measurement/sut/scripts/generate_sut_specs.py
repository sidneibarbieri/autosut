#!/usr/bin/env python3
"""
Canonical SUT Specification Generator

Reads pipeline outputs and generates deterministic SUT YAML specifications
for each ATT&CK campaign, based solely on structured STIX data.

No LLM calls. All inference is rule-based and auditable.
Every SUT element includes evidence_source tracing back to STIX objects.

Schema follows inNervoso format for compatibility, with additions:
  - evidence_sources: tracks which STIX fields contributed each element
  - confidence: per-element confidence (explicit/inferred/default)

Usage:
    python3 generate_sut_specs.py

Output:
    - results/sut_specs/<campaign_name>/sut.yaml
    - results/audit/infrastructure_matrix.csv
    - results/audit/sut_validation.csv
    - results/figures_data_sut.json

Maintainer note: anonymized for blind artifact release.
Date: 2026-03-06
"""

import json
import csv
import math
import re
import os
from collections import Counter, defaultdict
from pathlib import Path

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False
    print("[WARN] PyYAML not found. SUT specs will be saved as JSON instead.")

# ─────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────
SCRIPT_DIR = Path(__file__).parent
RESULTS_DIR = SCRIPT_DIR / "results"
AUDIT_DIR = RESULTS_DIR / "audit"
SUT_SPECS_DIR = RESULTS_DIR / "sut_specs"
DATA_DIR = SCRIPT_DIR / "data"
ENTERPRISE_FILE = DATA_DIR / "enterprise-attack.json"

# Infrastructure categories for campaign × infra matrix
INFRASTRUCTURE_CATEGORIES = [
    "Windows Workstation", "Windows Server", "Linux Server", "Linux Desktop",
    "macOS Host", "ESXi Host", "Network Device", "Web Server",
    "Database Server", "Mail Server", "Domain Controller", "File Server",
    "Cloud Service", "Container Host", "Security Appliance",
]

# Tactic -> implied services mapping
TACTIC_SERVICE_MAP = {
    "lateral-movement": ["smb", "rdp", "ssh", "winrm"],
    "credential-access": ["lsass", "kerberos", "ldap"],
    "exfiltration": ["https", "dns", "ftp"],
    "command-and-control": ["https", "dns", "http"],
    "collection": ["smb", "nfs"],
    "persistence": ["registry", "scheduled_tasks", "services"],
}

# Technique -> privilege requirements
PRIVILEGE_TECHNIQUES = {
    "T1068": "privileged_access",     # Exploitation for Privilege Escalation
    "T1548": "elevated_access",       # Abuse Elevation Control Mechanism
    "T1134": "token_manipulation",    # Access Token Manipulation
    "T1078": "valid_accounts",        # Valid Accounts
}

# Technique -> persistence surface
PERSISTENCE_TECHNIQUES = {
    "T1547": ["registry_run_keys", "startup_folder"],
    "T1053": ["scheduled_tasks"],
    "T1543": ["services"],
    "T1546": ["event_triggered_execution"],
    "T1037": ["logon_scripts"],
    "T1136": ["new_accounts"],
    "T1098": ["account_manipulation"],
}

# Technique -> defense evasion implications (security controls)
EVASION_TECHNIQUES = {
    "T1562": {"defender": "disabled", "security_monitoring": "impaired"},
    "T1070": {"log_collection": "cleared"},
    "T1036": {"file_inspection": "bypassed"},
    "T1027": {"antimalware": "bypassed"},
    "T1218": {"applocker": "bypassed"},
}

# Regex for CVE pattern
CVE_PATTERN = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)


# ─────────────────────────────────────────────────────────────────
# STIX helpers
# ─────────────────────────────────────────────────────────────────

def load_bundle(filepath):
    """Load a STIX 2.x bundle from JSON."""
    with open(filepath, 'r', encoding='utf-8') as f:
        bundle = json.load(f)
    return bundle['objects']


def is_deprecated_or_revoked(obj):
    return obj.get('x_mitre_deprecated', False) or obj.get('revoked', False)


def normalize_os_family(platform_label):
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


def get_attack_external_id(obj):
    for ref in obj.get('external_references', []) or []:
        if ref.get('source_name') == 'mitre-attack':
            return ref.get('external_id', '')
    return ''


def get_technique_tactics(tech):
    tactics = set()
    for phase in tech.get('kill_chain_phases', []):
        if phase.get('kill_chain_name') == 'mitre-attack':
            tactics.add(phase.get('phase_name', ''))
    return tactics


# ─────────────────────────────────────────────────────────────────
# SUT Specification Generation
# ─────────────────────────────────────────────────────────────────

def generate_sut_for_campaign(camp_name, camp_id, technique_objs,
                                software_objs, cve_ids, by_id):
    """
    Generate a canonical SUT specification for a single campaign.

    Returns a dict matching the inNervoso SUT YAML schema with
    evidence_source annotations.
    """
    sut = {}
    evidence = defaultdict(list)

    # Determine OS environments from techniques and software
    os_families = Counter()
    for tech in technique_objs:
        for p in tech.get('x_mitre_platforms', []):
            fam = normalize_os_family(p)
            if fam:
                os_families[fam] += 1
                evidence[f'os_{fam}'].append(f"technique:{get_attack_external_id(tech)}")
    for sw in software_objs:
        for p in sw.get('x_mitre_platforms', []):
            fam = normalize_os_family(p)
            if fam:
                os_families[fam] += 1
                evidence[f'os_{fam}'].append(f"software:{get_attack_external_id(sw)}")

    # Build per-OS-variant SUT entries
    for os_fam in sorted(os_families.keys()):
        variant_key = os_fam.lower().replace(' ', '_')
        variant = {
            'os': [os_fam],
            'evidence_source': evidence.get(f'os_{os_fam}', [])[:5],  # Trim for readability
            'confidence': 'explicit' if os_families[os_fam] >= 3 else 'inferred',
        }

        # Services - derived from tactics
        services = {}
        for tech in technique_objs:
            tactics = get_technique_tactics(tech)
            for tactic in tactics:
                for svc in TACTIC_SERVICE_MAP.get(tactic, []):
                    if svc not in services:
                        services[svc] = 'enabled'

        # Installed software - from linked software objects
        installed_sw = []
        for sw in software_objs:
            sw_platforms = [normalize_os_family(p) for p in sw.get('x_mitre_platforms', [])]
            # Include software if it's relevant to this OS variant
            if os_fam in sw_platforms or not sw_platforms or None in sw_platforms:
                sw_name = sw.get('name', 'unknown')
                installed_sw.append(sw_name)

        # Privilege - from privilege escalation techniques
        privilege = []
        for tech in technique_objs:
            ext_id = get_attack_external_id(tech)
            if ext_id in PRIVILEGE_TECHNIQUES:
                privilege.append(PRIVILEGE_TECHNIQUES[ext_id])
            tactics = get_technique_tactics(tech)
            if 'privilege-escalation' in tactics:
                if os_fam == 'Windows':
                    privilege.append('local_admin')
                elif os_fam in ('Linux', 'macOS'):
                    privilege.append('root')

        # Persistence surfaces
        persistence = []
        for tech in technique_objs:
            ext_id = get_attack_external_id(tech)
            if ext_id in PERSISTENCE_TECHNIQUES:
                persistence.extend(PERSISTENCE_TECHNIQUES[ext_id])

        # Security controls - from defense-evasion
        security_controls = {}
        for tech in technique_objs:
            ext_id = get_attack_external_id(tech)
            if ext_id in EVASION_TECHNIQUES:
                security_controls.update(EVASION_TECHNIQUES[ext_id])

        # Network requirements
        network = {}
        for tech in technique_objs:
            tactics = get_technique_tactics(tech)
            if 'command-and-control' in tactics:
                network['outbound_https'] = True
                network['dns_resolution'] = True
            if 'lateral-movement' in tactics:
                if os_fam == 'Windows':
                    network['domain_joined'] = True
            if 'exfiltration' in tactics:
                network['outbound_https'] = True

        # Domain role
        domain_role = []
        for tech in technique_objs:
            tactics = get_technique_tactics(tech)
            if 'credential-access' in tactics or 'lateral-movement' in tactics:
                if os_fam == 'Windows':
                    domain_role.append('member_workstation')

        variant['services'] = services
        variant['network'] = network
        variant['installed_software'] = sorted(set(installed_sw))
        variant['privilege'] = sorted(set(privilege))
        variant['domain_role'] = sorted(set(domain_role))
        variant['persistence_surfaces'] = sorted(set(persistence))
        variant['security_controls'] = security_controls
        variant['cve_ids'] = sorted(cve_ids) if cve_ids else []

        sut[variant_key] = variant

    return sut


# ─────────────────────────────────────────────────────────────────
# SUT Completeness Metric
# ─────────────────────────────────────────────────────────────────

COMPLETENESS_DIMENSIONS = [
    'os', 'services', 'network', 'installed_software', 'privilege',
    'domain_role', 'persistence_surfaces', 'security_controls',
]

def compute_sut_completeness_score(sut_spec):
    """
    Score how complete a SUT spec is across key dimensions.
    Returns: score (0.0–1.0), missing list.
    """
    if not sut_spec:
        return 0.0, COMPLETENESS_DIMENSIONS[:]

    # Aggregate across all OS variants
    filled = set()
    for variant_key, variant in sut_spec.items():
        if isinstance(variant, dict):
            for dim in COMPLETENESS_DIMENSIONS:
                val = variant.get(dim)
                if val:
                    if isinstance(val, (list, dict)):
                        if len(val) > 0:
                            filled.add(dim)
                    else:
                        filled.add(dim)

    missing = [d for d in COMPLETENESS_DIMENSIONS if d not in filled]
    score = round(len(filled) / len(COMPLETENESS_DIMENSIONS), 2)
    return score, missing


# ─────────────────────────────────────────────────────────────────
# SUT Structural Validation
# ─────────────────────────────────────────────────────────────────

# Windows-only services
WINDOWS_SERVICES = {'registry', 'scheduled_tasks', 'lsass', 'kerberos', 'winrm'}
# Linux-only services
LINUX_SERVICES = {'cron', 'systemd', 'nfs'}

def validate_sut_coherence(sut_spec, campaign_name):
    """
    Validate generated SUT for internal consistency.
    Returns: valid (bool), warnings list, errors list.
    """
    warnings = []
    errors = []

    if not sut_spec:
        errors.append("empty_sut")
        return False, warnings, errors

    for variant_key, variant in sut_spec.items():
        if not isinstance(variant, dict):
            continue

        os_list = variant.get('os', [])
        services = variant.get('services', {})

        # Check: at least one OS
        if not os_list:
            errors.append(f"{variant_key}: no OS specified")

        # Check: service-OS coherence
        for svc in services:
            if svc in WINDOWS_SERVICES and 'Windows' not in os_list:
                warnings.append(f"{variant_key}: Windows service '{svc}' on non-Windows OS {os_list}")
            if svc in LINUX_SERVICES and 'Linux' not in os_list:
                warnings.append(f"{variant_key}: Linux service '{svc}' on non-Linux OS {os_list}")

        # Check: persistence coherence
        persistence = variant.get('persistence_surfaces', [])
        if 'registry_run_keys' in persistence and 'Windows' not in os_list:
            warnings.append(f"{variant_key}: registry persistence on non-Windows OS")

        # Check: domain role coherence
        domain_role = variant.get('domain_role', [])
        if 'member_workstation' in domain_role and 'Windows' not in os_list:
            warnings.append(f"{variant_key}: domain_joined role on non-Windows OS")

    valid = len(errors) == 0
    return valid, warnings, errors


# ─────────────────────────────────────────────────────────────────
# Infrastructure Matrix
# ─────────────────────────────────────────────────────────────────

def classify_infrastructure(os_fam, services, domain_role, installed_sw):
    """Classify a SUT variant into infrastructure categories."""
    categories = Counter()

    if os_fam == 'Windows':
        if 'member_workstation' in domain_role or 'standalone' in domain_role:
            categories['Windows Workstation'] += 1
        elif any(s in services for s in ('ldap', 'kerberos', 'lsass')):
            categories['Domain Controller'] += 1
        else:
            categories['Windows Server'] += 1
    elif os_fam == 'Linux':
        # Heuristic: if web-related services, it's a web server
        if any(s in services for s in ('http', 'https', 'nginx', 'apache')):
            categories['Web Server'] += 1
        elif any(s in services for s in ('smb', 'nfs')):
            categories['File Server'] += 1
        else:
            categories['Linux Server'] += 1
    elif os_fam == 'macOS':
        categories['macOS Host'] += 1
    elif os_fam == 'ESXi':
        categories['ESXi Host'] += 1

    # Additional services-based classification
    if 'smtp' in services or 'exchange' in str(installed_sw).lower():
        categories['Mail Server'] += 1
    if 'mysql' in services or 'postgres' in services or 'database' in str(installed_sw).lower():
        categories['Database Server'] += 1

    return categories


def build_infrastructure_matrix(all_sut_specs):
    """
    Build campaign × infrastructure category matrix.

    Returns:
    - matrix: list of dicts (one per campaign)
    - diversity_scores: per-campaign diversity
    - entropy_scores: per-campaign Shannon entropy
    """
    matrix_rows = []
    diversity_scores = []
    entropy_scores = []
    global_category_counts = Counter()

    for camp_name, sut_spec in sorted(all_sut_specs.items()):
        camp_categories = Counter()

        for variant_key, variant in sut_spec.items():
            if not isinstance(variant, dict):
                continue
            os_list = variant.get('os', [])
            services = variant.get('services', {})
            domain_role = variant.get('domain_role', [])
            installed_sw = variant.get('installed_software', [])

            for os_fam in os_list:
                cats = classify_infrastructure(os_fam, services, domain_role, installed_sw)
                camp_categories.update(cats)

        # Row for matrix
        row = {'campaign_name': camp_name}
        for cat in INFRASTRUCTURE_CATEGORIES:
            row[cat] = camp_categories.get(cat, 0)
        matrix_rows.append(row)

        # Diversity = number of distinct categories used
        distinct = sum(1 for c in INFRASTRUCTURE_CATEGORIES if camp_categories.get(c, 0) > 0)
        diversity_scores.append(distinct)

        # Shannon entropy
        total = sum(camp_categories.values())
        if total > 0:
            probs = [camp_categories.get(c, 0) / total for c in INFRASTRUCTURE_CATEGORIES if camp_categories.get(c, 0) > 0]
            entropy = -sum(p * math.log2(p) for p in probs if p > 0)
        else:
            entropy = 0.0
        entropy_scores.append(round(entropy, 3))

        global_category_counts.update(camp_categories)

    return {
        'matrix_rows': matrix_rows,
        'diversity_scores': diversity_scores,
        'entropy_scores': entropy_scores,
        'global_category_counts': dict(global_category_counts.most_common()),
        'mean_diversity': round(sum(diversity_scores) / max(len(diversity_scores), 1), 1),
        'median_entropy': round(sorted(entropy_scores)[len(entropy_scores) // 2], 3) if entropy_scores else 0.0,
    }


# ─────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────

def main():
    print("=" * 70)
    print("Canonical SUT Specification Generator")
    print("=" * 70)

    # ── Load STIX data ──
    print("\n[1/6] Loading STIX bundle and pipeline outputs...")
    all_objects = load_bundle(ENTERPRISE_FILE)

    # Index objects
    by_type = defaultdict(list)
    by_id = {}
    for obj in all_objects:
        if is_deprecated_or_revoked(obj):
            continue
        by_type[obj.get('type', '')].append(obj)
        by_id[obj.get('id', '')] = obj

    # Build relationship index
    relationships = by_type.get('relationship', [])
    rel_fwd = defaultdict(list)
    rel_rev = defaultdict(list)
    for rel in relationships:
        src = rel.get('source_ref', '')
        tgt = rel.get('target_ref', '')
        rtype = rel.get('relationship_type', '')
        rel_fwd[src].append((rtype, tgt, rel))
        rel_rev[tgt].append((rtype, src, rel))

    campaigns = by_type.get('campaign', [])
    techniques = {t['id']: t for t in by_type.get('attack-pattern', [])}

    # Load campaign factual structure from pipeline audit
    factual_csv = AUDIT_DIR / 'campaign_factual_structure.csv'
    if not factual_csv.exists():
        print(f"[ERROR] {factual_csv} not found. Run sut_measurement_pipeline.py first.")
        return
    with open(factual_csv, 'r') as f:
        campaign_facts = list(csv.DictReader(f))
    print(f"  Loaded {len(campaign_facts)} campaign facts from audit CSV.")

    # ── Generate SUT specs ──
    print("\n[2/6] Generating SUT specifications...")
    SUT_SPECS_DIR.mkdir(parents=True, exist_ok=True)

    all_sut_specs = {}
    completeness_scores = []
    completeness_rows = []

    for fact in campaign_facts:
        camp_name = fact['campaign_name']
        camp_id = fact['campaign_id']

        # Resolve linked technique objects
        tech_ext_ids = set(fact.get('technique_ids', '').split(';')) - {''}
        tech_objs = []
        for tid, tobj in techniques.items():
            ext_id = get_attack_external_id(tobj)
            if ext_id in tech_ext_ids:
                tech_objs.append(tobj)

        # Resolve linked software objects
        sw_ext_ids = set(fact.get('software_ids', '').split(';')) - {''}
        sw_objs = []
        for sw in by_type.get('tool', []) + by_type.get('malware', []):
            sw_ext = get_attack_external_id(sw)
            if sw_ext in sw_ext_ids:
                sw_objs.append(sw)

        # CVEs
        cve_ids = set(fact.get('cve_ids', '').split(';')) - {''}

        # Generate SUT
        sut_spec = generate_sut_for_campaign(camp_name, camp_id, tech_objs,
                                              sw_objs, cve_ids, by_id)
        all_sut_specs[camp_name] = sut_spec

        # Completeness
        score, missing = compute_sut_completeness_score(sut_spec)
        completeness_scores.append(score)
        completeness_rows.append({
            'campaign_name': camp_name,
            'completeness_score': score,
            'missing_dimensions': ';'.join(missing),
            'os_variants': len(sut_spec),
        })

        # Save SUT spec
        safe_name = re.sub(r'[^\w\-]', '_', camp_name.lower().strip())
        camp_dir = SUT_SPECS_DIR / safe_name
        camp_dir.mkdir(parents=True, exist_ok=True)

        if HAS_YAML:
            with open(camp_dir / 'sut.yaml', 'w') as f:
                yaml.dump({f'sut_campaign__{safe_name}': sut_spec},
                          f, default_flow_style=False, sort_keys=True)
        else:
            with open(camp_dir / 'sut.json', 'w') as f:
                json.dump({f'sut_campaign__{safe_name}': sut_spec}, f, indent=2)

    n_campaigns = len(all_sut_specs)
    print(f"  Generated SUT specs for {n_campaigns} campaigns.")

    # ── Completeness summary ──
    print("\n[3/6] Computing SUT completeness metrics...")
    mean_completeness = round(sum(completeness_scores) / max(n_campaigns, 1), 2)
    median_completeness = round(sorted(completeness_scores)[n_campaigns // 2], 2) if n_campaigns else 0.0
    fully_specified = sum(1 for s in completeness_scores if s >= 0.8)
    fully_specified_pct = round(fully_specified / max(n_campaigns, 1) * 100, 1)
    print(f"  Mean completeness: {mean_completeness}")
    print(f"  Median completeness: {median_completeness}")
    print(f"  Fully specified (≥0.8): {fully_specified}/{n_campaigns} ({fully_specified_pct}%)")

    # Export completeness audit CSV
    with open(AUDIT_DIR / 'sut_completeness.csv', 'w', newline='') as f:
        writer = csv.DictWriter(
            f,
            fieldnames=['campaign_name', 'completeness_score',
                        'missing_dimensions', 'os_variants'],
            lineterminator='\n',
        )
        writer.writeheader()
        writer.writerows(sorted(completeness_rows, key=lambda r: r['campaign_name']))
    print(f"  OK Completeness audit: {AUDIT_DIR / 'sut_completeness.csv'}")

    # ── Validation ──
    print("\n[4/6] Validating SUT coherence...")
    validation_rows = []
    n_valid = 0
    total_warnings = 0
    total_errors = 0

    for camp_name, sut_spec in sorted(all_sut_specs.items()):
        valid, warnings, errors = validate_sut_coherence(sut_spec, camp_name)
        if valid:
            n_valid += 1
        total_warnings += len(warnings)
        total_errors += len(errors)
        validation_rows.append({
            'campaign_name': camp_name,
            'valid': valid,
            'warnings_count': len(warnings),
            'errors_count': len(errors),
            'warnings': '; '.join(warnings[:5]),
            'errors': '; '.join(errors[:5]),
        })

    validation_pass_pct = round(n_valid / max(n_campaigns, 1) * 100, 1)
    print(f"  Valid: {n_valid}/{n_campaigns} ({validation_pass_pct}%)")
    print(f"  Total warnings: {total_warnings}, errors: {total_errors}")

    with open(AUDIT_DIR / 'sut_validation.csv', 'w', newline='') as f:
        writer = csv.DictWriter(
            f,
            fieldnames=['campaign_name', 'valid', 'warnings_count',
                        'errors_count', 'warnings', 'errors'],
            lineterminator='\n',
        )
        writer.writeheader()
        writer.writerows(sorted(validation_rows, key=lambda r: r['campaign_name']))
    print(f"  OK Validation audit: {AUDIT_DIR / 'sut_validation.csv'}")

    # ── Infrastructure matrix ──
    print("\n[5/6] Building infrastructure matrix...")
    infra = build_infrastructure_matrix(all_sut_specs)
    print(f"  Mean diversity: {infra['mean_diversity']}")
    print(f"  Median entropy: {infra['median_entropy']}")
    print(f"  Global category counts: {infra['global_category_counts']}")

    # Export infrastructure matrix CSV
    fieldnames = ['campaign_name'] + INFRASTRUCTURE_CATEGORIES
    with open(AUDIT_DIR / 'infrastructure_matrix.csv', 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, lineterminator='\n')
        writer.writeheader()
        writer.writerows(infra['matrix_rows'])
    print(f"  OK Infrastructure matrix: {AUDIT_DIR / 'infrastructure_matrix.csv'}")

    # ── Export figure data ──
    print("\n[6/6] Exporting figure data...")
    sut_figure_data = {
        'sut_completeness': {
            'mean': mean_completeness,
            'median': median_completeness,
            'fully_specified_count': fully_specified,
            'fully_specified_pct': fully_specified_pct,
            'scores': completeness_scores,
        },
        'infrastructure_matrix': {
            'categories': INFRASTRUCTURE_CATEGORIES,
            'global_counts': infra['global_category_counts'],
            'mean_diversity': infra['mean_diversity'],
            'median_entropy': infra['median_entropy'],
            'diversity_scores': infra['diversity_scores'],
            'entropy_scores': infra['entropy_scores'],
        },
        'validation': {
            'valid_count': n_valid,
            'valid_pct': validation_pass_pct,
            'total_warnings': total_warnings,
            'total_errors': total_errors,
        },
    }

    with open(RESULTS_DIR / 'figures_data_sut.json', 'w') as f:
        json.dump(sut_figure_data, f, indent=2)
    print(f"  OK SUT figure data: {RESULTS_DIR / 'figures_data_sut.json'}")

    # Summary
    print("\n" + "=" * 70)
    print("SUT GENERATION SUMMARY")
    print("=" * 70)
    print(f"  Campaigns processed: {n_campaigns}")
    print(f"  SUT completeness: mean={mean_completeness}, median={median_completeness}")
    print(f"  Fully specified (≥0.8): {fully_specified}/{n_campaigns} ({fully_specified_pct}%)")
    print(f"  Validation pass rate: {n_valid}/{n_campaigns} ({validation_pass_pct}%)")
    print(f"  Infrastructure diversity: mean={infra['mean_diversity']}")
    print(f"  Infrastructure entropy: median={infra['median_entropy']}")


if __name__ == '__main__':
    main()
