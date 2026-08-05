#!/usr/bin/env python3
"""
Generate separated corpus tables for the paper methodology.
Campaign Objects (Primary Corpus) vs Intrusion Set Profiles (Extended Validation)
"""

import subprocess
import json
from pathlib import Path
from datetime import datetime

# Campaign Objects - Primary Corpus (methodologically precise)
CAMPAIGN_OBJECTS = [
    ("0.c0010", "C0010", "ATT&CK Campaign"),
    ("0.c0011", "C0011", "Transparent Tribe"),
    ("0.c0015", "C0015", "ATT&CK Campaign"),
    ("0.c0017", "C0017", "ATT&CK Campaign"),
    ("0.c0018", "C0018", "ATT&CK Campaign"),
    ("0.c0021", "C0021", "ATT&CK Campaign"),
    ("0.c0026", "C0026", "ATT&CK Campaign"),
    ("0.c0027", "C0027", "ATT&CK Campaign"),
    ("0.pikabot_realistic", "C0036", "Pikabot Feb 2024"),
    ("0.shadowray", "C0045", "ShadowRay AI/ML Attack"),
    ("0.c0047", "C0047", "RedDelta Modified PlugX"),
]

# Intrusion Set Profiles - Extended Validation (behaviorally sparser)
INTRUSION_SETS = [
    ("0.fox_kitten", "G0117", "Fox Kitten"),
]

def run_campaign(campaign_id):
    """Execute campaign and return results."""
    try:
        result = subprocess.run(
            ["python3", "scripts/run_campaign.py", "--campaign", campaign_id],
            capture_output=True, text=True, timeout=120,
            cwd=Path(__file__).parent.parent
        )
        output = result.stdout + result.stderr

        total = successful = failed = 0
        for line in output.split('\n'):
            if "Total:" in line:
                total = int(line.split(":")[1].strip())
            elif "Successful:" in line:
                successful = int(line.split(":")[1].strip())
            elif "Failed:" in line:
                failed = int(line.split(":")[1].strip())

        return total, successful, failed, output
    except subprocess.TimeoutExpired:
        return 0, 0, 0, "TIMEOUT"
    except Exception as e:
        return 0, 0, 0, f"ERROR: {e}"

def generate_corpus_table():
    """Generate separated corpus results."""
    print("=== METHODOLOGY: SEPARATED CORPUS ===")
    print()

    # Campaign Objects - Primary Corpus
    print("CAMPAIGN OBJECTS (Primary Corpus)")
    print("=" * 80)
    print(f"{'MITRE ID':<8} {'Campaign Name':<35} {'Result':<12} {'Coverage'}")
    print("-" * 80)

    campaign_results = []
    campaign_total = campaign_successful = 0

    for campaign_id, mitre_id, name in CAMPAIGN_OBJECTS:
        total, successful, failed, output = run_campaign(campaign_id)
        coverage = f"{successful}/{total}" if total > 0 else "0/0"
        pct = (successful/total*100) if total > 0 else 0

        print(f"{mitre_id:<8} {name:<35} {coverage:<12} {pct:.0f}%")

        campaign_results.append({
            "campaign_id": campaign_id,
            "mitre_id": mitre_id,
            "name": name,
            "total": total,
            "successful": successful,
            "failed": failed,
            "success_rate": pct,
            "type": "campaign_object"
        })

        campaign_total += total
        campaign_successful += successful

    print("-" * 80)
    campaign_coverage = f"{campaign_successful}/{campaign_total}"
    campaign_rate = (campaign_successful/campaign_total*100) if campaign_total > 0 else 0
    print(f"{'CAMPAIGNS':<8} {'11 Campaign Objects':<35} {campaign_coverage:<12} {campaign_rate:.1f}%")
    print()

    # Intrusion Set Profiles - Extended Validation
    print("INTRUSION SET PROFILES (Extended Validation)")
    print("=" * 80)
    print(f"{'Group ID':<8} {'Profile Name':<35} {'Result':<12} {'Coverage'}")
    print("-" * 80)

    intrusion_results = []
    intrusion_total = intrusion_successful = 0

    for campaign_id, group_id, name in INTRUSION_SETS:
        total, successful, failed, output = run_campaign(campaign_id)
        coverage = f"{successful}/{total}" if total > 0 else "0/0"
        pct = (successful/total*100) if total > 0 else 0

        print(f"{group_id:<8} {name:<35} {coverage:<12} {pct:.0f}%")

        intrusion_results.append({
            "campaign_id": campaign_id,
            "mitre_id": group_id,
            "name": name,
            "total": total,
            "successful": successful,
            "failed": failed,
            "success_rate": pct,
            "type": "intrusion_set"
        })

        intrusion_total += total
        intrusion_successful += successful

    print("-" * 80)
    intrusion_coverage = f"{intrusion_successful}/{intrusion_total}"
    intrusion_rate = (intrusion_successful/intrusion_total*100) if intrusion_total > 0 else 0
    print(f"{'PROFILES':<8} {'1 Intrusion Set':<35} {intrusion_coverage:<12} {intrusion_rate:.1f}%")
    print()

    # Overall Summary
    print("OVERALL METHODOLOGICAL SUMMARY")
    print("=" * 80)
    total_techniques = campaign_total + intrusion_total
    total_successful = campaign_successful + intrusion_successful
    overall_rate = (total_successful/total_techniques*100) if total_techniques > 0 else 0

    print(f"Primary Corpus: {len(CAMPAIGN_OBJECTS)} campaign objects, {campaign_coverage} ({campaign_rate:.1f}%)")
    print(f"Extended Validation: {len(INTRUSION_SETS)} intrusion sets, {intrusion_coverage} ({intrusion_rate:.1f}%)")
    print(f"Combined: {total_successful}/{total_techniques} ({overall_rate:.1f}%)")
    print()

    # Save results
    results = {
        "generated_at": datetime.now().isoformat(),
        "methodology": "separated_corpus",
        "primary_corpus": {
            "type": "campaign_objects",
            "description": "ATT&CK Enterprise campaign objects - methodologically precise",
            "campaigns": campaign_results,
            "summary": {
                "count": len(campaign_results),
                "total_techniques": campaign_total,
                "successful_techniques": campaign_successful,
                "success_rate": campaign_rate
            }
        },
        "extended_validation": {
            "type": "intrusion_set_profiles",
            "description": "Intrusion set profiles - behaviorally sparser CTI representations",
            "campaigns": intrusion_results,
            "summary": {
                "count": len(intrusion_results),
                "total_techniques": intrusion_total,
                "successful_techniques": intrusion_successful,
                "success_rate": intrusion_rate
            }
        },
        "overall": {
            "total_campaigns": len(campaign_results) + len(intrusion_results),
            "total_techniques": total_techniques,
            "successful_techniques": total_successful,
            "overall_success_rate": overall_rate
        }
    }

    # Save JSON
    output_file = Path("release/separated_corpus_results.json")
    output_file.write_text(json.dumps(results, indent=2))
    print(f"Results saved to: {output_file}")

    # Generate LaTeX tables
    latex_campaign = generate_latex_campaign_table(campaign_results)
    latex_intrusion = generate_latex_intrusion_table(intrusion_results)

    latex_file = Path("release/separated_corpus_tables.tex")
    with open(latex_file, 'w') as f:
        f.write("% Campaign Objects - Primary Corpus\n")
        f.write(latex_campaign)
        f.write("\n\n% Intrusion Set Profiles - Extended Validation\n")
        f.write(latex_intrusion)

    print(f"LaTeX tables saved to: {latex_file}")

    return results

def generate_latex_campaign_table(results):
    """Generate LaTeX table for campaign objects."""
    table = """\\begin{table}[htbp]
\\centering
\\caption{Campaign Objects - Primary Corpus}
\\label{tab:campaign-objects}
\\begin{tabular}{lcccc}
\\toprule
Campaign ID & Name & Techniques & Successful & Success Rate \\\\
\\midrule
"""

    for result in results:
        campaign_name = result['campaign_id'].replace('0.', '').replace('_', ' ').title()
        table += f"{result['mitre_id']} & {campaign_name:<25} & {result['total']:>2} & {result['successful']:>2} & {result['success_rate']:.0f}% \\\\\n"

    table += """\\bottomrule
\\end{tabular}
\\end{table}
"""
    return table

def generate_latex_intrusion_table(results):
    """Generate LaTeX table for intrusion set profiles."""
    table = """\\begin{table}[htbp]
\\centering
\\caption{Intrusion Set Profiles - Extended Validation}
\\label{tab:intrusion-sets}
\\begin{tabular}{lcccc}
\\toprule
Group ID & Profile Name & Techniques & Successful & Success Rate \\\\
\\midrule
"""

    for result in results:
        profile_name = result['campaign_id'].replace('0.', '').replace('_', ' ').title()
        table += f"{result['mitre_id']} & {profile_name:<25} & {result['total']:>2} & {result['successful']:>2} & {result['success_rate']:.0f}% \\\\\n"

    table += """\\bottomrule
\\end{tabular}
\\end{table}
"""
    return table

if __name__ == "__main__":
    generate_corpus_table()
