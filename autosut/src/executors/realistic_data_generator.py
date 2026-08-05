#!/usr/bin/env python3
"""
Realistic data generator for STICKS campaigns.
Generates plausible corporate files, logs, and credentials for exfiltration simulation.
"""

import json
import os
import random
import string
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List

def generate_realistic_files(target_dir: Path, campaign_id: str) -> None:
    """Generate realistic files for exfiltration with plausible content."""
    target_dir.mkdir(parents=True, exist_ok=True)

    # Corporate documents with realistic structure
    docs = {
        "quarterly_report_Q4_2024.docx": generate_document(),
        "employee_list_2024.xlsx": generate_employee_list(),
        "financial_projections_2025.pdf": generate_financial_data(),
        "customer_database_backup.sql": generate_customer_data(),
        "api_keys_production.json": generate_api_keys(),
        "ssh_keys.tar.gz": generate_ssh_keys(),
        "application_logs_2024-12.log": generate_app_logs(),
        "system_audit_report.txt": generate_audit_report(),
    }

    for filename, content in docs.items():
        filepath = target_dir / filename
        if isinstance(content, bytes):
            filepath.write_bytes(content)
        else:
            filepath.write_text(content, encoding='utf-8')
        # Set realistic permissions and timestamps
        filepath.chmod(0o644)
        # Random modification time within last 30 days
        days_ago = random.randint(1, 30)
        timestamp = datetime.now() - timedelta(days=days_ago)
        os.utime(filepath, (timestamp.timestamp(), timestamp.timestamp()))

def generate_document() -> str:
    """Generate realistic corporate document content."""
    return """QUARTERLY REPORT Q4 2024
====================================

Executive Summary:
- Revenue increased by 23% YoY to $45.2M
- Customer acquisition cost reduced by 15%
- Operating margin improved to 18.7%

Key Metrics:
- Active users: 1,247,892
- Conversion rate: 3.4%
- Churn rate: 2.1%

Confidential - For Internal Use Only
Generated: {date}
""".format(date=datetime.now().strftime('%Y-%m-%d'))

def generate_employee_list() -> str:
    """Generate realistic employee data."""
    departments = ['Engineering', 'Sales', 'Marketing', 'HR', 'Finance']
    employees = []

    for i in range(50):
        emp = {
            'id': f'EMP{1000+i}',
            'name': f'Employee_{i}',
            'email': f'emp{i}@company.com',
            'department': random.choice(departments),
            'salary': random.randint(60000, 180000),
            'start_date': f'202{random.randint(0,4)}-{random.randint(1,12):02d}-{random.randint(1,28):02d}'
        }
        employees.append(emp)

    return json.dumps(employees, indent=2)

def generate_financial_data() -> str:
    """Generate realistic financial projections."""
    data = {
        'revenue_projections': {
            'Q1_2025': 12.3,
            'Q2_2025': 13.7,
            'Q3_2025': 14.2,
            'Q4_2025': 15.8
        },
        'expenses': {
            'engineering': 8.2,
            'sales': 4.1,
            'marketing': 2.3,
            'operations': 3.7
        },
        'profit_margin': '18.7%'
    }
    return json.dumps(data, indent=2)

def generate_customer_data() -> str:
    """Generate realistic customer database backup."""
    customers = []
    for i in range(100):
        customer = {
            'id': f'CUST{5000+i}',
            'name': f'Customer_{i}',
            'email': f'customer{i}@client.com',
            'phone': f'+1-555-{random.randint(100,999)}-{random.randint(1000,9999)}',
            'address': f'{random.randint(100,999)} Main St, City, ST {random.randint(10000,99999)}',
            'signup_date': f'202{random.randint(0,4)}-{random.randint(1,12):02d}-{random.randint(1,28):02d}',
            'total_purchases': random.uniform(100.0, 50000.0)
        }
        customers.append(customer)

    return "-- Customer Database Backup --\n" + json.dumps(customers, indent=2)

def generate_api_keys() -> str:
    """Generate realistic API keys (obfuscated for security)."""
    return """{
    "production": {
        "stripe": "STRIPE_EXAMPLE_REDACTED",
        "aws": "AWS_EXAMPLE_REDACTED",
        "sendgrid": "SENDGRID_EXAMPLE_REDACTED"
    },
    "staging": {
        "stripe": "STRIPE_TEST_EXAMPLE_REDACTED",
        "aws": "AWS_TEST_EXAMPLE_REDACTED"
    }
}"""

def generate_ssh_keys() -> bytes:
    """Generate realistic SSH key bundle (simulated)."""
    # This would be a real tar.gz in production
    content = """id_rsa_simulated:
SIMULATED OPENSSH KEY MATERIAL -- NOT REAL SECRET MATERIAL
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAIEA2K8Qx...[REDACTED]
END SIMULATED OPENSSH KEY MATERIAL

id_rsa.pub:
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDYrxDE... user@host

authorized_keys:
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDYrxDE... user@host"""
    return content.encode('utf-8')

def generate_app_logs() -> str:
    """Generate realistic application logs."""
    logs = []
    base_time = datetime.now() - timedelta(days=7)

    for i in range(1000):
        timestamp = base_time + timedelta(minutes=i*10)
        level = random.choice(['INFO', 'WARN', 'ERROR', 'DEBUG'])
        message = random.choice([
            'User login successful',
            'Database connection established',
            'API request processed',
            'Cache miss for key',
            'Payment processed',
            'Failed authentication attempt',
            'Service health check passed'
        ])

        log_entry = f"{timestamp.isoformat()} {level} {message}\n"
        logs.append(log_entry)

    return ''.join(logs)

def generate_audit_report() -> str:
    """Generate realistic system audit report."""
    return """SYSTEM AUDIT REPORT
==================

Date: {date}
Auditor: Security Team
Scope: Production Infrastructure

Findings:
1. SSH keys with weak permissions - LOW RISK
2. Outdated SSL certificates - MEDIUM RISK
3. Exposed API documentation - LOW RISK

Recommendations:
- Rotate SSH keys quarterly
- Update SSL certificates before expiry
- Restrict API documentation access

Compliance: 87% (Target: 95%)
""".format(date=datetime.now().strftime('%Y-%m-%d'))

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Generate realistic data for campaigns")
    parser.add_argument("--target-dir", required=True, help="Target directory for files")
    parser.add_argument("--campaign-id", required=True, help="Campaign ID for context")

    args = parser.parse_args()

    target_path = Path(args.target_dir)
    generate_realistic_files(target_path, args.campaign_id)

    print(f"Generated realistic files in {target_path}")
    print(f"Files created: {len(list(target_path.iterdir()))}")
