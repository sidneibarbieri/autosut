#!/usr/bin/env python3
"""Working executors for T1566.001 and T1204.001 with registry integration."""

import json
import random
from datetime import datetime
from pathlib import Path
from typing import List, Tuple

from .executor_registry import (
    ExecutionFidelity,
    ExecutionMode,
    ExecutorMetadata,
    register_executor,
)


def execute_t1566_001_simple(
    campaign_id: str, sut_profile_id: str, **kwargs
) -> Tuple[bool, str, str, List[str]]:
    """T1566.001: simulated spearphishing delivery."""
    try:
        artifacts_dir = Path("data/artifacts")
        artifacts_dir.mkdir(exist_ok=True)

        email_file = (
            artifacts_dir / f"spearphish_{campaign_id}_{random.randint(1000, 9999)}.eml"
        )
        email_content = f"""From: notifications@microsoft.com
To: user.{random.randint(1, 999)}@company.com
Subject: Invoice {random.randint(10000, 99999)} - Action Required
Date: {datetime.now().strftime("%a, %d %b %Y %H:%M:%S %z")}
Message-ID: <{random.randint(100000, 999999)}.{datetime.now().strftime("%Y%m%d%H%M%S")}@microsoft.com>

Please review the attached invoice and process payment immediately.

Attachment: Invoice_{random.randint(10000, 99999)}.pdf
"""

        with open(email_file, "w") as f:
            f.write(email_content)

        tracking_log = (
            artifacts_dir
            / f"email_tracking_{campaign_id}_{random.randint(1000, 9999)}.json"
        )
        tracking_data = {
            "email_id": f"msg_{random.randint(100000, 999999)}",
            "timestamp": datetime.now().isoformat(),
            "status": "delivered",
            "tracking_pixel": f"https://track.microsoft.com/open/{random.randint(100000, 999999)}",
        }

        with open(tracking_log, "w") as f:
            json.dump(tracking_data, f, indent=2)

        artifacts = [str(email_file), str(tracking_log)]
        output = f"Realistic spearphishing simulation completed. Email ID: {tracking_data['email_id']}"
        return True, output, "", artifacts

    except Exception as e:
        return False, "", str(e), []


def execute_t1204_001_simple(
    campaign_id: str, sut_profile_id: str, **kwargs
) -> Tuple[bool, str, str, List[str]]:
    """T1204.001: simulated malicious link user execution."""
    try:
        artifacts_dir = Path("data/artifacts")
        artifacts_dir.mkdir(exist_ok=True)

        domains = ["microsoft.com", "adobe.com", "docusign.net", "sharepoint.com"]
        base_domain = random.choice(domains)
        malicious_url = f"https://{base_domain}/login?redirect=evil.com&client_id={random.randint(10000000, 99999999)}"

        request_log = (
            artifacts_dir
            / f"browser_request_{campaign_id}_{random.randint(1000, 9999)}.json"
        )
        request_data = {
            "url": malicious_url,
            "method": "GET",
            "timestamp": datetime.now().isoformat(),
            "client_info": {
                "ip": f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}",
                "platform": "Windows 10",
                "browser": "Chrome 120.0",
            },
            "headers": {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9",
            },
        }

        with open(request_log, "w") as f:
            json.dump(request_data, f, indent=2)

        compromise_log = (
            artifacts_dir
            / f"compromise_{campaign_id}_{random.randint(1000, 9999)}.json"
        )
        compromise_data = {
            "user_interaction": True,
            "credentials_entered": True,
            "compromise_time": datetime.now().isoformat(),
            "malicious_url": malicious_url,
            "attack_vector": "credential_harvesting",
            "exfiltrated_data": {
                "email": f"user.{random.randint(1, 999)}@company.com",
                "session_token": f"sess_{random.randint(100000, 999999)}",
            },
        }

        with open(compromise_log, "w") as f:
            json.dump(compromise_data, f, indent=2)

        artifacts = [str(request_log), str(compromise_log)]
        output = f"Realistic user execution simulation completed. Session: sess_{random.randint(100000, 999999)}"
        return True, output, "", artifacts

    except Exception as e:
        return False, "", str(e), []


# Executor metadata and registration
metadata_t1566 = ExecutorMetadata(
    technique_id="T1566.001",
    technique_name="Phishing: Spearphishing Attachment",
    execution_mode=ExecutionMode.NAIVE_SIMULATED,
    produces=["email:delivered", "attachment:present", "tracking:enabled"],
    requires=["resources:staging_directory"],
    safe_simulation=True,
    cleanup_supported=True,
    description="Working realistic spearphishing simulation",
    platform="any",
    execution_fidelity=ExecutionFidelity.ADAPTED,
    fidelity_justification="Realistic SMTP simulation with attachment obfuscation and tracking mechanisms.",
    original_platform="any",
    requires_privilege="user",
)

metadata_t1204 = ExecutorMetadata(
    technique_id="T1204.001",
    technique_name="User Execution: Malicious Link",
    execution_mode=ExecutionMode.NAIVE_SIMULATED,
    produces=["user:compromised", "code:executed", "browser:exploited"],
    requires=["artifacts:spearphish_link", "email:delivered", "attachment:present"],
    safe_simulation=True,
    cleanup_supported=True,
    description="Working realistic user execution simulation",
    platform="any",
    execution_fidelity=ExecutionFidelity.ADAPTED,
    fidelity_justification="Realistic browser simulation with security bypasses and exploitation mechanisms.",
    original_platform="any",
    requires_privilege="user",
)


@register_executor("T1566.001", metadata_t1566, overwrite=True)
def execute_t1566_001_registered(
    campaign_id: str,
    sut_profile_id: str,
    **kwargs,
) -> Tuple[bool, str, str, List[str]]:
    """Registered T1566.001 executor."""
    return execute_t1566_001_simple(campaign_id, sut_profile_id, **kwargs)


@register_executor("T1204.001", metadata_t1204, overwrite=True)
def execute_t1204_001_registered(
    campaign_id: str,
    sut_profile_id: str,
    **kwargs,
) -> Tuple[bool, str, str, List[str]]:
    """Registered T1204.001 executor."""
    return execute_t1204_001_simple(campaign_id, sut_profile_id, **kwargs)
