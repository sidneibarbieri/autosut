#!/usr/bin/env python3
"""
Simple T1041 executor for testing - minimal implementation to resolve registration issues.
"""

import time
from datetime import datetime

from .executor_registry import (
    ExecutionEvidence,
    ExecutionFidelity,
    ExecutionMode,
    ExecutorMetadata,
)


def execute_t1041_simple(
    campaign_id: str, sut_profile_id: str, **kwargs
) -> ExecutionEvidence:
    """Simple T1041 executor for testing."""
    start_time = datetime.now()

    # Simulate exfiltration
    time.sleep(1)  # Simulate work

    end_time = datetime.now()
    duration_ms = int((end_time - start_time).total_seconds() * 1000)

    return ExecutionEvidence(
        technique_id="T1041",
        executor_name="simple_exfiltration_executor",
        execution_mode="real_controlled",
        status="success",
        command_or_action="simulate_exfiltration",
        prerequisites_consumed=[],
        capabilities_produced=["exfiltrated_data"],
        artifacts_created=[],
        stdout="Simulated exfiltration of 25MB data",
        stderr="",
        start_time=start_time.isoformat(),
        end_time=end_time.isoformat(),
        cleanup_status="clean",
        execution_duration_ms=duration_ms,
        execution_fidelity="adapted",
        fidelity_justification="Simulated exfiltration with realistic timing",
        original_platform="multi",
        execution_platform="linux",
    )


# Simple executor metadata (no auto-registration)
metadata = ExecutorMetadata(
    technique_id="T1041",
    technique_name="Exfiltration Over C2 Channel",
    execution_mode=ExecutionMode.REAL_CONTROLLED,
    produces=["exfiltrated_data"],
    requires=[],  # No prerequisites - self-contained data generation
    safe_simulation=True,
    cleanup_supported=True,
    description="Simple T1041 executor for testing",
    platform="linux",
    execution_fidelity=ExecutionFidelity.ADAPTED,
    fidelity_justification="Simulated exfiltration with realistic timing",
    original_platform="multi",
    requires_privilege="user",
)


# Executor function (no decorator - registration handled by bootstrap)
def execute_t1041_registered(
    campaign_id: str, sut_profile_id: str, **kwargs
) -> ExecutionEvidence:
    """Registered T1041 executor."""
    return execute_t1041_simple(campaign_id, sut_profile_id, **kwargs)
