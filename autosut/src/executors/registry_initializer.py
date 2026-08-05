#!/usr/bin/env python3
"""Deterministic executor registry bootstrap."""

from importlib import import_module
from typing import List

from .executor_registry import registry

_INITIALIZED = False

MODULES_TO_LOAD: List[str] = [
    "executors.simple_working_executors",
    "executors.legacy_campaign_executors",
    "executors.campaign_expansion_executors",
    "executors.extended_campaign_executors",
    "executors.simple_working_executors_shadowray",
    "executors.working_executors",
    "executors.shadowray_additional_executors",
    "executors.fox_kitten_real",
    "executors.shadowray_fixed_executors",
    "executors.privilege_escalation_executors",
    "executors.simple_t1041_executor",
]

EXPECTED_MIN_EXECUTORS = 20


def initialize_registry(force: bool = False) -> None:
    """Import all executor modules exactly once and assert registry population."""
    global _INITIALIZED
    if _INITIALIZED and not force:
        return

    for module_path in MODULES_TO_LOAD:
        import_module(module_path)

    total = len(registry.list_available())
    if total < EXPECTED_MIN_EXECUTORS:
        raise RuntimeError(
            f"Registry initialization incomplete: expected >= {EXPECTED_MIN_EXECUTORS} executors, found {total}"
        )

    _INITIALIZED = True
