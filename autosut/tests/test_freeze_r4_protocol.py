"""A predeclared R4 template becomes executable only after immutable revision binding."""

from __future__ import annotations

import hashlib
import importlib.util
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = PROJECT_ROOT / "scripts" / "freeze_r4_protocol.py"


def _module():
    spec = importlib.util.spec_from_file_location("freeze_r4_protocol", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _template() -> dict:
    return {
        "schema_version": "r4-interruption-protocol/v2",
        "protocol_id": "r4-template-test",
        "status": "predeclared_before_execution",
        "execution_requirements": {
            "execution_mode": "supervised",
            "evidence_role": "qualification",
            "implementation_revision": "immutable_clean_commit",
            "topology": "isolated_caldera_docker",
            "manifest_validation": "required",
        },
        "cells": [
            {
                "id": "R4V2-test",
                "stage": "enroll_agent",
                "condition": "enrollment_poll_active",
                "injection": "sigterm",
                "property": "test",
            }
        ],
    }


def test_freeze_binds_the_exact_template_hash_and_clean_commit():
    module = _module()
    template = _template()
    raw = b'{"template":"bytes"}'
    frozen = module.freeze_protocol(
        template,
        template_sha256=hashlib.sha256(raw).hexdigest(),
        revision="a" * 40,
    )

    assert frozen["status"] == "frozen_for_execution"
    assert frozen["frozen_revision"] == "a" * 40
    assert frozen["template_sha256"] == hashlib.sha256(raw).hexdigest()
    assert template["status"] == "predeclared_before_execution"


def test_freeze_rejects_nonpredeclared_template_or_dirty_revision():
    module = _module()
    template = _template()
    template["status"] = "frozen_for_execution"
    try:
        module.freeze_protocol(template, template_sha256="b" * 64, revision="a" * 40)
    except ValueError as error:
        assert "predeclared" in str(error)
    else:
        raise AssertionError("a frozen template must not be overwritten")

    try:
        module.freeze_protocol(_template(), template_sha256="b" * 64, revision="not-a-commit")
    except ValueError as error:
        assert "40-character" in str(error)
    else:
        raise AssertionError("a non-commit revision must fail")
