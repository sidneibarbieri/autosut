from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODULE_PATH = PROJECT_ROOT / "scripts" / "generate_compatibility_rule_surface.py"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "sticks_generate_compatibility_rule_surface",
        MODULE_PATH,
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_report_payload_exposes_rule_keywords_and_regexes() -> None:
    module = _load_module()
    pipeline = module._load_pipeline_module()

    payload = module._report_payload(pipeline)

    assert "Windows Domain" in payload["id_platform_keywords"]
    assert "kerberos" in payload["lateral_software_keywords"]
    assert "boot|firmware|kernel" in payload["kernel_boot_regex"]
    assert "lsass" in payload["vmr_name_regex"]
    assert payload["default_fallback_class"] == "VMR"
    assert payload["policy_labels"] == ["CF", "VMR", "ID"]
    assert "routing-policy label" in payload["label_semantics"]
    assert "not an observed minimum-backend" in payload["label_semantics"]
    assert "manual-label packet" in payload["manual_validation_requirement"]
