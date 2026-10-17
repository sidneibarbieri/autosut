"""Receipt audits recompute resource predicates from retained observations."""

import importlib.util
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/audit_corpus_resource_witnesses.py"
SPEC = importlib.util.spec_from_file_location("audit_corpus_resource_witnesses", SCRIPT)
audit_module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = audit_module
SPEC.loader.exec_module(audit_module)


def _receipt() -> dict:
    digest = "a" * 64
    return {
        "required_resources": ["controlled-ingress-channel"],
        "observations": {
            "controlled-ingress-channel": {
                "source_sha256": digest,
                "destination_sha256": digest,
                "server_log": '172.20.0.2 - - "GET /fixture HTTP/1.1" 200 -',
                "request_observed": True,
            }
        },
        "gateway": {
            "host_gateway_access": "blocked_observed",
            "positive_before_rule": True,
            "listener_live_after_rule": True,
            "dropped_packets": 2,
        },
        "network_internal": True,
        "teardown_clean": True,
        "resource_witnessed": True,
        "campaign_executed": False,
    }


def test_recomputes_ingress_log_and_hashes() -> None:
    audit_module.audit_network_receipt(_receipt(), ("controlled-ingress-channel",))


def test_missing_raw_request_log_is_rejected() -> None:
    receipt = _receipt()
    receipt["observations"]["controlled-ingress-channel"]["server_log"] = ""
    with pytest.raises(ValueError, match="request log"):
        audit_module.audit_network_receipt(receipt, ("controlled-ingress-channel",))


def test_campaign_execution_claim_is_rejected() -> None:
    receipt = _receipt()
    receipt["campaign_executed"] = True
    with pytest.raises(ValueError, match="campaign execution"):
        audit_module.audit_network_receipt(receipt, ("controlled-ingress-channel",))
