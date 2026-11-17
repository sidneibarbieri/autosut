"""Qualify the local planning boundary without provisioning infrastructure."""

from __future__ import annotations
import hashlib
import http.client
import json
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path
import pytest
from planning.environment_workbench import plan_environment
from planning.environment_workbench_http import build_handler

ROOT = Path(__file__).resolve().parents[1]
PLAN = ROOT / "release/inputs/sticks/c0045-v1/C0045.procedural-plan.json"


@pytest.fixture
def server():
    instance = ThreadingHTTPServer(("127.0.0.1", 0), build_handler(ROOT))
    thread = threading.Thread(target=instance.serve_forever, daemon=True)
    thread.start()
    yield instance
    instance.shutdown()
    instance.server_close()
    thread.join(timeout=5)


def request(server, method, path, body=None, headers=None):
    connection = http.client.HTTPConnection(*server.server_address, timeout=10)
    connection.request(method, path, body=body, headers=headers or {})
    response = connection.getresponse()
    status, data = response.status, response.read()
    connection.close()
    return status, data


def test_http_matches_shared_cli_service(server):
    status, data = request(
        server,
        "POST",
        "/api/plan",
        PLAN.read_bytes(),
        {"Content-Type": "application/json"},
    )
    assert status == 200
    assert json.loads(data) == plan_environment(PLAN).model_dump(mode="json")
    assert json.loads(data)["operational_status"] == "not_run"


def test_example_is_the_actual_pinned_plan(server):
    status, data = request(server, "GET", "/api/example")
    assert status == 200
    assert json.loads(data) == json.loads(PLAN.read_text())


def test_changed_plan_fails_hash_gate(server):
    payload = json.loads(PLAN.read_text())
    payload["campaign_name"] = "changed"
    status, data = request(server, "POST", "/api/plan", json.dumps(payload))
    assert status == 400
    assert "hash mismatch" in json.loads(data)["detail"]


@pytest.mark.parametrize("payload", ["[]", "null", "{", '"text"'])
def test_malformed_or_nonobject_input_has_explicit_error(server, payload):
    status, data = request(server, "POST", "/api/plan", payload)
    assert status == 400
    assert json.loads(data)["error"] == "invalid_plan"


def test_unknown_fields_do_not_disappear_and_error_does_not_echo_input(server):
    payload = json.loads(PLAN.read_text())
    payload.pop("content_sha256")
    payload["unknown"] = "private-input-marker"
    payload["content_sha256"] = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    status, data = request(server, "POST", "/api/plan", json.dumps(payload))
    assert status == 400
    assert b"extra_forbidden" in data
    assert b"private-input-marker" not in data


def test_cross_origin_and_untrusted_host_are_refused(server):
    for headers in [
        {"Origin": "https://external.example"},
        {"Host": "external.example"},
    ]:
        status, _ = request(server, "POST", "/api/plan", PLAN.read_bytes(), headers)
        assert status == 403


def test_oversized_body_is_refused_before_parsing(server):
    status, _ = request(
        server, "POST", "/api/plan", headers={"Content-Length": str(1024 * 1024 + 1)}
    )
    assert status == 413


def test_only_declared_static_assets_are_served(server):
    status, data = request(server, "GET", "/")
    assert status == 200
    assert b"Environment planning" in data
    status, _ = request(server, "GET", "/../../requirements.txt")
    assert status == 404
