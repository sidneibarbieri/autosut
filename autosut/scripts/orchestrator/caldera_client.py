"""Thin client for the running MITRE Caldera REST API.

The orchestrator's Caldera-driven execution path uses this client to:

- Verify that a Caldera C2 is reachable at the configured URL.
- List, create, and start operations against registered agents.
- Submit Atomic Red Team abilities (when the atomic plugin is loaded).
- Pull operation outputs to capture per-technique evidence.

The client deliberately does the minimum needed to drive an adversary
emulation; it is not a full Caldera SDK.
"""

from __future__ import annotations

import json
import subprocess
import time
import urllib.error
import urllib.request
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Callable, Optional


CALDERA_URL = "http://localhost:8888"
CALDERA_CONTAINER = "autosut-caldera"


@contextmanager
def endpoint(base_url: str, container_name: str):
    """Point the client at a specific Caldera instance for the duration of the block.

    Every client function reads the module-level target URL and container by name, so rebinding
    them here retargets all of them at once -- used to drive a per-run isolated Caldera instead of
    the persistent development one. The previous target and the cached key are restored on exit.
    """
    global CALDERA_URL, CALDERA_CONTAINER
    previous_url, previous_container = CALDERA_URL, CALDERA_CONTAINER
    CALDERA_URL, CALDERA_CONTAINER = base_url, container_name
    reset_cache()
    try:
        yield
    finally:
        CALDERA_URL, CALDERA_CONTAINER = previous_url, previous_container
        reset_cache()


def _read_red_api_key_from_container() -> Optional[str]:
    """The official MITRE Caldera container randomises ``api_key_red`` in
    ``conf/local.yml`` on first boot. Read it from the running container."""
    proc = subprocess.run(
        ["docker", "exec", CALDERA_CONTAINER, "cat", "/usr/src/app/conf/local.yml"],
        capture_output=True, text=True, check=False, timeout=5,
    )
    if proc.returncode != 0:
        return None
    for line in proc.stdout.splitlines():
        if line.startswith("api_key_red:"):
            return line.split(":", 1)[1].strip()
    return None


_CACHED_API_KEY: Optional[str] = None


def reset_cache() -> None:
    """Forget Caldera-derived client state after a C2 container restart."""
    global _CACHED_API_KEY, _ABILITIES_CACHE
    _CACHED_API_KEY = None
    _ABILITIES_CACHE = []


def get_red_api_key() -> Optional[str]:
    """Return the live red api key, caching after first read."""
    global _CACHED_API_KEY
    if _CACHED_API_KEY is None:
        _CACHED_API_KEY = _read_red_api_key_from_container()
    return _CACHED_API_KEY


DEFAULT_API_KEY = ""  # resolved on first probe via get_red_api_key()


@dataclass
class CalderaInfo:
    url: str
    reachable: bool
    api_ok: bool
    api_key_in_use: str
    server_version: Optional[str] = None


def _http(method: str, path: str, api_key: Optional[str] = None,
          body: Any = None, timeout: float = 10.0) -> tuple[int, str]:
    url = f"{CALDERA_URL}{path}"
    effective_key = api_key or get_red_api_key() or ""
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
    headers = {"Content-Type": "application/json", "KEY": effective_key}
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return 0, str(exc)


def probe(api_key: Optional[str] = None) -> CalderaInfo:
    """Probe a running Caldera and return basic reachability info."""
    landing_ok = False
    api_ok = False
    server_version = None

    landing_status, _ = _http("GET", "/", api_key=api_key, timeout=5)
    landing_ok = landing_status == 200

    api_status, api_body = _http("GET", "/api/v2/health", api_key=api_key, timeout=5)
    api_ok = api_status == 200
    if api_ok and api_body.strip().startswith("{"):
        # Parse only when the body looks like a JSON object so we never
        # need a defensive try/except: a non-JSON 200 from /health would
        # be a Caldera bug worth surfacing - but probe() is the health
        # check itself, so we record the absence rather than raise.
        payload = json.loads(api_body)
        if isinstance(payload, dict):
            server_version = (payload.get("version")
                              or payload.get("server")
                              or payload.get("name"))

    return CalderaInfo(
        url=CALDERA_URL,
        reachable=landing_ok,
        api_ok=api_ok,
        api_key_in_use=(api_key or get_red_api_key() or ""),
        server_version=server_version,
    )


def wait_until_ready(api_key: Optional[str] = None,
                      max_seconds: int = 60,
                      poll_seconds: float = 3.0) -> CalderaInfo:
    """Poll Caldera until the landing page returns 200 or the budget expires."""
    deadline = time.monotonic() + max_seconds
    last = probe(api_key)
    while time.monotonic() < deadline and not last.reachable:
        time.sleep(poll_seconds)
        last = probe(api_key)
    return last


def _get_json_list(path: str, api_key: Optional[str] = None,
                   timeout: float = 10.0) -> list[dict]:
    """GET a Caldera endpoint that returns a JSON list.

    Returns ``[]`` only when Caldera is unreachable (network-level failure;
    status==0). Any HTTP error from a reachable Caldera raises so the bug
    surfaces immediately rather than masquerading as "no data". JSON decode
    errors also propagate - a 200 response that isn't valid JSON is a real
    bug, never silently swallowed.
    """
    status, body = _http("GET", path, api_key=api_key, timeout=timeout)
    if status == 0:
        return []
    if status != 200:
        raise RuntimeError(
            f"Caldera GET {path} returned HTTP {status}: {body[:200]}"
        )
    data = json.loads(body)
    return data if isinstance(data, list) else []


def list_agents(api_key: Optional[str] = None) -> list[dict]:
    return _get_json_list("/api/v2/agents", api_key=api_key, timeout=10)


def list_abilities(api_key: Optional[str] = None) -> list[dict]:
    return _get_json_list("/api/v2/abilities", api_key=api_key, timeout=30)


def create_ability(ability_id: str, name: str, technique_id: str,
                   technique_name: str, tactic: str, command: str,
                   platform: str = "linux", executor_name: str = "sh",
                   description: str = "", cleanup: str = "",
                   api_key: Optional[str] = None) -> Optional[str]:
    """Register a custom ability Caldera's stockpile does not ship.

    Stockpile abilities cover generic ATT&CK techniques; a campaign-specific
    exploit (a named service's job-submission endpoint, a particular CVE
    boundary) has no stock equivalent and must be authored. Returns the
    ability_id, or None when Caldera is unreachable.
    """
    body = {
        "ability_id": ability_id,
        "name": name,
        "description": description or name,
        "tactic": tactic,
        "technique_id": technique_id,
        "technique_name": technique_name,
        "executors": [
            {
                "platform": platform,
                "name": executor_name,
                "command": command,
                "cleanup": [cleanup] if cleanup else [],
                "timeout": 120,
            }
        ],
    }
    response = _post_json("/api/v2/abilities", body, api_key=api_key)
    if response is None:
        return None
    global _ABILITIES_CACHE
    _ABILITIES_CACHE = []  # the technique index must re-list to see the new ability
    return response.get("ability_id") or ability_id


def find_ability_by_technique(technique_id: str,
                               api_key: Optional[str] = None) -> Optional[dict]:
    """Return the first ability whose `technique_id` matches."""
    abilities = list_abilities(api_key)
    for ability in abilities:
        if ability.get("technique_id") == technique_id:
            return ability
    return None


_ABILITIES_CACHE: list[dict] = []
PREFERRED_LINUX_ABILITY_BY_TECHNIQUE = {
    # Software Discovery: stock Caldera lists Chrome/Go/Python checks. The
    # AutoSUT Linux Python SUT is guaranteed to have Python, while Chrome is
    # intentionally absent from the minimal image.
    "T1518": "b18e8767-b7ea-41a3-8e80-baf65a5ddef5",
}


def all_abilities_indexed_by_technique(api_key: Optional[str] = None) -> dict[str, list[dict]]:
    """Return abilities grouped by technique_id. Caches the first call."""
    global _ABILITIES_CACHE
    if not _ABILITIES_CACHE:
        _ABILITIES_CACHE = list_abilities(api_key)
    index: dict[str, list[dict]] = {}
    for ability in _ABILITIES_CACHE:
        tid = ability.get("technique_id") or ""
        if tid:
            index.setdefault(tid, []).append(ability)
    return index


def best_ability_for(technique_id: str,
                     preferred_platform: str = "linux",
                     api_key: Optional[str] = None,
                     strict_platform: bool = True) -> Optional[dict]:
    """Pick a Caldera ability for the technique, preferring the requested
    platform when available.

    With ``strict_platform=True`` (default), returns None when no ability has
    an executor for ``preferred_platform``. This guards against dispatching
    Windows-only abilities at a Linux sandcat (which Caldera rejects with
    "Mismatched ability platform and executor"). Pass strict_platform=False
    to fall back to the first candidate regardless of platform (useful only
    for annotation, not for dispatch).

    When multiple abilities have a matching executor, abilities whose first
    Linux executor has no ``parsers`` and no ``payloads`` field (i.e. simple
    self-contained commands) are preferred - they are far more likely to
    succeed without a configured fact source.
    """
    index = all_abilities_indexed_by_technique(api_key)
    candidates = index.get(technique_id, [])
    if not candidates:
        return None

    # First pass: must have the platform executor.
    matched = [a for a in candidates
               if preferred_platform in {e.get("platform")
                                          for e in a.get("executors", [])}]
    if not matched:
        if strict_platform:
            return None
        return candidates[0]

    preferred_ability_id = PREFERRED_LINUX_ABILITY_BY_TECHNIQUE.get(technique_id)
    if preferred_ability_id:
        for ability in matched:
            if ability.get("ability_id") == preferred_ability_id:
                return ability

    # Second pass: prefer the simpler, self-contained variants.
    def simplicity(ability: dict) -> int:
        platform_executors = [executor for executor in ability.get("executors", [])
                              if executor.get("platform") == preferred_platform]
        if not platform_executors:
            return 100
        first_executor = platform_executors[0]
        score = 0
        if first_executor.get("parsers"):
            score += 2
        if first_executor.get("payloads"):
            score += 1
        return score

    matched.sort(key=simplicity)
    return matched[0]


def caldera_summary() -> dict:
    """Snapshot the live Caldera state for the manifest provenance file."""
    info = probe()
    return {
        "url": info.url,
        "reachable": info.reachable,
        "api_ok": info.api_ok,
        "server_version": info.server_version,
        "agent_count": len(list_agents()) if info.api_ok else 0,
        "ability_count": len(list_abilities()) if info.api_ok else 0,
    }


def container_id() -> Optional[str]:
    """Inspect the Caldera container, if any, by canonical name."""
    proc = subprocess.run(
        ["docker", "ps", "--filter", "name=autosut-caldera",
         "--format", "{{.ID}}"],
        capture_output=True, text=True, check=False,
    )
    cid = proc.stdout.strip()
    return cid or None


def container_ip() -> Optional[str]:
    """Return the Caldera container's bridge IP, suitable for SUT->C2 traffic
    inside the same Docker bridge network."""
    proc = subprocess.run(
        ["docker", "inspect", "-f",
         "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
         CALDERA_CONTAINER],
        capture_output=True, text=True, check=False, timeout=5,
    )
    ip = proc.stdout.strip()
    return ip or None


# ---------------------------------------------------------------------------
# Sandcat agent download + operation lifecycle
# ---------------------------------------------------------------------------

# Canonical planner ids exposed by stock Caldera 5.x. The atomic planner is
# the right pick for per-technique single-agent dispatch: it walks the
# adversary's atomic_ordering one ability at a time and produces clean
# per-link evidence.
ATOMIC_PLANNER_ID = "aaa7c857-37a0-4c4a-85f7-4e9f7f30e31a"


def download_sandcat(platform: str = "linux",
                     architecture: str = "amd64",
                     api_key: Optional[str] = None,
                     timeout: float = 30.0) -> Optional[bytes]:
    """Download a sandcat agent binary built for the requested platform/arch.

    Caldera's sandcat plugin serves precompiled binaries through GET
    /file/download with headers ``platform`` and ``file: sandcat.go``. Stock
    builds include Linux x86_64, Linux ARM64, Darwin, Darwin ARM64, Windows.
    """
    url = f"{CALDERA_URL}/file/download"
    effective_key = api_key or get_red_api_key() or ""
    headers = {
        "KEY": effective_key,
        "platform": platform,
        "file": "sandcat.go",
        "architecture": architecture,
    }
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status != 200:
                return None
            return resp.read()
    except (urllib.error.HTTPError, urllib.error.URLError,
            TimeoutError, OSError):
        return None


def _post_json(path: str, body: dict, api_key: Optional[str] = None,
               timeout: float = 15.0) -> Optional[dict]:
    """POST a JSON body. Returns the decoded response dict on 200/201.
    Network unreachability returns None; HTTP errors raise; JSON errors
    raise. Callers should already have probed Caldera's reachability.
    """
    status, response_body = _http("POST", path, api_key=api_key,
                                   body=body, timeout=timeout)
    if status == 0:
        return None
    if status not in (200, 201):
        raise RuntimeError(
            f"Caldera POST {path} returned HTTP {status}: {response_body[:200]}"
        )
    return json.loads(response_body)


def list_adversaries(api_key: Optional[str] = None) -> list[dict]:
    return _get_json_list("/api/v2/adversaries", api_key=api_key, timeout=10)


def create_adversary(name: str, ability_ids: list[str],
                     description: str = "AutoSUT-generated adversary",
                     api_key: Optional[str] = None) -> Optional[str]:
    """Create a one-off adversary that runs the listed abilities in order.

    Returns the new adversary_id, or None when Caldera is unreachable.
    """
    import uuid as _uuid
    adversary_id = str(_uuid.uuid4())
    body = {
        "adversary_id": adversary_id,
        "name": name,
        "description": description,
        "atomic_ordering": ability_ids,
        "objective": "495a9828-cab1-44dd-a0ca-66e58177d8cc",  # stock "default"
        "tags": ["autosut"],
    }
    response = _post_json("/api/v2/adversaries", body, api_key=api_key)
    if response is None:
        return None
    return response.get("adversary_id") or adversary_id


def start_operation(name: str, adversary_id: str,
                    planner_id: str = ATOMIC_PLANNER_ID,
                    group: str = "red",
                    api_key: Optional[str] = None) -> Optional[str]:
    """Launch a Caldera operation. Returns operation id, or None when
    Caldera is unreachable. HTTP/JSON errors propagate.
    """
    import uuid as _uuid
    operation_id = str(_uuid.uuid4())
    body = {
        "id": operation_id,
        "name": name,
        "adversary": {"adversary_id": adversary_id},
        "planner": {"id": planner_id},
        "source": {"id": "ed32b9c3-9593-4c33-b0db-e2007315096b"},  # basic facts
        "group": group,
        "state": "running",
        "autonomous": 1,
        "obfuscator": "plain-text",
        "auto_close": True,
        "jitter": "0/0",
        "visibility": 50,
    }
    response = _post_json("/api/v2/operations", body, api_key=api_key)
    if response is None:
        return None
    return response.get("id") or operation_id


def get_operation(operation_id: str,
                  api_key: Optional[str] = None) -> Optional[dict]:
    """Returns the operation dict; None when Caldera is unreachable; HTTP
    and JSON errors propagate."""
    status, body = _http("GET", f"/api/v2/operations/{operation_id}",
                         api_key=api_key, timeout=10)
    if status == 0:
        return None
    if status != 200:
        raise RuntimeError(
            f"Caldera GET operation/{operation_id} returned HTTP {status}: "
            f"{body[:200]}"
        )
    return json.loads(body)


def get_operation_report(operation_id: str,
                         api_key: Optional[str] = None) -> Optional[dict]:
    """Return the operation report - includes per-step (link) outcomes with
    stdout/stderr and statuses, which is the audit trail we want in the
    AutoSUT manifest. None when Caldera is unreachable; HTTP and JSON errors
    propagate.
    """
    return _post_json(
        f"/api/v2/operations/{operation_id}/report",
        body={"enable_agent_output": True},
        api_key=api_key,
        timeout=30,
    )


def wait_operation_done(operation_id: str,
                        max_seconds: int = 120,
                        poll_seconds: float = 3.0,
                        api_key: Optional[str] = None) -> Optional[dict]:
    """Poll the operation until its state is `finished` or budget expires."""
    deadline = time.monotonic() + max_seconds
    while time.monotonic() < deadline:
        op = get_operation(operation_id, api_key=api_key)
        if op is None:
            return None
        state = op.get("state", "")
        if state == "finished":
            return op
        time.sleep(poll_seconds)
    return get_operation(operation_id, api_key=api_key)


def wait_agent_registered(paw_substring: Optional[str] = None,
                          group: str = "red",
                          max_seconds: int = 60,
                          poll_seconds: float = 2.0,
                          api_key: Optional[str] = None) -> Optional[dict]:
    """Wait until at least one agent (optionally matching paw_substring) shows
    up in the requested group. Returns the agent dict or None on timeout."""
    deadline = time.monotonic() + max_seconds
    while time.monotonic() < deadline:
        agents = list_agents(api_key=api_key)
        for agent in agents:
            if agent.get("group") != group:
                continue
            if paw_substring and paw_substring not in (agent.get("paw") or ""):
                continue
            return agent
        time.sleep(poll_seconds)
    return None


class CalderaClient:
    """A Caldera REST client bound to one instance's URL, key, and container.

    All request state lives on the instance, so correctness does not depend on the module-level
    target or on the execution lock: two clients for two isolated Caldera instances can be used
    independently. This is the canonical client for the lifecycle; the module-level functions above
    remain only for the legacy dispatch path pending consolidation.
    """

    def __init__(self, base_url: str, api_key: str, container_name: str):
        self.base_url = base_url
        self.api_key = api_key
        self.container_name = container_name

    def _http(self, method: str, path: str, body: Any = None,
              timeout: float = 10.0) -> tuple[int, str]:
        data = json.dumps(body).encode("utf-8") if body is not None else None
        headers = {"Content-Type": "application/json", "KEY": self.api_key}
        req = urllib.request.Request(
            f"{self.base_url}{path}", data=data, method=method, headers=headers
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.status, resp.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode("utf-8")
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            return 0, str(exc)

    def _post_json(self, path: str, body: dict, timeout: float = 15.0) -> Optional[dict]:
        status, response_body = self._http("POST", path, body=body, timeout=timeout)
        if status == 0:
            return None
        if status not in (200, 201):
            raise RuntimeError(f"Caldera POST {path} returned HTTP {status}: {response_body[:200]}")
        return json.loads(response_body)

    def _get_json_list(self, path: str, timeout: float = 10.0) -> list[dict]:
        status, body = self._http("GET", path, timeout=timeout)
        if status == 0:
            return []
        if status != 200:
            raise RuntimeError(f"Caldera GET {path} returned HTTP {status}: {body[:200]}")
        data = json.loads(body)
        return data if isinstance(data, list) else []

    def probe(self) -> CalderaInfo:
        landing_status, _ = self._http("GET", "/", timeout=5)
        api_status, _ = self._http("GET", "/api/v2/health", timeout=5)
        return CalderaInfo(
            url=self.base_url, reachable=landing_status == 200,
            api_ok=api_status == 200, api_key_in_use=self.api_key,
        )

    def download_sandcat(self, platform: str = "linux", architecture: str = "amd64",
                         timeout: float = 30.0) -> Optional[bytes]:
        headers = {"KEY": self.api_key, "platform": platform,
                   "file": "sandcat.go", "architecture": architecture}
        req = urllib.request.Request(
            f"{self.base_url}/file/download", headers=headers, method="GET"
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read() if resp.status == 200 else None
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError):
            return None

    def list_agents(self) -> list[dict]:
        return self._get_json_list("/api/v2/agents", timeout=10)

    def wait_agent_registered(
        self,
        paw_substring: Optional[str] = None,
        group: str = "red",
        max_seconds: int = 90,
        poll_seconds: float = 2.0,
        on_pending_poll: Callable[[], None] | None = None,
    ) -> Optional[dict]:
        """Wait for an agent and optionally expose the first observed pending enrollment.

        The callback runs only after a real agents API response contains no matching agent.  That
        is a semantic boundary for interruption experiments: Sandcat has already been launched
        and Caldera has been queried, yet enrollment has not completed.
        """
        deadline = time.monotonic() + max_seconds
        pending_notified = False
        while time.monotonic() < deadline:
            for agent in self.list_agents():
                if agent.get("group") != group:
                    continue
                if paw_substring and paw_substring not in (agent.get("paw") or ""):
                    continue
                return agent
            if not pending_notified and on_pending_poll is not None:
                on_pending_poll()
                pending_notified = True
            time.sleep(poll_seconds)
        return None

    def create_ability(self, ability_id: str, name: str, technique_id: str, technique_name: str,
                       tactic: str, command: str, platform: str = "linux",
                       executor_name: str = "sh", description: str = "",
                       cleanup: str = "", fact_source: str | None = None) -> Optional[str]:
        """Register an ability. When fact_source is set, the executor parses its stdout into that
        fact, so a later ability on another host can consume it with #{fact_source}."""
        executor = {"platform": platform, "name": executor_name, "command": command,
                    "cleanup": [cleanup] if cleanup else [], "timeout": 120}
        if fact_source:
            executor["parsers"] = [{
                "module": "plugins.stockpile.app.parsers.basic",
                "parserconfigs": [{"source": fact_source, "edge": None, "target": None}],
            }]
        body = {
            "ability_id": ability_id, "name": name, "description": description or name,
            "tactic": tactic, "technique_id": technique_id, "technique_name": technique_name,
            "executors": [executor],
        }
        response = self._post_json("/api/v2/abilities", body)
        return None if response is None else (response.get("ability_id") or ability_id)

    def create_adversary(self, name: str, ability_ids: list[str],
                         description: str = "AutoSUT-generated adversary") -> Optional[str]:
        import uuid
        adversary_id = str(uuid.uuid4())
        body = {
            "adversary_id": adversary_id, "name": name, "description": description,
            "atomic_ordering": ability_ids,
            "objective": "495a9828-cab1-44dd-a0ca-66e58177d8cc", "tags": ["autosut"],
        }
        response = self._post_json("/api/v2/adversaries", body)
        return None if response is None else (response.get("adversary_id") or adversary_id)

    def start_operation(self, name: str, adversary_id: str,
                        planner_id: str = ATOMIC_PLANNER_ID, group: str = "red") -> Optional[str]:
        import uuid
        operation_id = str(uuid.uuid4())
        body = {
            "id": operation_id, "name": name,
            "adversary": {"adversary_id": adversary_id}, "planner": {"id": planner_id},
            "source": {"id": "ed32b9c3-9593-4c33-b0db-e2007315096b"}, "group": group,
            "state": "running", "autonomous": 1, "obfuscator": "plain-text",
            "auto_close": True, "jitter": "0/0", "visibility": 50,
        }
        response = self._post_json("/api/v2/operations", body)
        return None if response is None else (response.get("id") or operation_id)

    def get_operation(self, operation_id: str) -> Optional[dict]:
        status, body = self._http("GET", f"/api/v2/operations/{operation_id}", timeout=10)
        if status == 0:
            return None
        if status != 200:
            raise RuntimeError(f"Caldera GET operation/{operation_id} returned HTTP {status}")
        return json.loads(body)

    def wait_operation_done(self, operation_id: str, max_seconds: int = 120,
                            poll_seconds: float = 3.0) -> Optional[dict]:
        deadline = time.monotonic() + max_seconds
        while time.monotonic() < deadline:
            operation = self.get_operation(operation_id)
            if operation is None:
                return None
            if operation.get("state") == "finished":
                return operation
            time.sleep(poll_seconds)
        return self.get_operation(operation_id)

    def get_operation_report(self, operation_id: str) -> Optional[dict]:
        return self._post_json(
            f"/api/v2/operations/{operation_id}/report",
            {"enable_agent_output": True}, timeout=30,
        )

    def container_ip(self) -> Optional[str]:
        proc = subprocess.run(
            ["docker", "inspect", "-f",
             "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", self.container_name],
            capture_output=True, text=True, check=False, timeout=5,
        )
        return proc.stdout.strip() or None
