"""CVE injection recipes.

Each recipe is a function `inject_<recipe_name>(env)` that installs the
vulnerable software (or surrogate) inside an already-up environment and
returns a CVEFidelity record documenting what was actually done.

Adding a new CVE means adding one function here and referencing it from
catalog.py via `install_recipe`.
"""

from __future__ import annotations

import json
import shlex
from typing import Callable

from .environment import DockerEnvironment
from .models import CVEFidelity, CVEInjection, FidelityLevel, Realization


# ---------------------------------------------------------------------------
# Recipe: Ray 2.6.3 (CVE-2023-48022)
# ---------------------------------------------------------------------------

def inject_ray_2_6_3(env: DockerEnvironment) -> CVEFidelity:
    """Install the actual vulnerable Ray ML version on the SUT.

    Ray is open source on PyPI. Version 2.6.3 has the unauthenticated job
    submission endpoint that is the CVE-2023-48022 surface. After install we
    launch ray head in a way that exposes the dashboard.
    """
    log_path = "sut/cve_injection_CVE-2023-48022_real.log"

    steps = [
        ("install curl for later probes (python:3.11-slim has no curl)",
         "apt-get update -o Acquire::AllowInsecureRepositories=true "
         "-o Acquire::AllowDowngradeToInsecureRepositories=true && "
         "apt-get install -y --allow-unauthenticated curl || true"),
        ("install Ray 2.6.3 with dashboard extras",
         "python3 -m pip install --no-cache-dir --root-user-action=ignore "
         "'ray[default]==2.6.3' 'click<8.2' 'protobuf<5' 'pydantic<2' "
         "'async_timeout' 'opencensus' 'aiorwlock' 'pyOpenSSL'"),
        ("start ray head with dashboard exposed (head also acts as worker)",
         _ray_start_command() + " && sleep 20 && ray status 2>&1 | head -15"),
        ("preflight two sequential Ray jobs",
         _ray_jobs_preflight_command()),
    ]
    overall_ok = True
    for label, cmd in steps:
        result = env.run_shell(cmd, log_name=log_path, timeout=900)
        if not result.ok:
            overall_ok = False
            break

    return CVEFidelity(
        cve_id="CVE-2023-48022",
        fidelity=FidelityLevel.adapted,
        realization=Realization.real_cve,
        success=overall_ok,
        log_path=log_path,
        notes="Ray 2.6.3 installed from PyPI with default dashboard enabled. "
              "The unauthenticated job-submission endpoint is the documented "
              "RCE surface for CVE-2023-48022. Success requires two "
              "sequential job submissions to reach SUCCEEDED.",
    )


def _ray_jobs_preflight_command() -> str:
    """Return a command that proves the Ray job API accepts sequential jobs."""

    jobs = [
        {"entrypoint": "echo preflight_one > /tmp/ray_preflight_one.txt"},
        {"entrypoint": "echo preflight_two > /tmp/ray_preflight_two.txt"},
    ]
    script = "\n".join([
        "import json",
        "import requests",
        "import sys",
        "import time",
        f"jobs = json.loads({json.dumps(jobs)!r})",
        "base = 'http://127.0.0.1:8265'",
        "terminal = {'SUCCEEDED', 'FAILED', 'STOPPED'}",
        "for index, payload in enumerate(jobs):",
        "    response = requests.post(base + '/api/jobs/', json=payload, timeout=30)",
        "    print('post', index, response.status_code, response.text[:1000])",
        "    response.raise_for_status()",
        "    body = response.json()",
        "    submission_id = body.get('submission_id') or body.get('job_id')",
        "    if not submission_id:",
        "        sys.exit(1)",
        "    final_status = None",
        "    for attempt in range(60):",
        "        status_response = requests.get(base + '/api/jobs/' + submission_id, timeout=10)",
        "        print('poll', index, attempt, status_response.status_code, status_response.text[:1000])",
        "        status_response.raise_for_status()",
        "        final_status = status_response.json().get('status')",
        "        if final_status in terminal:",
        "            break",
        "        time.sleep(1)",
        "    if final_status != 'SUCCEEDED':",
        "        sys.exit(1)",
        "print('ray_job_preflight=ok')",
    ])
    return "python3 -c " + shlex.quote(script)


def _ray_start_command() -> str:
    return (
        "ray start --head --dashboard-host=0.0.0.0 --dashboard-port=8265 "
        "--port=6379 --include-dashboard=true --num-cpus=2 --num-gpus=0"
    )


def rebind_ray_after_isolation(env: DockerEnvironment) -> None:
    """Restart Ray after its container IP changes and verify the Jobs API."""
    command = (
        "ray stop --force >/tmp/ray-stop-after-isolation.log 2>&1 || true; "
        + _ray_start_command()
        + " && sleep 20 && "
        + _ray_jobs_preflight_command()
    )
    result = env.run_shell(command, log_name="sut/ray_rebind_after_isolation.log", timeout=900)
    if not result.ok:
        raise RuntimeError("Ray Jobs API failed after replay network isolation")


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

def inject_globalprotect_surrogate(env: DockerEnvironment) -> CVEFidelity:
    """Adapted/surrogate for CVE-2024-3400 (Palo Alto GlobalProtect).

    The real disclosure: the GlobalProtect portal accepts an attacker-supplied
    SESSID cookie that is later passed unsanitised to a shell, allowing OS
    command injection. The surrogate exposes /ssl-vpn/login.esp on port 8443
    and runs the cookie value through a shell.
    """
    log_path = "sut/cve_injection_CVE-2024-3400.log"
    surrogate_py = (
        "from flask import Flask, request, jsonify\\n"
        "import os\\n"
        "app = Flask(__name__)\\n"
        "@app.route('/ssl-vpn/login.esp', methods=['GET', 'POST'])\\n"
        "def login():\\n"
        "    sessid = request.cookies.get('SESSID', '')\\n"
        "    if sessid.startswith('CMD:'):\\n"
        "        cmd = sessid.removeprefix('CMD:')\\n"
        "        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)\\n"
        "        return {'auth': 'failed', 'evidence': proc.stdout, 'returncode': proc.returncode}, 200\\n"
        "    return {'auth': 'failed'}, 401\\n"
        "@app.route('/')\\n"
        "def root():\\n"
        "    return 'GlobalProtect Portal (surrogate)'\\n"
        "if __name__ == '__main__':\\n"
        "    app.run(host='0.0.0.0', port=8443)\\n"
    )
    steps = [
        ("install flask",
         "python3 -m pip install --no-cache-dir --root-user-action=ignore flask"),
        ("write surrogate",
         f'printf "{surrogate_py}" > /opt/globalprotect_surrogate.py && head -3 /opt/globalprotect_surrogate.py'),
        ("start surrogate on 8443",
         "nohup python3 /opt/globalprotect_surrogate.py > /tmp/gp.log 2>&1 & "
         "sleep 4 && python3 -c \"import urllib.request as u; "
         "r = u.urlopen('http://127.0.0.1:8443/', timeout=5); "
         "print('probe', r.status, r.read().decode()[:60])\""),
    ]
    ok = True
    for _, cmd in steps:
        if not env.run_shell(cmd, log_name=log_path, timeout=180).ok:
            ok = False
            break
    return CVEFidelity(
        cve_id="CVE-2024-3400",
        fidelity=FidelityLevel.adapted,
        realization=Realization.surrogate,
        success=ok, log_path=log_path,
        notes="Surrogate of GlobalProtect SSL VPN login.esp endpoint. The "
              "SESSID cookie command-injection semantics are preserved; the "
              "actual Palo Alto product is paywalled.",
    )


def inject_salesforce_api_surrogate(env: DockerEnvironment) -> CVEFidelity:
    """No-CVE surrogate of a Salesforce-like REST API for data exfiltration.

    The surrogate exposes /services/data/v59.0/sobjects/Account/<id> and
    /services/data/v59.0/query?q=... and accepts a Bearer token. The
    technique sequence exercises programmatic CRM exfiltration semantics.
    """
    log_path = "sut/cve_injection_salesforce_surrogate.log"
    surrogate_py = (
        "from flask import Flask, request, jsonify\\n"
        "app = Flask(__name__)\\n"
        "@app.before_request\\n"
        "def auth():\\n"
        "    h = request.headers.get('Authorization', '')\\n"
        "    if not h.startswith('Bearer '): return ('Unauthorized', 401)\\n"
        "@app.route('/services/data/v59.0/sobjects/Account/<oid>')\\n"
        "def acc(oid):\\n"
        "    return jsonify(Id=oid, Name='Acme Test', Phone='555-LAB', "
        "                    Industry='Lab', AnnualRevenue=1000000)\\n"
        "@app.route('/services/data/v59.0/query')\\n"
        "def query():\\n"
        "    return jsonify(totalSize=2, done=True, records=[ "
        "      dict(Id='001LAB001', Name='Customer Alpha', Email='alpha@lab.test'), "
        "      dict(Id='001LAB002', Name='Customer Beta',  Email='beta@lab.test'), "
        "    ])\\n"
        "if __name__ == '__main__':\\n"
        "    app.run(host='0.0.0.0', port=8443)\\n"
    )
    steps = [
        ("install flask",
         "python3 -m pip install --no-cache-dir --root-user-action=ignore flask"),
        ("write surrogate",
         f'printf "{surrogate_py}" > /opt/sf_surrogate.py'),
        ("start surrogate on 8443 and probe (expect 401 without bearer)",
         "nohup python3 /opt/sf_surrogate.py > /tmp/sf.log 2>&1 & "
         "sleep 5 && "
         "python3 -c \"import urllib.request as u, urllib.error as e; "
         "import sys; status=None; "
         "h={'Authorization':'Bearer LAB-TOKEN'}; "
         "req=u.Request('http://127.0.0.1:8443/services/data/v59.0/query', headers=h); "
         "status=u.urlopen(req, timeout=5).status; "
         "sys.stdout.write(f'probe status={status}\\\\n')\""),
    ]
    ok = True
    for _, cmd in steps:
        if not env.run_shell(cmd, log_name=log_path, timeout=180).ok:
            ok = False
            break
    return CVEFidelity(
        cve_id="N/A_salesforce_surrogate",
        fidelity=FidelityLevel.adapted,
        realization=Realization.surrogate,
        success=ok, log_path=log_path,
        notes="Surrogate Salesforce REST API. No CVE; the technique sequence "
              "exercises Bearer-token API exfiltration semantics.",
    )


def inject_ray_dashboard_surrogate(env: DockerEnvironment) -> CVEFidelity:
    """Adapted-surrogate fallback for CVE-2023-48022.

    Runs a Flask service whose POST /api/jobs/ endpoint executes the JSON
    payload's `entrypoint` field exactly the way the Ray dashboard does
    pre-patch - unauthenticated, no validation. The technique sequence
    against this surrogate is byte-for-byte identical to the one against
    the real dashboard, so the executor walks the same code path.
    """
    log_path = "sut/cve_injection_CVE-2023-48022_surrogate.log"
    surrogate_py = (
        "from flask import Flask, request, jsonify\\n"
        "import os\\n"
        "app = Flask(__name__)\\n"
        "@app.route('/api/jobs/', methods=['POST'])\\n"
        "def submit():\\n"
        "    payload = request.get_json(force=True) or {}\\n"
        "    cmd = payload.get('entrypoint', '')\\n"
        "    returncode = os.system(cmd) >> 8\\n"
        "    return jsonify(submission_id='sid_surrogate_0001', stdout='', returncode=returncode), 200\\n"
        "@app.route('/')\\n"
        "def root():\\n"
        "    return 'Ray Dashboard (surrogate)'\\n"
        "if __name__ == '__main__':\\n"
        "    app.run(host='0.0.0.0', port=8265)\\n"
    )

    steps = [
        ("install python flask + requests",
         "python3 -m pip install --no-cache-dir --root-user-action=ignore flask requests"),
        ("write surrogate dashboard service",
         f'printf "{surrogate_py}" > /opt/surrogate.py && head -3 /opt/surrogate.py'),
        ("start surrogate dashboard in background on port 8265 and probe via python",
         "nohup python3 /opt/surrogate.py > /tmp/surrogate.log 2>&1 & "
         "sleep 5 && "
         'python3 -c "import urllib.request, sys; '
         "r = urllib.request.urlopen('http://127.0.0.1:8265/'); "
         "sys.stdout.write(f'probe OK: {r.status} body={r.read().decode()[:60]!r}\\n')\""),
        ("exercise surrogate job endpoint",
         "python3 -c \"import requests; r=requests.post('http://127.0.0.1:8265/api/jobs/', json={'entrypoint':'echo probe'}); print('job_probe', r.status_code, r.text[:200])\"; "
         "cat /tmp/surrogate.log"),
    ]
    overall_ok = True
    for label, cmd in steps:
        result = env.run_shell(cmd, log_name=log_path, timeout=300)
        if not result.ok:
            overall_ok = False
            break

    return CVEFidelity(
        cve_id="CVE-2023-48022",
        fidelity=FidelityLevel.adapted,
        realization=Realization.surrogate,
        success=overall_ok,
        log_path=log_path,
        notes="Adapted/surrogate: Flask service mimicking the unauthenticated "
              "POST /api/jobs/ endpoint of the Ray dashboard. The technique "
              "executor walks the same exploit path against this surrogate. "
              "The CVE itself is not exploited; the technique semantics are.",
    )


def inject_ray_dashboard_guarded(env: DockerEnvironment) -> CVEFidelity:
    """Guarded counterpart to the Ray dashboard surrogate for the consequence study.

    This is byte-for-byte the surrogate above, with one change: POST /api/jobs/
    requires an Authorization: Bearer token and returns 401 without it. Structured
    CTI for ShadowRay links no software and says nothing about authentication, so
    an authenticated Jobs API is as CTI-consistent as an unauthenticated one. This
    arm isolates that single free dimension: an unauthenticated job submission,
    the path the technique chain walks, is refused here.
    """
    log_path = "sut/cve_injection_CVE-2023-48022_guarded.log"
    surrogate_py = (
        "from flask import Flask, request, jsonify\\n"
        "import os\\n"
        "TOKEN = 'lab-operator-token'\\n"
        "app = Flask(__name__)\\n"
        "@app.route('/api/jobs/', methods=['POST'])\\n"
        "def submit():\\n"
        "    header = request.headers.get('Authorization', '')\\n"
        "    if header != 'Bearer ' + TOKEN:\\n"
        "        return jsonify(error='unauthorized'), 401\\n"
        "    payload = request.get_json(force=True) or {}\\n"
        "    cmd = payload.get('entrypoint', '')\\n"
        "    returncode = os.system(cmd) >> 8\\n"
        "    return jsonify(submission_id='sid_guarded_0001', stdout='', returncode=returncode), 200\\n"
        "@app.route('/')\\n"
        "def root():\\n"
        "    return 'Ray Dashboard (guarded surrogate)'\\n"
        "if __name__ == '__main__':\\n"
        "    app.run(host='0.0.0.0', port=8265)\\n"
    )
    steps = [
        ("install python flask + requests",
         "python3 -m pip install --no-cache-dir --root-user-action=ignore flask requests"),
        ("write guarded dashboard service",
         f'printf "{surrogate_py}" > /opt/guarded.py && head -3 /opt/guarded.py'),
        ("start guarded dashboard in background on port 8265 and probe root",
         "nohup python3 /opt/guarded.py > /tmp/guarded.log 2>&1 & "
         "sleep 5 && "
         'python3 -c "import urllib.request, sys; '
         "r = urllib.request.urlopen('http://127.0.0.1:8265/'); "
         "sys.stdout.write(f'probe OK: {r.status} body={r.read().decode()[:60]!r}\\n')\""),
        ("prove the job endpoint rejects a tokenless submission and accepts a tokened one",
         "python3 -c \""
         "import requests; "
         "u=requests.post('http://127.0.0.1:8265/api/jobs/', json={'entrypoint':'echo probe'}); "
         "a=requests.post('http://127.0.0.1:8265/api/jobs/', json={'entrypoint':'echo probe'}, "
         "headers={'Authorization':'Bearer lab-operator-token'}); "
         "print('tokenless', u.status_code, 'tokened', a.status_code); "
         "assert u.status_code==401 and a.status_code==200\"; "
         "cat /tmp/guarded.log"),
    ]
    overall_ok = True
    for _, cmd in steps:
        if not env.run_shell(cmd, log_name=log_path, timeout=300).ok:
            overall_ok = False
            break
    return CVEFidelity(
        cve_id="CVE-2023-48022",
        fidelity=FidelityLevel.adapted,
        realization=Realization.surrogate,
        success=overall_ok,
        log_path=log_path,
        notes="Guarded counterpart of the Ray dashboard surrogate: POST /api/jobs/ "
              "requires a Bearer token. A tokenless submission, the path the chain "
              "walks, is refused with 401. Used only by the consequence study.",
    )


RECIPES: dict[str, Callable[[DockerEnvironment], CVEFidelity]] = {
    "ray_2_6_3": inject_ray_2_6_3,
    "ray_dashboard_surrogate": inject_ray_dashboard_surrogate,
    "ray_dashboard_guarded": inject_ray_dashboard_guarded,
    "globalprotect_surrogate": inject_globalprotect_surrogate,
    "salesforce_api_surrogate": inject_salesforce_api_surrogate,
}


def inject(env: DockerEnvironment, cve_set: list[CVEInjection]) -> list[CVEFidelity]:
    """Run every requested injection and return audit records."""
    fidelity_records: list[CVEFidelity] = []
    for cve in cve_set:
        recipe = RECIPES.get(cve.install_recipe)
        if recipe is None:
            fidelity_records.append(
                CVEFidelity(
                    cve_id=cve.cve_id,
                    fidelity=FidelityLevel.inspired,
                    realization=Realization.generic_primitive,
                    success=False,
                    log_path="",
                    notes=f"No install recipe registered for {cve.install_recipe}. "
                          f"Falling back to inspired (nothing injected).",
                )
            )
            continue
        fidelity_records.append(recipe(env))
    return fidelity_records
