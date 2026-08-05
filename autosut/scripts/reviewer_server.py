"""Live reviewer console for AutoSUT.

Replaces the static dashboard with a small HTTP server (stdlib-only, no
external deps) that lets a artifact evaluator:

- See every recent campaign run (manifest, rubric, Caldera operations) live.
- Trigger a campaign run from the browser and watch the orchestrator's
  output stream into the page.
- Serve every evidence file under ``release/evidence/`` for inspection.

Zero external dependencies on purpose — adding Flask or FastAPI to the
artifact's runtime would force every reviewer to ``pip install`` and
arguments would shift to "did Flask 2 or 3" instead of the methodology.
Python stdlib's :mod:`http.server` is enough for the read-mostly,
single-user workload of an artifact-evaluation review.

Security: the front-end uses ``textContent`` and ``createElement``
exclusively for any dynamic value so subprocess stdout cannot inject
HTML into the DOM. The server-rendered shell is the only place a static
template touches the page.

Usage::

    .venv/bin/python scripts/reviewer_server.py --port 8765
    # then open http://localhost:8765 in a browser.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import threading
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

PROJECT_ROOT = Path(__file__).resolve().parent.parent
EVIDENCE_ROOT = PROJECT_ROOT / "release" / "evidence"
DASHBOARD_ROOT = PROJECT_ROOT / "release" / "dashboard"
CAMPAIGNS_ROOT = PROJECT_ROOT / "campaigns"
ORCHESTRATOR_SCRIPT = PROJECT_ROOT / "scripts" / "run_orchestrated_campaign.py"
PYTHON_EXE = PROJECT_ROOT / ".venv" / "bin" / "python"


class JobRegistry:
    """Thread-safe registry of in-flight and completed campaign jobs."""

    def __init__(self) -> None:
        self._jobs: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()

    def create(self, campaign_id: str) -> str:
        job_id = f"job_{uuid.uuid4().hex[:10]}"
        with self._lock:
            self._jobs[job_id] = {
                "job_id": job_id,
                "campaign_id": campaign_id,
                "state": "pending",
                "started_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "finished_at": None,
                "exit_code": None,
                "stdout_tail": "",
            }
        return job_id

    def update(self, job_id: str, **fields: Any) -> None:
        with self._lock:
            if job_id in self._jobs:
                self._jobs[job_id].update(fields)

    def list_all(self) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(job) for job in self._jobs.values()]


JOBS = JobRegistry()


def _list_known_campaigns() -> list[str]:
    return sorted(path.stem for path in CAMPAIGNS_ROOT.glob("0.*.json"))


GOLDEN_RUNS_PATH = PROJECT_ROOT / "release" / "golden_runs.json"


def _list_recent_runs(limit: int = 40) -> list[dict[str, Any]]:
    """List golden runs only. The static dashboard and this live console
    share the same filter: nothing experimental or partial bleeds into the
    reviewer-facing view."""
    if not GOLDEN_RUNS_PATH.exists():
        return []
    golden_data = json.loads(GOLDEN_RUNS_PATH.read_text(encoding="utf-8"))
    runs: list[dict[str, Any]] = []
    for entry in golden_data.get("campaigns", [])[:limit]:
        evidence_relative = entry["evidence_path"]
        run_dir = Path(evidence_relative)
        if not run_dir.is_absolute():
            run_dir = (PROJECT_ROOT / evidence_relative).resolve()
        manifest_path = run_dir / "manifest.json"
        if not manifest_path.exists():
            continue
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        techniques = manifest.get("techniques", [])
        successful = sum(1 for tech in techniques if tech.get("status") == "success")
        runs.append({
            "run_id": entry["golden_run_id"],
            "campaign_id": entry["campaign_id"],
            "techniques_total": len(techniques),
            "techniques_success": successful,
            "evidence_path": str(run_dir.relative_to(PROJECT_ROOT)),
            "has_caldera": (run_dir / "caldera").exists(),
            "has_rubric": (run_dir / "fidelity_report.json").exists(),
        })
    return runs


def _run_campaign_in_background(job_id: str, campaign_id: str) -> None:
    JOBS.update(job_id, state="running")
    process = subprocess.Popen(
        [str(PYTHON_EXE), str(ORCHESTRATOR_SCRIPT), campaign_id],
        cwd=str(PROJECT_ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    stdout_lines: list[str] = []
    if process.stdout is not None:
        for line in process.stdout:
            stdout_lines.append(line)
            if len(stdout_lines) > 200:
                stdout_lines.pop(0)
            JOBS.update(job_id, stdout_tail="".join(stdout_lines[-50:]))
    exit_code = process.wait()
    JOBS.update(
        job_id,
        state="completed" if exit_code == 0 else "failed",
        exit_code=exit_code,
        finished_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        stdout_tail="".join(stdout_lines[-50:]),
    )


# The front-end uses textContent + createElement exclusively for any dynamic
# value, so subprocess output (stdout_tail) can never inject HTML into the
# DOM. The static shell below is the only template literal in the page.
_INDEX_HTML = """<!doctype html>
<html lang='en'>
<head>
  <meta charset='utf-8'>
  <title>AutoSUT - Live Reviewer Console</title>
  <style>
    body { font-family: -apple-system, "Segoe UI", Roboto, sans-serif;
           margin: 24px; max-width: 1100px; color: #1a1a1a; }
    h1 { font-size: 20px; margin: 0 0 6px; }
    h2 { font-size: 16px; border-bottom: 1px solid #ccc; padding-bottom: 4px;
          margin-top: 28px; }
    section { margin-bottom: 24px; }
    button, select { font-size: 14px; padding: 6px 12px; }
    button { background: #1a4d7a; color: white; border: 0; cursor: pointer;
              border-radius: 3px; }
    button:hover { background: #143a5e; }
    .job { background: #f6f6f6; border-left: 3px solid #1a4d7a;
            padding: 10px 14px; margin: 8px 0; font-family: monospace;
            font-size: 12px; white-space: pre-wrap; }
    .job-meta { font-family: -apple-system, sans-serif; font-size: 13px;
                margin-bottom: 8px; }
    table { border-collapse: collapse; width: 100%; font-size: 13px; }
    th, td { border: 1px solid #ddd; padding: 6px 10px; text-align: left; }
    th { background: #e7eff5; color: #1a4d7a; }
    .muted { color: #777; font-size: 12px; }
    .ok { color: #1a7a3a; font-weight: 600; }
    .partial { color: #b8810a; font-weight: 600; }
    .err { color: #a02020; font-weight: 600; }
    a { color: #1a4d7a; }
  </style>
</head>
<body>
  <h1>AutoSUT - Live Reviewer Console</h1>
  <p class='muted'>Trigger campaigns, watch them run, audit evidence.
     Reproducibility recipe: <code>docs/REPRODUCIBILITY_AND_NARRATIVE.md</code>.</p>

  <section>
    <h2>Trigger a campaign run</h2>
    <select id='campaign-select'></select>
    <button id='trigger-btn'>Run</button>
    <p class='muted'>The orchestrator runs in a background thread.
       Status updates auto-refresh every 3 s.</p>
  </section>

  <section>
    <h2>Active and recent jobs</h2>
    <div id='jobs'></div>
  </section>

  <section>
    <h2>Recent campaign runs (from <code>release/evidence/</code>)</h2>
    <table id='runs'>
      <thead><tr>
        <th>Campaign</th><th>Run</th><th>Success</th>
        <th>Caldera</th><th>Rubric</th><th>Evidence</th>
      </tr></thead>
      <tbody></tbody>
    </table>
  </section>

  <script>
    function elementWithText(tagName, text, className) {
      const node = document.createElement(tagName);
      if (text !== undefined && text !== null) {
        node.textContent = String(text);
      }
      if (className) { node.className = className; }
      return node;
    }

    async function loadCampaigns() {
      const campaigns = await (await fetch('/api/campaigns')).json();
      const select = document.getElementById('campaign-select');
      while (select.firstChild) { select.removeChild(select.firstChild); }
      campaigns.forEach(function (id) {
        const option = document.createElement('option');
        option.value = id;
        option.textContent = id;
        select.appendChild(option);
      });
    }

    document.getElementById('trigger-btn').addEventListener('click', async function () {
      const campaign = document.getElementById('campaign-select').value;
      const response = await fetch('/api/runs', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ campaign_id: campaign })
      });
      await response.json();
      refresh();
    });

    function renderJobs(container, jobs) {
      while (container.firstChild) { container.removeChild(container.firstChild); }
      if (jobs.length === 0) {
        container.appendChild(elementWithText('p',
          'No jobs yet.', 'muted'));
        return;
      }
      jobs.forEach(function (job) {
        const wrap = elementWithText('div', null, 'job');
        const meta = elementWithText('div', null, 'job-meta');
        const stateClass = job.state === 'completed' ? 'ok'
                          : job.state === 'failed' ? 'err' : 'partial';
        meta.appendChild(elementWithText('strong', job.campaign_id));
        meta.appendChild(document.createTextNode(' · ' + job.job_id + ' '));
        meta.appendChild(elementWithText('span', job.state, stateClass));
        if (job.exit_code !== null && job.exit_code !== undefined) {
          meta.appendChild(document.createTextNode(' · exit=' + job.exit_code));
        }
        meta.appendChild(document.createTextNode(' · started ' + job.started_at));
        wrap.appendChild(meta);
        if (job.stdout_tail) {
          wrap.appendChild(document.createTextNode(job.stdout_tail));
        }
        container.appendChild(wrap);
      });
    }

    function renderRuns(tbody, runs) {
      while (tbody.firstChild) { tbody.removeChild(tbody.firstChild); }
      runs.forEach(function (run) {
        const row = document.createElement('tr');
        row.appendChild(elementWithText('td', run.campaign_id));
        const runCell = document.createElement('td');
        runCell.appendChild(elementWithText('code', run.run_id));
        row.appendChild(runCell);
        const ratio = run.techniques_total
          ? run.techniques_success + '/' + run.techniques_total : '-';
        row.appendChild(elementWithText('td', ratio));
        row.appendChild(elementWithText('td', run.has_caldera ? 'OK' : '-'));
        row.appendChild(elementWithText('td', run.has_rubric ? 'OK' : '-'));
        const link = document.createElement('a');
        link.href = '/evidence/' + run.evidence_path.replace('release/evidence/', '')
                    + '/manifest.json';
        link.textContent = run.evidence_path;
        const linkCell = document.createElement('td');
        const code = document.createElement('code');
        code.appendChild(link);
        linkCell.appendChild(code);
        row.appendChild(linkCell);
        tbody.appendChild(row);
      });
    }

    async function refresh() {
      const jobs = await (await fetch('/api/jobs')).json();
      renderJobs(document.getElementById('jobs'), jobs);
      const runs = await (await fetch('/api/runs')).json();
      renderRuns(document.querySelector('#runs tbody'), runs);
    }

    loadCampaigns().then(refresh);
    setInterval(refresh, 3000);
  </script>
</body>
</html>"""


class ReviewerHandler(BaseHTTPRequestHandler):
    """One method per HTTP verb; routes are a flat dispatch table."""

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - stdlib name
        return  # quieter; production logging is out of scope for an artifact

    def _send_json(self, payload: Any, status: int = 200) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_text(self, text: str, status: int = 200,
                   content_type: str = "text/plain; charset=utf-8") -> None:
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, file_path: Path) -> None:
        body = file_path.read_bytes()
        suffix = file_path.suffix.lower()
        content_type = {
            ".json": "application/json",
            ".html": "text/html; charset=utf-8",
            ".css": "text/css",
            ".log": "text/plain; charset=utf-8",
            ".txt": "text/plain; charset=utf-8",
        }.get(suffix, "application/octet-stream")
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        path = urlparse(self.path).path

        if path == "/":
            self._send_text(_INDEX_HTML, content_type="text/html; charset=utf-8")
            return
        if path == "/api/campaigns":
            self._send_json(_list_known_campaigns())
            return
        if path == "/api/runs":
            self._send_json(_list_recent_runs())
            return
        if path == "/api/jobs":
            jobs = sorted(JOBS.list_all(),
                          key=lambda job: job["started_at"], reverse=True)
            self._send_json(jobs[:20])
            return
        if path.startswith("/evidence/"):
            relative = path[len("/evidence/"):]
            file_path = (EVIDENCE_ROOT / relative).resolve()
            allowed_root = EVIDENCE_ROOT.resolve()
            if allowed_root not in file_path.parents and file_path != allowed_root:
                self._send_text("evidence path escapes root", status=403)
                return
            if not file_path.exists() or not file_path.is_file():
                self._send_text(f"not found: {relative}", status=404)
                return
            self._send_file(file_path)
            return
        if path == "/dashboard":
            dashboard_html = DASHBOARD_ROOT / "index.html"
            if dashboard_html.exists():
                self._send_file(dashboard_html)
                return
            self._send_text(
                "dashboard not built; run scripts/build_reviewer_dashboard.py",
                status=404,
            )
            return

        self._send_text(f"not found: {path}", status=404)

    def do_POST(self) -> None:
        if self.path != "/api/runs":
            self._send_text(f"not found: {self.path}", status=404)
            return
        content_length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(content_length)
        body = json.loads(raw_body or b"{}")
        campaign_id = body.get("campaign_id")
        if not campaign_id or campaign_id not in _list_known_campaigns():
            self._send_json({"error": f"unknown campaign_id: {campaign_id}"}, status=400)
            return
        job_id = JOBS.create(campaign_id)
        worker = threading.Thread(
            target=_run_campaign_in_background,
            args=(job_id, campaign_id),
            daemon=True,
        )
        worker.start()
        self._send_json({"job_id": job_id, "campaign_id": campaign_id})


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--bind", default="127.0.0.1")
    args = parser.parse_args()

    server = ThreadingHTTPServer((args.bind, args.port), ReviewerHandler)
    print(f"[reviewer-server] http://{args.bind}:{args.port}")
    print(f"[reviewer-server] {len(_list_known_campaigns())} campaigns available")
    print(f"[reviewer-server] Ctrl-C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("[reviewer-server] shutting down")
        server.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
