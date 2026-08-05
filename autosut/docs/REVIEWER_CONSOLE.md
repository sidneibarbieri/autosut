# Live Reviewer Console

`scripts/reviewer_server.py` is AutoSUT's live counterpart to the static
`release/dashboard/index.html`. It is a reviewer-facing surface for monitoring
local runs without leaving the browser.

## What it adds over the static dashboard

| Concern | Static dashboard | Live console |
|---|---|---|
| Visibility of in-flight runs | none — reviewer must re-run `build_reviewer_dashboard.py` after each campaign | auto-refresh every 3 s |
| Ability to trigger a run | reviewer must drop to terminal | one click in the browser |
| Manifest / evidence access | filesystem paths in the HTML | HTTP routes under `/evidence/<run>/...` |
| Concurrency surface | n/a | every triggered run is its own background thread; multiple campaigns can be running simultaneously |

## Zero external dependencies on purpose

The console uses only Python's standard library
(``http.server.ThreadingHTTPServer``, ``threading``, ``json``,
``subprocess``). Adding Flask or FastAPI would force a ``pip install``
on every reviewer's machine and the artifact evaluation discussion
would shift from "did the methodology hold" to "did Flask 2 or 3
install cleanly". Stdlib is enough for the read-mostly,
single-reviewer workload.

## Security choices (for artifact evaluation)

- **Path traversal**: the ``/evidence/<relative>`` route resolves the
  requested path and rejects with HTTP 403/404 when the resolved file
  is outside ``release/evidence/``. Verified with
  ``curl http://127.0.0.1:8765/evidence/../../../../etc/passwd`` → HTTP
  404.
- **XSS**: the front-end uses ``textContent`` and
  ``document.createElement`` exclusively for any dynamic value
  (campaign IDs, job IDs, stdout tails). The only template literal in
  the page is the static shell. Subprocess output cannot inject HTML
  into the DOM.
- **Bind address**: defaults to ``127.0.0.1``; the reviewer must
  explicitly pass ``--bind 0.0.0.0`` to expose to the network.
- **Honest errors**: the server propagates JSON decode errors,
  subprocess errors, and HTTP errors instead of returning a generic
  "500 internal error" silently. A reviewer sees what failed.

## Endpoints

| Verb | Path | Purpose |
|---|---|---|
| GET | ``/`` | Reviewer-facing HTML console |
| GET | ``/dashboard`` | Static dashboard (if built) |
| GET | ``/api/campaigns`` | JSON list of all known campaign IDs |
| GET | ``/api/runs`` | JSON list of most recent 40 runs (mtime-sorted) |
| GET | ``/api/jobs`` | JSON list of in-flight + recently completed jobs |
| POST | ``/api/runs`` | Trigger a run; body ``{"campaign_id": "..."}`` |
| GET | ``/evidence/<path>`` | Serve any file under ``release/evidence/`` (path-confined) |

## Usage

```bash
.venv/bin/python scripts/reviewer_server.py --port 8765
# Open http://localhost:8765 in a browser.
# The page lists all 18 available campaigns. Select one, click "Run",
# watch the stdout stream into the page in real time.
```

## End-to-end smoke (this is also the regression test)

```text
=== GET / ===
<!doctype html><html lang='en'> ...

=== GET /api/campaigns ===
18 campaigns returned

=== GET /api/runs ===
40 recent runs, sorted by mtime

=== POST /api/runs ===
{"job_id": "job_<10hex>", "campaign_id": "0.cve_2021_41773"}

=== GET /api/jobs ===
job in state "running"

=== GET /evidence/../../../../etc/passwd ===
HTTP 404 (path escape rejected)
```
