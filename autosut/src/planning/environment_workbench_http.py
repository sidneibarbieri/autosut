"""Loopback-only HTTP adapter for environment planning, without execution."""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlsplit

from pydantic import ValidationError

from .environment_workbench import plan_environment_payload

MAXIMUM_BODY_BYTES = 1024 * 1024
STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/environment-map.js": ("environment-map.js", "text/javascript; charset=utf-8"),
    "/styles.css": ("styles.css", "text/css; charset=utf-8"),
}


def build_handler(artifact_root: Path) -> type[BaseHTTPRequestHandler]:
    web_root = artifact_root / "web" / "environment-workbench"
    example = (
        artifact_root / "release/inputs/sticks/c0045-v1/C0045.procedural-plan.json"
    )

    class PlanningHandler(BaseHTTPRequestHandler):
        def _local_request(self) -> bool:
            allowed_hosts = {
                f"127.0.0.1:{self.server.server_port}",
                f"localhost:{self.server.server_port}",
            }
            host = self.headers.get("Host")
            origin = self.headers.get("Origin")
            return host in allowed_hosts and (
                origin is None or origin in {f"http://{item}" for item in allowed_hosts}
            )

        def _send(self, status: int, body: bytes, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; frame-ancestors 'none'; object-src 'none'",
            )
            self.end_headers()
            self.wfile.write(body)

        def _json(self, status: int, payload: object) -> None:
            self._send(
                status, json.dumps(payload).encode(), "application/json; charset=utf-8"
            )

        def do_GET(self) -> None:  # noqa: N802
            if not self._local_request():
                self._json(403, {"error": "local_origin_required"})
                return
            path = urlsplit(self.path).path
            if path == "/api/example":
                self._send(200, example.read_bytes(), "application/json; charset=utf-8")
                return
            asset = STATIC_FILES.get(path)
            if asset is None:
                self._json(404, {"error": "not_found"})
                return
            filename, content_type = asset
            self._send(200, (web_root / filename).read_bytes(), content_type)

        def do_POST(self) -> None:  # noqa: N802
            if not self._local_request():
                self._json(403, {"error": "local_origin_required"})
                return
            if urlsplit(self.path).path != "/api/plan":
                self._json(404, {"error": "not_found"})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self._json(400, {"error": "invalid_length"})
                return
            if not 1 <= length <= MAXIMUM_BODY_BYTES:
                self._json(
                    413, {"error": "body_size", "maximum_bytes": MAXIMUM_BODY_BYTES}
                )
                return
            try:
                payload = json.loads(self.rfile.read(length).decode("utf-8"))
                result = plan_environment_payload(payload)
            except ValidationError as error:
                self._json(
                    400,
                    {
                        "error": "invalid_plan",
                        "detail": error.errors(
                            include_input=False,
                            include_context=False,
                            include_url=False,
                        ),
                    },
                )
                return
            except (ValueError, UnicodeDecodeError) as error:
                self._json(400, {"error": "invalid_plan", "detail": str(error)})
                return
            self._json(200, result.model_dump(mode="json"))

    return PlanningHandler
