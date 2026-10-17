#!/usr/bin/env python3
"""Bind the predeclared R4 v2 template to one clean source revision before execution.

The template describes the matrix but deliberately carries no candidate commit. This command
creates the immutable execution instance consumed by ``run_interruption_matrix.py``. It refuses a
dirty source state, an untracked or modified template, and an existing output path; a field trial
therefore cannot silently select its code revision or overwrite a previous protocol instance.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from infrastructure.revision import current_revision  # noqa: E402

_COMMIT_SHA256 = re.compile(r"^[0-9a-f]{40}$")


def freeze_protocol(template: dict, *, template_sha256: str, revision: str) -> dict:
    """Return a deterministic frozen v2 protocol instance from a predeclared template."""

    if template.get("schema_version") != "r4-interruption-protocol/v2":
        raise ValueError("only an R4 v2 template can be frozen")
    if template.get("status") != "predeclared_before_execution":
        raise ValueError("only a predeclared R4 v2 template can be frozen")
    if not _COMMIT_SHA256.fullmatch(revision):
        raise ValueError("revision must be an immutable 40-character git commit")
    requirements = template.get("execution_requirements")
    if not isinstance(requirements, dict):
        raise ValueError("template lacks execution requirements")
    if requirements.get("implementation_revision") != "immutable_clean_commit":
        raise ValueError("template does not require an immutable clean commit")
    frozen = json.loads(json.dumps(template))
    frozen["status"] = "frozen_for_execution"
    frozen["frozen_revision"] = revision
    frozen["template_sha256"] = template_sha256
    return frozen


def _relative_to_project(path: Path) -> str:
    try:
        return path.resolve().relative_to(PROJECT_ROOT.resolve()).as_posix()
    except ValueError as error:
        raise ValueError("protocol paths must stay under the artifact root") from error


def _require_tracked_clean_template(template_path: Path) -> None:
    """Ensure the template itself is a committed input, rather than an edited local draft."""

    relative = _relative_to_project(template_path)
    subprocess.run(
        ["git", "ls-files", "--error-unmatch", "--", relative],
        cwd=PROJECT_ROOT,
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    status = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=all", "--", relative],
        cwd=PROJECT_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    if status.stdout.strip():
        raise ValueError("protocol template must be committed and unmodified before freezing")


def _write_new_json(path: Path, payload: dict) -> None:
    if path.exists():
        raise FileExistsError(f"refusing to overwrite frozen protocol: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--template",
        type=Path,
        default=(
            PROJECT_ROOT
            / "release"
            / "experiments"
            / "r4_interruption_matrix_protocol_v2.json"
        ),
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    args = parser.parse_args()

    if not _COMMIT_SHA256.fullmatch(args.revision):
        parser.error("--revision must be an immutable 40-character git commit")
    observed_revision = current_revision(PROJECT_ROOT)
    if observed_revision != args.revision:
        parser.error("--revision must match the current clean source revision")
    try:
        _require_tracked_clean_template(args.template)
        output = args.output.resolve()
        _relative_to_project(output)
        template_bytes = args.template.read_bytes()
        template = json.loads(template_bytes)
        if not isinstance(template, dict):
            raise ValueError("protocol template must be a JSON object")
        frozen = freeze_protocol(
            template,
            template_sha256=hashlib.sha256(template_bytes).hexdigest(),
            revision=args.revision,
        )
        _write_new_json(output, frozen)
    except (OSError, ValueError, json.JSONDecodeError, subprocess.CalledProcessError) as error:
        parser.error(str(error))
    print(f"[r4-freeze] frozen protocol: {output.relative_to(PROJECT_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
