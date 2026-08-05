#!/usr/bin/env python3
"""Verify an extracted AutoSUT artifact against ``ARTIFACT_MANIFEST.md``.

The check is intentionally exact: every packaged file (apart from the manifest
itself and Git administrative state) must be listed, and every listed path must
match both its byte count and SHA-256 digest.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
from pathlib import Path


COUNT_RE = re.compile(r"^- Files: `(?P<count>\d+)`$", re.MULTILINE)
ROW_RE = re.compile(
    r"^\| `(?P<path>[^`]+)` \| (?P<size>\d+) \| `(?P<digest>[0-9a-f]{64})` \|$",
    re.MULTILINE,
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _parse_manifest(manifest: Path) -> tuple[int, dict[str, tuple[int, str]]]:
    text = manifest.read_text(encoding="utf-8")
    count_match = COUNT_RE.search(text)
    if count_match is None:
        raise ValueError("manifest is missing the declared file count")

    entries: dict[str, tuple[int, str]] = {}
    for match in ROW_RE.finditer(text):
        relative = match.group("path")
        path = Path(relative)
        if path.is_absolute() or relative in {"", "."} or ".." in path.parts:
            raise ValueError(f"manifest contains unsafe path: {relative!r}")
        if relative in entries:
            raise ValueError(f"manifest contains duplicate path: {relative}")
        entries[relative] = (int(match.group("size")), match.group("digest"))

    declared_count = int(count_match.group("count"))
    if len(entries) != declared_count:
        raise ValueError(
            f"manifest declares {declared_count} files but contains {len(entries)} rows"
        )
    return declared_count, entries


def _actual_files(
    root: Path,
    manifest: Path,
    *,
    allow_runtime_state: bool = False,
    expected_paths: set[str] | None = None,
) -> tuple[dict[str, Path], list[str]]:
    files: dict[str, Path] = {}
    errors: list[str] = []
    manifest_resolved = manifest.resolve()
    expected_paths = expected_paths or set()
    for path in sorted(root.rglob("*")):
        relative_path = path.relative_to(root)
        if ".git" in relative_path.parts:
            continue
        relative = relative_path.as_posix()
        if (
            allow_runtime_state
            and relative not in expected_paths
            and _is_allowed_runtime_path(relative)
        ):
            continue
        if path.is_symlink():
            errors.append(f"symbolic link is not allowed: {relative}")
            continue
        if not path.is_file() or path.resolve() == manifest_resolved:
            continue
        files[relative] = path
    return files, errors


def _is_allowed_runtime_path(relative: str) -> bool:
    """Return whether an unlisted path is documented local runtime state."""
    path = Path(relative)
    # A reviewer's virtual environment may carry any name, so match the family rather
    # than the literal directory: its symlinks must not fail a check about the shipped tree.
    if any(part == "venv" or part.startswith(".venv") for part in path.parts):
        return True
    if any(
        part
        in {
            ".venv",
            ".pytest_cache",
            ".mypy_cache",
            ".ruff_cache",
            ".tox",
            ".nox",
            "__pycache__",
            ".vagrant",
            "htmlcov",
        }
        for part in path.parts
    ):
        return True
    if path.suffix in {".pyc", ".pyo"} or path.name in {".DS_Store", ".coverage"}:
        return True
    runtime_prefixes = (
        "autosut/data/artifacts/",
        "autosut/release/evidence/",
        "autosut/results/evidence/",
    )
    if relative.startswith(runtime_prefixes):
        return True
    if relative.startswith((
        "autosut/release/orchestrated_replay_",
        "autosut/release/concurrent_batch_",
        "autosut/results/tables/all_tables_",
    )):
        return True
    return False


def verify_manifest(
    root: Path,
    manifest: Path,
    *,
    allow_runtime_state: bool = False,
) -> list[str]:
    """Return all integrity errors; an empty list means exact agreement."""
    root = root.resolve()
    manifest = manifest.resolve()
    if not root.is_dir():
        return [f"artifact root is not a directory: {root}"]
    if not manifest.is_file():
        return [f"manifest does not exist: {manifest}"]
    try:
        manifest.relative_to(root)
    except ValueError:
        return [f"manifest must be inside artifact root: {manifest}"]

    try:
        _, expected = _parse_manifest(manifest)
    except (OSError, UnicodeError, ValueError) as exc:
        return [str(exc)]

    actual, errors = _actual_files(
        root,
        manifest,
        allow_runtime_state=allow_runtime_state,
        expected_paths=set(expected),
    )
    expected_paths = set(expected)
    actual_paths = set(actual)
    for relative in sorted(expected_paths - actual_paths):
        errors.append(f"listed file is missing: {relative}")
    unlisted = sorted(actual_paths - expected_paths)
    if allow_runtime_state:
        unlisted = [path for path in unlisted if not _is_allowed_runtime_path(path)]
    for relative in unlisted:
        errors.append(f"unlisted file is present: {relative}")

    for relative in sorted(expected_paths & actual_paths):
        expected_size, expected_digest = expected[relative]
        path = actual[relative]
        actual_size = path.stat().st_size
        if actual_size != expected_size:
            errors.append(
                f"size mismatch: {relative} "
                f"(expected {expected_size}, got {actual_size})"
            )
            continue
        actual_digest = _sha256(path)
        if actual_digest != expected_digest:
            errors.append(
                f"SHA-256 mismatch: {relative} "
                f"(expected {expected_digest}, got {actual_digest})"
            )
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=Path.cwd(),
        help="extracted artifact root (default: current directory)",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path("ARTIFACT_MANIFEST.md"),
        help="manifest path, relative to --root unless absolute",
    )
    parser.add_argument(
        "--allow-runtime-state",
        action="store_true",
        help=(
            "allow unlisted local runtime state (.venv, Python caches, and "
            "reviewer-generated evidence/replay reports); all manifest-listed "
            "files are still checked exactly"
        ),
    )
    args = parser.parse_args(argv)
    root = args.root.resolve()
    manifest = args.manifest
    if not manifest.is_absolute():
        manifest = root / manifest

    errors = verify_manifest(
        root,
        manifest,
        allow_runtime_state=args.allow_runtime_state,
    )
    if errors:
        for error in errors:
            print(f"[manifest-check][FAIL] {error}", file=sys.stderr)
        return 1

    _, entries = _parse_manifest(manifest)
    print(f"[manifest-check] PASS: {len(entries)} files match size and SHA-256")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
