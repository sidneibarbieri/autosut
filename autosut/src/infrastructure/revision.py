"""The implementation revision a run executed on, so a qualification set is tied to one code state.

A reproducible result requires every run in a set to have executed on the same, current
implementation revision. Recording the code state with each run makes that check evidence-based: a
set produced before a later code change no longer matches the revision it is being asked to qualify.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path

# The revision identifies the implementation source only. Runtime and derived outputs (evidence
# bundles, qualification reports, the execution lock, generated results) must not perturb it, or a
# run's own outputs would change the id mid-set. These are the source directories that define it.
SOURCE_PATHSPEC = ("src", "scripts", "tests", "lab")
SOURCE_IGNORED_PARTS = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".vagrant",
    ".venv",
    "__pycache__",
    "runtime",
}
SOURCE_IGNORED_SUFFIXES = {".pyc", ".pyo"}
REVISION_PATTERN = re.compile(r"^[0-9a-f]{40}(?:\+tree-[0-9a-f]{16})?$")
REVISION_STAMP_FILENAME = "IMPLEMENTATION_REVISION.json"
REVISION_STAMP_SCHEMA = "autosut-implementation-revision/v1"


def included_source_path(relative: Path) -> bool:
    """Apply the implementation revision's source-file exclusions."""
    return not (
        set(relative.parts) & SOURCE_IGNORED_PARTS
        or relative.suffix in SOURCE_IGNORED_SUFFIXES
    )


def _git(project_root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args],
        cwd=project_root,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    ).stdout


def _untracked_source_digest(project_root: Path, listing: str) -> str:
    """A hash over each untracked, non-ignored source file's path and content."""
    digest = hashlib.sha256()
    for relative_path in sorted(line for line in listing.splitlines() if line):
        absolute = project_root / relative_path
        if not absolute.is_file():
            continue
        digest.update(relative_path.encode("utf-8"))
        digest.update(b"\0")
        digest.update(absolute.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def source_snapshot_digest(project_root: Path) -> str:
    """Hash the packaged implementation files without relying on Git metadata."""
    digest = hashlib.sha256()
    for source_directory in SOURCE_PATHSPEC:
        directory = project_root / source_directory
        if not directory.is_dir():
            continue
        for path in sorted(directory.rglob("*")):
            relative = path.relative_to(project_root)
            if (
                not path.is_file()
                or not included_source_path(relative)
            ):
                continue
            digest.update(relative.as_posix().encode("utf-8"))
            digest.update(b"\0")
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(65536), b""):
                    digest.update(chunk)
            digest.update(b"\0")
    return digest.hexdigest()


def write_revision_stamp(project_root: Path, revision: str) -> Path:
    """Bind a Git-derived revision to the implementation snapshot shipped in an archive."""
    if not REVISION_PATTERN.fullmatch(revision):
        raise ValueError(f"cannot stamp invalid implementation revision {revision!r}")
    payload = {
        "schema_version": REVISION_STAMP_SCHEMA,
        "revision": revision,
        "source_sha256": source_snapshot_digest(project_root),
    }
    path = project_root / REVISION_STAMP_FILENAME
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return path


def revision_from_stamp(project_root: Path) -> str:
    stamp_path = project_root / REVISION_STAMP_FILENAME
    if not stamp_path.is_file():
        return "no-git"
    payload = json.loads(stamp_path.read_text(encoding="utf-8"))
    required_keys = {"schema_version", "revision", "source_sha256"}
    if set(payload) != required_keys or payload["schema_version"] != REVISION_STAMP_SCHEMA:
        raise ValueError("invalid implementation revision stamp schema")
    revision = payload["revision"]
    source_sha256 = payload["source_sha256"]
    if not isinstance(revision, str) or not REVISION_PATTERN.fullmatch(revision):
        raise ValueError("implementation revision stamp has an invalid revision")
    if not isinstance(source_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", source_sha256):
        raise ValueError("implementation revision stamp has an invalid source hash")
    observed_digest = source_snapshot_digest(project_root)
    if observed_digest == source_sha256:
        return revision
    base_commit = revision.split("+tree-", maxsplit=1)[0]
    return f"{base_commit}+tree-{observed_digest[:16]}"


def current_revision(project_root: Path) -> str:
    """Identify the implementation-source state a run executed on, including uncommitted work.

    Scoped to the source directories only, so a run's own evidence, reports, and lock file never
    change the id: two different source states yield different ids, identical source yields the same
    id, and repeated runs on one source share it. On a source tree with no changes this is the git
    commit; otherwise it appends a hash over the tracked source blobs, the source diff, and each
    untracked non-ignored source file's content. Untracked files are included because most of the
    canonical implementation is not yet committed.
    """
    if (project_root / REVISION_STAMP_FILENAME).is_file():
        return revision_from_stamp(project_root)
    if shutil.which("git") is None:
        return revision_from_stamp(project_root)
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=project_root,
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )
    if head.returncode != 0:
        return revision_from_stamp(project_root)
    commit = head.stdout.strip()
    diff = _git(project_root, "diff", "HEAD", "--", *SOURCE_PATHSPEC)
    untracked = _git(
        project_root, "ls-files", "--others", "--exclude-standard", "--", *SOURCE_PATHSPEC
    ).strip()
    if not diff.strip() and not untracked:
        return commit
    tracked = _git(project_root, "ls-files", "-s", "--", *SOURCE_PATHSPEC)
    tree_hash = hashlib.sha256(
        (
            tracked
            + "\n---diff---\n"
            + diff
            + "\n---untracked---\n"
            + _untracked_source_digest(project_root, untracked)
        ).encode("utf-8")
    ).hexdigest()[:16]
    return f"{commit}+tree-{tree_hash}"
