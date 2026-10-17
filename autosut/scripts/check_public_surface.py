#!/usr/bin/env python3
"""
Audit the public repository surface for publication blockers.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import lzma
import os
import re
import shutil
import subprocess
from functools import lru_cache
from itertools import pairwise
from pathlib import Path

if __package__ in {None, ""}:
    from measurement_diagnostics import is_measurement_log_path
else:
    from scripts.measurement_diagnostics import is_measurement_log_path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
# The public-surface audit is a reviewer-local observation.  It is useful to
# retain after a run, but it is not claim evidence and therefore must not
# become an immutable release-manifest entry merely because the audit ran.
RUNTIME_REPORT_DIRECTORY = PROJECT_ROOT / "results" / "reviewer_runtime"
OUTPUT_JSON = RUNTIME_REPORT_DIRECTORY / "public_surface_report.json"
OUTPUT_MD = RUNTIME_REPORT_DIRECTORY / "PUBLIC_SURFACE_REPORT.md"
DECLARED_RUNTIME_REPORT_PATHS = frozenset(
    {
        "results/reviewer_runtime/public_surface_report.json",
        "results/reviewer_runtime/PUBLIC_SURFACE_REPORT.md",
        "results/reviewer_runtime/review-report.json",
    }
)

REQUIRED_PATHS = [
    "run_review_check.sh",
    "run_vm_backed_campaign.sh",
    "README.md",
    "REVIEWER_GUIDE.md",
    "REPRODUCIBILITY.md",
    "MANIFEST.md",
    "ARCHITECTURE.md",
    "PUBLIC_REPOSITORY_SCOPE.md",
    "artifact/setup.sh",
    "artifact/run.sh",
    "artifact/validate.sh",
    "scripts/run_campaign.py",
    "scripts/run_reviewer_workflow.sh",
    "scripts/publish_study_values.py",
    "scripts/validate_claim_surface.py",
    "scripts/run_arm_comparison.py",
    "scripts/generate_tables.py",
    "scripts/run_lab_campaign.py",
    "release/inputs/sticks/c0045-v1/manifest.json",
    "release/experiments/arm_comparison/C0045.json",
    "release/experiments/C0045_EXECUTION_GATE.md",
    "release/study_values.tex",
]

SENSITIVE_PATHS = [
    "measurement/.env",
    "measurement/meta",
    "results/evidence",
    "results/frozen",
    "config.json",
    "config.local.json",
]

PUBLIC_DOCS = [
    "README.md",
    "REVIEWER_GUIDE.md",
    "REPRODUCIBILITY.md",
    "ARCHITECTURE.md",
    "PUBLIC_REPOSITORY_SCOPE.md",
    "measurement/sut/CLAIMS_TO_EVIDENCE.md",
    "README_MULTI_VM.md",
    "docs/README.md",
    "docs/reproducibility.md",
    "docs/reviewer_quickstart.md",
    "docs/README_REALISTIC.md",
    "docs/architecture.md",
    "docs/architecture/EXECUTION_MODEL.md",
    "docs/architecture/PROPOSAL_ADMISSION_BOUNDARY.md",
    "docs/SEMANTIC_ENRICHMENT_PROTOCOL.md",
    "docs/WINDOWS_PROVIDER_DEVELOPMENT.md",
    "docs/NATIVE_WINDOWS_CORPUS_ADJUDICATION.md",
]

REQUIRED_DOCUMENTATION_SNIPPETS = {
    "ARCHITECTURE.md": (
        "bash run_review_check.sh",
        "Docker is required for the live replay.",
    ),
    "docs/architecture/PROPOSAL_ADMISSION_BOUNDARY.md": (
        "D2: fixed catalog and deterministic binding",
        "D3: bounded proposal with deterministic admission",
    ),
}

FORBIDDEN_SNIPPETS = [
    "main.py init",
    "lib/run_campaign.py",
    "Caldera 5.3.0",
    "Apple Silicon M4 Max",
    "3-VM Caldera Setup",
    "sticks/vagrant",
    "8/8 techniques successful",
    "fully isolated virtual testbed",
    "Validated 2026-05-26",
    "caldera_manager.py",
    "reviewer_server.py",
    "Live Reviewer Console",
    "STICKS artifact",
    "one representative campaign",
    "CAMPAIGN_SUT_FIDELITY_MATRIX",
    "The first two paths are the canonical validation contract.",
    "supported, but intentionally heavier.",
    "STICKS ",
]

# Venue names, submission vocabulary and retired review-artifact identifiers, stored as
# BLAKE2b-64 digests of one token or a two-token phrase so the gate never names them.
ADMINISTRATIVE_TERM_DIGESTS = frozenset({
    "f99b60544109131b", "6abb237e042beeb1", "2bd2e89df314690e", "35761706649dfae9",
    "e2d1a66b4bbcd176", "ef07ec9ae38539e0", "443ca6e9b967b7fc", "7084f2296a863a84",
    "c65be06972bc44e0", "d084ce99e0f80a0d", "fca7e0a67e0df247", "5130d41c1fa99469",
    "a393b7f69e9b2fd8", "4b17966e631f798a", "026d8cd4ef2c656d", "6b198f90d1af0517",
    "f3353b5558ad8c26", "2c0305ba00de25c7", "36a075564c31102a", "9e86c3249a8c8180",
})
TERM_TOKEN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9&.\-]*[A-Za-z0-9])?")
# Vendored third-party datasets quote paper citations verbatim and are exempt.
THIRD_PARTY_DATA_PREFIXES = (
    "data/stix/",
    "measurement/sut/scripts/data/",
)

SENSITIVE_TEXT_PATTERNS = {
    "OpenAI/Anthropic secret-key token": re.compile(
        r"\bsk-(?:proj-|ant-api\d{2}-)[A-Za-z0-9_-]{20,}"
    ),
    "GitHub personal-access token": re.compile(r"\bghp_[A-Za-z0-9]{20,}"),
    "private-key material": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
}


def term_digest(term: str) -> str:
    return hashlib.blake2b(term.encode("utf-8"), digest_size=8).hexdigest()


def contains_administrative_term(text: str) -> bool:
    tokens = TERM_TOKEN.findall(text)
    phrases = (f"{first} {second}" for first, second in pairwise(tokens))
    return any(term_digest(gram) in ADMINISTRATIVE_TERM_DIGESTS for gram in (*tokens, *phrases))


def home_path_snippets(home: Path) -> list[str]:
    """Treat named homes as private, excluding generic container directories."""
    generic_homes = {Path("/"), Path("/root"), Path("/tmp"), Path("/var/tmp")}
    return [] if home in generic_homes else [str(home)]


SENSITIVE_TEXT_SNIPPETS = home_path_snippets(Path.home())

MAX_EXPANDED_GZIP_BYTES = 64 * 1024 * 1024
MAX_EXPANDED_XZ_BYTES = 512 * 1024 * 1024
AUDIT_CHUNK_BYTES = 1024 * 1024
AUDIT_OVERLAP_BYTES = 4096


def public_file_payload(path: Path) -> bytes:
    """Read a packaged file, including bounded gzip content, without skipping it."""
    data = path.read_bytes()
    if not data.startswith(b"\x1f\x8b"):
        return data
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as archive:
        expanded = archive.read(MAX_EXPANDED_GZIP_BYTES + 1)
    if len(expanded) > MAX_EXPANDED_GZIP_BYTES:
        raise ValueError(f"gzip content exceeds audit limit: {path}")
    return expanded


def public_file_views(path: Path):
    """Yield bounded decoded views of raw, gzip, or XZ package content."""
    with path.open("rb") as source:
        header = source.read(6)
    if header.startswith(b"\xfd7zXZ\x00"):
        previous = b""
        expanded_bytes = 0
        with lzma.open(path, "rb") as archive:
            while block := archive.read(AUDIT_CHUNK_BYTES):
                expanded_bytes += len(block)
                if expanded_bytes > MAX_EXPANDED_XZ_BYTES:
                    raise ValueError(f"XZ content exceeds audit limit: {path}")
                window = previous + block
                yield from decoded_views(window)
                previous = window[-AUDIT_OVERLAP_BYTES:]
        return
    yield from decoded_views(public_file_payload(path))


def decoded_views(data: bytes):
    yield data.decode("utf-8", errors="replace")
    if b"\x00" in data:
        yield data.decode("utf-16le", errors="ignore")
        yield data.decode("utf-16be", errors="ignore")

TEXT_EXTENSIONS = {
    ".cfg",
    ".css",
    ".csv",
    ".html",
    ".ini",
    ".js",
    ".json",
    ".md",
    ".py",
    ".rb",
    ".sh",
    ".tex",
    ".toml",
    ".txt",
    ".tsv",
    ".yaml",
    ".yml",
}

TEXT_FILENAMES = {
    "Vagrantfile",
}

LOCAL_RUNTIME_ARTIFACTS = [
    ".venv",
    ".pytest_cache",
    "__pycache__",
    "src/executors/__pycache__",
    "src/loaders/__pycache__",
    "tests/__pycache__",
    "lab/vagrant/.vagrant",
    "measurement/sut/.vagrant",
    "cloud-init/seed.iso",
    "cloud-init/run-overlay.qcow2",
    "cloud-init/vars.fd",
    "cloud-init/meta-data",
    "cloud-init/user-data",
    "cloud-init/iso-root",
    "run-overlay.qcow2",
    "vars.fd",
    "edk2-aarch64-code.fd",
    "sticks-arm64-qemu.box",
    "sticks-simple.box",
    "sticks-box",
    "sticks-box-simple",
    "evidence/qemu-base",
    "evidence/qemu-multi",
    "results/exploratory",
    "removed_reports",
]

RUNTIME_DIRECTORY_NAMES = {
    ".venv",
    ".vagrant",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".tox",
    ".nox",
    "__pycache__",
    "node_modules",
}

STRUCTURE_SMELLS = [
    "docs/docs",
    "docs/artifact_guide",
    "docs/reproducibility",
    "lab/qeu",
]


def existing_paths(paths: list[str]) -> list[str]:
    return [path for path in paths if (PROJECT_ROOT / path).exists()]


def find_local_runtime_artifacts() -> list[str]:
    """Find runtime state at any depth, including per-machine Vagrant dirs."""
    found = {
        relative
        for relative in LOCAL_RUNTIME_ARTIFACTS
        if (path := PROJECT_ROOT / relative).is_file() or (path.is_dir() and any(path.iterdir()))
    }
    for current_root, directory_names, file_names in os.walk(PROJECT_ROOT):
        current_path = Path(current_root)
        for directory_name in list(directory_names):
            if directory_name not in RUNTIME_DIRECTORY_NAMES:
                continue
            runtime_path = current_path / directory_name
            found.add(runtime_path.relative_to(PROJECT_ROOT).as_posix())
            directory_names.remove(directory_name)
        for file_name in file_names:
            path = current_path / file_name
            if path.name == ".coverage" or path.suffix in {".pyc", ".pyo"}:
                found.add(path.relative_to(PROJECT_ROOT).as_posix())
    return sorted(found)


def missing_paths(paths: list[str]) -> list[str]:
    return [path for path in paths if not (PROJECT_ROOT / path).exists()]


def find_forbidden_hits() -> list[dict[str, str]]:
    hits: list[dict[str, str]] = []
    for relative_path in PUBLIC_DOCS:
        path = PROJECT_ROOT / relative_path
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8")
        for snippet in FORBIDDEN_SNIPPETS:
            if snippet in text:
                hits.append({"path": relative_path, "snippet": snippet})
    return hits


def find_missing_documentation_snippets() -> list[dict[str, str]]:
    """Require the public architecture to retain its critical claim boundaries."""
    missing: list[dict[str, str]] = []
    for relative_path, snippets in REQUIRED_DOCUMENTATION_SNIPPETS.items():
        path = PROJECT_ROOT / relative_path
        if not path.is_file():
            missing.extend({"path": relative_path, "snippet": snippet} for snippet in snippets)
            continue
        text = path.read_text(encoding="utf-8")
        missing.extend(
            {"path": relative_path, "snippet": snippet}
            for snippet in snippets
            if snippet not in text
        )
    return missing


def is_runtime_state(path: Path) -> bool:
    """Return whether a relative path belongs to reviewer-created state."""
    return (
        path.as_posix() in DECLARED_RUNTIME_REPORT_PATHS
        or is_measurement_log_path(path)
        or any(part in RUNTIME_DIRECTORY_NAMES for part in path.parts)
        or (path.name == ".coverage" or path.suffix in {".pyc", ".pyo"})
    )


def iter_public_files() -> list[Path]:
    """List files that can enter a public package without scanning local caches."""
    if is_git_worktree():
        completed = subprocess.run(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        paths = [PROJECT_ROOT / relative for relative in completed.stdout.split("\0") if relative]
        return sorted(path for path in paths if path.is_file())

    files: list[Path] = []
    for current_root, directory_names, file_names in os.walk(PROJECT_ROOT):
        directory_names[:] = [
            name
            for name in directory_names
            if name != ".git" and name not in RUNTIME_DIRECTORY_NAMES
        ]
        current_path = Path(current_root)
        for file_name in file_names:
            path = current_path / file_name
            if not is_runtime_state(path.relative_to(PROJECT_ROOT)):
                files.append(path)
    return sorted(files)


def find_sensitive_text_hits() -> list[dict[str, str]]:
    hits: list[dict[str, str]] = []
    for path in iter_public_files():
        if path in {OUTPUT_JSON, OUTPUT_MD}:
            continue
        relative = path.relative_to(PROJECT_ROOT)
        if is_runtime_state(relative):
            continue
        relative_path = relative.as_posix()
        found: set[str] = set()
        for view in public_file_views(path):
            for snippet in SENSITIVE_TEXT_SNIPPETS:
                if snippet not in found and snippet in view:
                    found.add(snippet)
                    hits.append({"path": relative_path, "snippet": snippet})
            for label, pattern in SENSITIVE_TEXT_PATTERNS.items():
                if label not in found and pattern.search(view):
                    found.add(label)
                    hits.append({"path": relative_path, "snippet": label})
            if (
                (path.suffix.lower() in TEXT_EXTENSIONS or path.name in TEXT_FILENAMES)
                and not relative_path.startswith(THIRD_PARTY_DATA_PREFIXES)
                and "venue or submission term" not in found
                and contains_administrative_term(view)
            ):
                found.add("venue or submission term")
                hits.append({"path": relative_path, "snippet": "venue or submission term"})
    return hits


@lru_cache(maxsize=1)
def is_git_worktree() -> bool:
    """Detect a checkout even when the artifact is nested in a monorepo."""
    if shutil.which("git") is None:
        return False
    result = subprocess.run(
        ["git", "rev-parse", "--is-inside-work-tree"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    return result.returncode == 0 and result.stdout.strip() == "true"


def is_git_ignored(relative_path: str) -> bool:
    # ZIP downloads from anonymous mirrors do not include .git metadata. Treat
    # reviewer-generated runtime paths as ignorable there too so the checker can
    # be run both before and after artifact/setup.sh.
    if not is_git_worktree():
        path = Path(relative_path)
        return (
            relative_path in LOCAL_RUNTIME_ARTIFACTS
            or any(part in RUNTIME_DIRECTORY_NAMES for part in path.parts)
            or (path.name == ".coverage" or path.suffix in {".pyc", ".pyo"})
        )

    result = subprocess.run(
        ["git", "check-ignore", relative_path],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    return result.returncode == 0


def split_runtime_artifacts(paths: list[str]) -> tuple[list[str], list[str]]:
    ignored: list[str] = []
    blockers: list[str] = []
    for path in paths:
        if is_git_ignored(path):
            ignored.append(path)
        else:
            blockers.append(path)
    return ignored, blockers


def split_structure_smells(paths: list[str]) -> tuple[list[str], list[str]]:
    ignored: list[str] = []
    blockers: list[str] = []
    for path in paths:
        if is_git_ignored(path):
            ignored.append(path)
        else:
            blockers.append(path)
    return ignored, blockers


def build_report() -> dict:
    required_missing = missing_paths(REQUIRED_PATHS)
    sensitive_paths = existing_paths(SENSITIVE_PATHS)
    runtime_paths = find_local_runtime_artifacts()
    ignored_runtime_paths, blocker_paths = split_runtime_artifacts(runtime_paths)
    structure_smells = existing_paths(STRUCTURE_SMELLS)
    ignored_structure_smells, blocker_structure_smells = split_structure_smells(structure_smells)
    forbidden_hits = find_forbidden_hits()
    missing_documentation_snippets = find_missing_documentation_snippets()
    sensitive_text_hits = find_sensitive_text_hits()

    return {
        "required_paths_checked": REQUIRED_PATHS,
        "missing_required_paths": required_missing,
        "sensitive_paths_present": sensitive_paths,
        "forbidden_text_hits": forbidden_hits,
        "missing_documentation_snippets": missing_documentation_snippets,
        "sensitive_text_hits": sensitive_text_hits,
        "ignored_local_runtime_artifacts": ignored_runtime_paths,
        "local_runtime_artifacts_present": blocker_paths,
        "ignored_structure_smells": ignored_structure_smells,
        "structure_smells_present": blocker_structure_smells,
        "status": (
            "clean"
            if not required_missing
            and not sensitive_paths
            and not forbidden_hits
            and not missing_documentation_snippets
            and not sensitive_text_hits
            and not blocker_paths
            and not blocker_structure_smells
            else "needs_attention"
        ),
    }


def write_markdown(report: dict) -> None:
    OUTPUT_MD.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Public Surface Report",
        "",
        f"- Status: `{report['status']}`",
        "",
        "## Missing Required Paths",
        "",
    ]

    if report["missing_required_paths"]:
        lines.extend(f"- `{path}`" for path in report["missing_required_paths"])
    else:
        lines.append("- None")

    lines.extend(["", "## Sensitive Paths Present", ""])
    if report["sensitive_paths_present"]:
        lines.extend(f"- `{path}`" for path in report["sensitive_paths_present"])
    else:
        lines.append("- None")

    lines.extend(["", "## Forbidden Text Hits", ""])
    if report["forbidden_text_hits"]:
        for hit in report["forbidden_text_hits"]:
            lines.append(f"- `{hit['path']}` contains `{hit['snippet']}`")
    else:
        lines.append("- None")

    lines.extend(["", "## Missing Required Documentation Commitments", ""])
    if report["missing_documentation_snippets"]:
        for item in report["missing_documentation_snippets"]:
            lines.append(f"- `{item['path']}` is missing `{item['snippet']}`")
    else:
        lines.append("- None")

    lines.extend(["", "## Sensitive Text Hits", ""])
    if report["sensitive_text_hits"]:
        for hit in report["sensitive_text_hits"]:
            lines.append(f"- `{hit['path']}` contains `{hit['snippet']}`")
    else:
        lines.append("- None")

    lines.extend(["", "## Local Runtime Artifacts Present", ""])
    if report["local_runtime_artifacts_present"]:
        lines.extend(f"- `{path}`" for path in report["local_runtime_artifacts_present"])
    else:
        lines.append("- None")

    lines.extend(["", "## Ignored Local Runtime Artifacts", ""])
    if report["ignored_local_runtime_artifacts"]:
        lines.extend(f"- `{path}`" for path in report["ignored_local_runtime_artifacts"])
    else:
        lines.append("- None")

    lines.extend(["", "## Structure Smells Present", ""])
    if report["structure_smells_present"]:
        lines.extend(f"- `{path}`" for path in report["structure_smells_present"])
    else:
        lines.append("- None")

    lines.extend(["", "## Ignored Structure Smells", ""])
    if report["ignored_structure_smells"]:
        lines.extend(f"- `{path}`" for path in report["ignored_structure_smells"])
    else:
        lines.append("- None")

    OUTPUT_MD.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    report = build_report()
    OUTPUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_JSON.write_text(json.dumps(report, indent=2), encoding="utf-8")
    write_markdown(report)
    print(f"Wrote {OUTPUT_JSON}")
    print(f"Wrote {OUTPUT_MD}")
    if report["status"] != "clean":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
