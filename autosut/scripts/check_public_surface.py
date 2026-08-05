#!/usr/bin/env python3
"""
Audit the public repository surface for publication blockers.
"""

from __future__ import annotations

import json
import os
import subprocess
from functools import lru_cache
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_JSON = PROJECT_ROOT / "results" / "public_surface_report.json"
OUTPUT_MD = PROJECT_ROOT / "results" / "PUBLIC_SURFACE_REPORT.md"

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
    "scripts/run_arm_comparison.py",
    "scripts/generate_tables.py",
    "scripts/run_lab_campaign.py",
    "release/inputs/sticks/c0045-v1/manifest.json",
    "release/experiments/arm_comparison/C0045.json",
    "release/experiments/C0045_EXECUTION_GATE.md",
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
    "measurement/sut/README.md",
    "measurement/sut/README_REPRODUCIBILITY.md",
    "measurement/sut/CLAIMS_TO_EVIDENCE.md",
    "README_MULTI_VM.md",
    "docs/README.md",
    "docs/reproducibility.md",
    "docs/reviewer_quickstart.md",
    "docs/README_REALISTIC.md",
]

FORBIDDEN_SNIPPETS = [
    "main.py init",
    "lib/run_campaign.py",
    "Caldera 5.3.0",
    "Apple Silicon M4 Max",
    "3-VM Caldera Setup",
    "sticks/vagrant",
    "8/8 techniques successful",
    "fully isolated virtual testbed",
    "ACM " + "CC" + "S",
    "N" + "DSS " + "2026",
    "camera-" + "ready",
    "submission " + "freeze",
]

SENSITIVE_TEXT_SNIPPETS = [
    str(Path.home()),
]

TEXT_EXTENSIONS = {
    ".json",
    ".md",
    ".rb",
    ".tex",
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
    found = set(existing_paths(LOCAL_RUNTIME_ARTIFACTS))
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


def is_runtime_state(path: Path) -> bool:
    """Return whether a relative path belongs to reviewer-created state."""
    return any(part in RUNTIME_DIRECTORY_NAMES for part in path.parts) or (
        path.name == ".coverage" or path.suffix in {".pyc", ".pyo"}
    )


def find_sensitive_text_hits() -> list[dict[str, str]]:
    hits: list[dict[str, str]] = []
    for path in PROJECT_ROOT.rglob("*"):
        if not path.is_file():
            continue
        if path in {OUTPUT_JSON, OUTPUT_MD}:
            continue
        relative = path.relative_to(PROJECT_ROOT)
        if is_runtime_state(relative):
            continue
        if (
            path.suffix.lower() not in TEXT_EXTENSIONS
            and path.name not in TEXT_FILENAMES
        ):
            continue
        relative_path = relative.as_posix()
        if is_git_worktree() and is_git_ignored(relative_path):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for snippet in SENSITIVE_TEXT_SNIPPETS:
            if snippet in text:
                hits.append({"path": relative_path, "snippet": snippet})
    return hits


@lru_cache(maxsize=1)
def is_git_worktree() -> bool:
    """Detect a checkout even when the artifact is nested in a monorepo."""
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
        return relative_path in LOCAL_RUNTIME_ARTIFACTS or any(
            part in RUNTIME_DIRECTORY_NAMES for part in path.parts
        ) or (
            path.name == ".coverage" or path.suffix in {".pyc", ".pyo"}
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
    ignored_structure_smells, blocker_structure_smells = split_structure_smells(
        structure_smells
    )
    forbidden_hits = find_forbidden_hits()
    sensitive_text_hits = find_sensitive_text_hits()

    return {
        "required_paths_checked": REQUIRED_PATHS,
        "missing_required_paths": required_missing,
        "sensitive_paths_present": sensitive_paths,
        "forbidden_text_hits": forbidden_hits,
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
            and not sensitive_text_hits
            and not blocker_paths
            and not blocker_structure_smells
            else "needs_attention"
        ),
    }


def write_markdown(report: dict) -> None:
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

    lines.extend(["", "## Sensitive Text Hits", ""])
    if report["sensitive_text_hits"]:
        for hit in report["sensitive_text_hits"]:
            lines.append(f"- `{hit['path']}` contains `{hit['snippet']}`")
    else:
        lines.append("- None")

    lines.extend(["", "## Local Runtime Artifacts Present", ""])
    if report["local_runtime_artifacts_present"]:
        lines.extend(
            f"- `{path}`" for path in report["local_runtime_artifacts_present"]
        )
    else:
        lines.append("- None")

    lines.extend(["", "## Ignored Local Runtime Artifacts", ""])
    if report["ignored_local_runtime_artifacts"]:
        lines.extend(
            f"- `{path}`" for path in report["ignored_local_runtime_artifacts"]
        )
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
    OUTPUT_JSON.write_text(json.dumps(report, indent=2), encoding="utf-8")
    write_markdown(report)
    print(f"Wrote {OUTPUT_JSON}")
    print(f"Wrote {OUTPUT_MD}")
    if report["status"] != "clean":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
