from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
from pathlib import Path

from scripts import check_public_surface
from scripts.verify_artifact_manifest import verify_manifest


def _write_manifest(root: Path, files: list[Path]) -> Path:
    rows = []
    for path in sorted(files):
        relative = path.relative_to(root).as_posix()
        payload = path.read_bytes()
        rows.append(
            f"| `{relative}` | {len(payload)} | `{hashlib.sha256(payload).hexdigest()}` |"
        )
    manifest = root / "ARTIFACT_MANIFEST.md"
    manifest.write_text(
        "\n".join(
            [
                "# Artifact Manifest",
                "",
                f"- Files: `{len(rows)}`",
                "- Hash: SHA-256",
                "",
                "| Path | Bytes | SHA-256 |",
                "| --- | ---: | --- |",
                *rows,
                "",
            ]
        ),
        encoding="utf-8",
    )
    return manifest


def test_exact_manifest_passes(tmp_path: Path) -> None:
    first = tmp_path / "first.txt"
    second = tmp_path / "nested" / "second.bin"
    second.parent.mkdir()
    first.write_text("alpha\n", encoding="utf-8")
    second.write_bytes(b"\x00\x01\x02")
    manifest = _write_manifest(tmp_path, [first, second])

    assert verify_manifest(tmp_path, manifest) == []


def test_direct_manifest_cli_does_not_generate_local_bytecode(tmp_path):
    source = Path(__file__).resolve().parents[1] / "scripts"
    scripts = tmp_path / "autosut/scripts"
    scripts.mkdir(parents=True)
    for name in ("verify_artifact_manifest.py", "measurement_diagnostics.py"):
        shutil.copy2(source / name, scripts / name)
    _write_manifest(tmp_path, list(scripts.iterdir()))
    environment = dict(os.environ)
    environment.pop("PYTHONDONTWRITEBYTECODE", None)
    result = subprocess.run(
        [sys.executable, str(scripts / "verify_artifact_manifest.py"), "--root", str(tmp_path)],
        env=environment, capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stderr
    assert not list(tmp_path.rglob("__pycache__"))


def test_measurement_logs_have_exact_runtime_allowance(tmp_path):
    tracked = tmp_path / "tracked.txt"
    tracked.write_text("frozen\n")
    manifest = _write_manifest(tmp_path, [tracked])
    directory = tmp_path / "autosut/results/reviewer_runtime/measurement-A1b2C3"
    directory.mkdir(parents=True)
    log = directory / "measurement_pipeline_release.log"
    log.write_text("diagnostic\n")
    assert verify_manifest(tmp_path, manifest, allow_runtime_state=True) == []
    assert verify_manifest(tmp_path, manifest)
    unexpected = directory / "unlisted.txt"
    unexpected.write_text("not a diagnostic\n")
    assert any("unlisted.txt" in error for error in verify_manifest(
        tmp_path, manifest, allow_runtime_state=True,
    ))


def test_measurement_log_symlink_is_not_runtime_allowance(tmp_path):
    tracked = tmp_path / "tracked.txt"
    tracked.write_text("frozen\n")
    manifest = _write_manifest(tmp_path, [tracked])
    directory = tmp_path / "autosut/results/reviewer_runtime/measurement-A1b2C3"
    directory.mkdir(parents=True)
    (directory / "measurement_pipeline_release.log").symlink_to(tracked)
    assert any("symbolic link" in error for error in verify_manifest(
        tmp_path, manifest, allow_runtime_state=True,
    ))


def test_manifest_detects_missing_unlisted_and_changed_files(tmp_path: Path) -> None:
    listed = tmp_path / "listed.txt"
    missing = tmp_path / "missing.txt"
    listed.write_text("before\n", encoding="utf-8")
    missing.write_text("present\n", encoding="utf-8")
    manifest = _write_manifest(tmp_path, [listed, missing])

    listed.write_text("after!\n", encoding="utf-8")
    missing.unlink()
    (tmp_path / "unlisted.txt").write_text("extra\n", encoding="utf-8")

    errors = verify_manifest(tmp_path, manifest)
    assert any("SHA-256 mismatch: listed.txt" in error for error in errors)
    assert any("listed file is missing: missing.txt" in error for error in errors)
    assert any("unlisted file is present: unlisted.txt" in error for error in errors)


def test_manifest_rejects_unsafe_path(tmp_path: Path) -> None:
    manifest = tmp_path / "ARTIFACT_MANIFEST.md"
    manifest.write_text(
        "\n".join(
            [
                "# Artifact Manifest",
                "",
                "- Files: `1`",
                "- Hash: SHA-256",
                "",
                "| Path | Bytes | SHA-256 |",
                "| --- | ---: | --- |",
                f"| `../escape` | 0 | `{'0' * 64}` |",
                "",
            ]
        ),
        encoding="utf-8",
    )

    assert verify_manifest(tmp_path, manifest) == [
        "manifest contains unsafe path: '../escape'"
    ]


def test_runtime_state_requires_explicit_allowance(tmp_path: Path) -> None:
    tracked = tmp_path / "tracked.txt"
    tracked.write_text("tracked\n", encoding="utf-8")
    manifest = _write_manifest(tmp_path, [tracked])
    runtime = tmp_path / "autosut" / ".venv" / "state.txt"
    runtime.parent.mkdir(parents=True)
    runtime.write_text("local\n", encoding="utf-8")
    runtime_link = runtime.parent / "python3"
    runtime_link.symlink_to("state.txt")

    strict_errors = verify_manifest(tmp_path, manifest)
    assert "symbolic link is not allowed: autosut/.venv/python3" in strict_errors
    assert "unlisted file is present: autosut/.venv/state.txt" in strict_errors
    assert verify_manifest(
        tmp_path,
        manifest,
        allow_runtime_state=True,
    ) == []


def test_reviewer_generated_pairs_and_runs_are_runtime_state(tmp_path: Path) -> None:
    tracked = tmp_path / "tracked.txt"
    tracked.write_text("tracked\n", encoding="utf-8")
    manifest = _write_manifest(tmp_path, [tracked])
    generated = tmp_path / "autosut" / "runtime" / "review-pairs" / "pair.json"
    generated.parent.mkdir(parents=True)
    generated.write_text('{"status":"prepared"}\n', encoding="utf-8")

    assert "unlisted file is present: autosut/runtime/review-pairs/pair.json" in verify_manifest(
        tmp_path, manifest
    )
    assert verify_manifest(tmp_path, manifest, allow_runtime_state=True) == []
    tracked.write_text("changed\n", encoding="utf-8")
    assert any("tracked.txt" in error for error in verify_manifest(
        tmp_path, manifest, allow_runtime_state=True
    ))


def test_runtime_allowance_does_not_permit_external_symlinks(tmp_path: Path) -> None:
    tracked = tmp_path / "tracked.txt"
    tracked.write_text("tracked\n", encoding="utf-8")
    manifest = _write_manifest(tmp_path, [tracked])
    (tmp_path / "unexpected-link").symlink_to("tracked.txt")

    assert verify_manifest(
        tmp_path,
        manifest,
        allow_runtime_state=True,
    ) == ["symbolic link is not allowed: unexpected-link"]


def test_runtime_allowance_still_checks_manifest_listed_runtime_prefix(
    tmp_path: Path,
) -> None:
    replay = tmp_path / "autosut" / "release" / "orchestrated_replay_frozen.tsv"
    replay.parent.mkdir(parents=True)
    replay.write_text("frozen\n", encoding="utf-8")
    manifest = _write_manifest(tmp_path, [replay])
    replay.write_text("changed\n", encoding="utf-8")

    errors = verify_manifest(tmp_path, manifest, allow_runtime_state=True)
    assert any(
        error.startswith("size mismatch: autosut/release/orchestrated_replay_frozen.tsv")
        or error.startswith("SHA-256 mismatch: autosut/release/orchestrated_replay_frozen.tsv")
        for error in errors
    )


def test_runtime_allowance_ignores_nested_vm_and_tool_cache_state(tmp_path: Path) -> None:
    tracked = tmp_path / "tracked.txt"
    tracked.write_text("tracked\n", encoding="utf-8")
    manifest = _write_manifest(tmp_path, [tracked])
    runtime_files = (
        tmp_path / "autosut" / "lab" / "target" / ".vagrant" / "machine.id",
        tmp_path / "autosut" / ".ruff_cache" / "state",
        tmp_path / "autosut" / "htmlcov" / "index.html",
        tmp_path / "autosut" / ".coverage",
    )
    for path in runtime_files:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("local\n", encoding="utf-8")

    assert verify_manifest(tmp_path, manifest, allow_runtime_state=True) == []


def test_post_run_surface_reports_do_not_weaken_immutable_manifest(
    tmp_path: Path, monkeypatch
) -> None:
    """An audit report is local state; claim evidence remains byte-exact."""
    artifact_root = tmp_path / "autosut"
    for relative in check_public_surface.REQUIRED_PATHS:
        path = artifact_root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("fixture\n", encoding="utf-8")

    (artifact_root / "ARCHITECTURE.md").write_text(
        "bash run_review_check.sh\nDocker is required for the live replay.\n",
        encoding="utf-8",
    )
    proposal_boundary = (
        artifact_root / "docs" / "architecture" / "PROPOSAL_ADMISSION_BOUNDARY.md"
    )
    proposal_boundary.parent.mkdir(parents=True, exist_ok=True)
    proposal_boundary.write_text(
        "D2: fixed catalog and deterministic binding\n"
        "D3: bounded proposal with deterministic admission\n",
        encoding="utf-8",
    )

    immutable = (
        artifact_root / "release" / "experiments" / "arm_comparison" / "C0045.json"
    )
    manifest = _write_manifest(
        tmp_path, [path for path in tmp_path.rglob("*") if path.is_file()]
    )

    runtime_directory = artifact_root / "results" / "reviewer_runtime"
    monkeypatch.setattr(check_public_surface, "PROJECT_ROOT", artifact_root)
    monkeypatch.setattr(
        check_public_surface,
        "RUNTIME_REPORT_DIRECTORY",
        runtime_directory,
    )
    monkeypatch.setattr(
        check_public_surface,
        "OUTPUT_JSON",
        runtime_directory / "public_surface_report.json",
    )
    monkeypatch.setattr(
        check_public_surface,
        "OUTPUT_MD",
        runtime_directory / "PUBLIC_SURFACE_REPORT.md",
    )
    monkeypatch.setattr(check_public_surface, "is_git_worktree", lambda: False)

    check_public_surface.main()

    reviewer_report = runtime_directory / "review-report.json"
    reviewer_report.write_text("reviewer-local\n", encoding="utf-8")

    assert verify_manifest(tmp_path, manifest, allow_runtime_state=True) == []
    strict_errors = verify_manifest(tmp_path, manifest)
    assert any(
        "results/reviewer_runtime/public_surface_report.json" in error
        for error in strict_errors
    )
    assert any("results/reviewer_runtime/review-report.json" in error for error in strict_errors)

    unexpected = runtime_directory / "unexpected.json"
    unexpected.write_text("not a declared report\n", encoding="utf-8")
    runtime_errors = verify_manifest(tmp_path, manifest, allow_runtime_state=True)
    assert (
        "unlisted file is present: autosut/results/reviewer_runtime/unexpected.json"
        in runtime_errors
    )

    immutable.write_text("tampered\n", encoding="utf-8")
    tamper_errors = verify_manifest(tmp_path, manifest, allow_runtime_state=True)
    assert any(
        error.startswith(
            "size mismatch: autosut/release/experiments/arm_comparison/C0045.json"
        )
        or error.startswith(
            "SHA-256 mismatch: autosut/release/experiments/arm_comparison/C0045.json"
        )
        for error in tamper_errors
    )
