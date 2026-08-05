from __future__ import annotations

import hashlib
from pathlib import Path

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
