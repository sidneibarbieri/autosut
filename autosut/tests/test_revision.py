"""Implementation revisions remain verifiable in Git-free artifact archives."""

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from infrastructure.revision import current_revision, write_revision_stamp  # noqa: E402

REVISION = "a" * 40 + "+tree-" + "b" * 16


def test_packaged_revision_is_recovered_without_git(tmp_path: Path) -> None:
    source = tmp_path / "src" / "module.py"
    source.parent.mkdir()
    source.write_text("VALUE = 1\n", encoding="utf-8")
    write_revision_stamp(tmp_path, REVISION)

    assert current_revision(tmp_path) == REVISION


def test_packaged_revision_when_git_binary_is_absent(tmp_path: Path, monkeypatch) -> None:
    source = tmp_path / "src" / "module.py"
    source.parent.mkdir()
    source.write_text("VALUE = 1\n", encoding="utf-8")
    write_revision_stamp(tmp_path, REVISION)
    monkeypatch.setattr("infrastructure.revision.shutil.which", lambda name: None)

    assert current_revision(tmp_path) == REVISION


def test_packaged_source_change_derives_a_new_revision(tmp_path: Path) -> None:
    source = tmp_path / "scripts" / "driver.py"
    source.parent.mkdir()
    source.write_text("VALUE = 1\n", encoding="utf-8")
    write_revision_stamp(tmp_path, REVISION)
    source.write_text("VALUE = 2\n", encoding="utf-8")

    observed = current_revision(tmp_path)

    assert observed.startswith("a" * 40 + "+tree-")
    assert observed != REVISION


@pytest.mark.skipif(shutil.which("git") is None, reason="Git is unavailable")
def test_packaged_revision_ignores_ancestor_git_repository(tmp_path: Path) -> None:
    parent = tmp_path / "parent"
    parent.mkdir()
    subprocess.run(["git", "init", "-q", str(parent)], check=True)
    subprocess.run(
        ["git", "-C", str(parent), "-c", "user.name=Test",
         "-c", "user.email=test@example.invalid", "commit", "-q", "--allow-empty", "-m", "init"],
        check=True,
    )
    package = parent / "package"
    source = package / "src" / "module.py"
    source.parent.mkdir(parents=True)
    source.write_text("VALUE = 1\n", encoding="utf-8")
    write_revision_stamp(package, REVISION)

    assert current_revision(package) == REVISION

    source.write_text("VALUE = 2\n", encoding="utf-8")
    changed_revision = current_revision(package)
    assert changed_revision.startswith("a" * 40 + "+tree-")
    assert changed_revision != REVISION


def test_invalid_packaged_revision_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="invalid implementation revision"):
        write_revision_stamp(tmp_path, "no-git")
