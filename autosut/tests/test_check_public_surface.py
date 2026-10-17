from __future__ import annotations

import gzip
import lzma
from pathlib import Path

import pytest

from scripts import check_public_surface


def test_runtime_state_detection_is_recursive() -> None:
    assert check_public_surface.is_runtime_state(Path(".venv/bin/activate"))
    assert check_public_surface.is_runtime_state(Path("lab/target/.vagrant/machines/default/id"))
    assert check_public_surface.is_runtime_state(Path("src/__pycache__/module.cpython-312.pyc"))
    assert check_public_surface.is_runtime_state(Path("results/.coverage"))


def test_release_evidence_is_not_runtime_state() -> None:
    assert not check_public_surface.is_runtime_state(
        Path("release/evidence/run/sut/containment.log")
    )


def test_public_surface_works_without_git_binary(monkeypatch) -> None:
    check_public_surface.is_git_worktree.cache_clear()
    monkeypatch.setattr(check_public_surface.shutil, "which", lambda name: None)

    assert not check_public_surface.is_git_worktree()
    assert check_public_surface.is_git_ignored(".venv/bin/python")
    check_public_surface.is_git_worktree.cache_clear()


def test_generic_container_home_is_not_a_personal_identifier() -> None:
    assert check_public_surface.home_path_snippets(Path("/root")) == []
    assert check_public_surface.home_path_snippets(Path("/tmp")) == []
    assert check_public_surface.home_path_snippets(Path("/tmp/reviewer")) == ["/tmp/reviewer"]
    assert check_public_surface.home_path_snippets(Path("/Users/example")) == ["/Users/example"]


def test_only_declared_public_surface_reports_are_runtime_state() -> None:
    assert check_public_surface.is_runtime_state(
        Path("results/reviewer_runtime/public_surface_report.json")
    )
    assert check_public_surface.is_runtime_state(
        Path("results/reviewer_runtime/PUBLIC_SURFACE_REPORT.md")
    )
    assert check_public_surface.is_runtime_state(
        Path("results/reviewer_runtime/review-report.json")
    )
    assert not check_public_surface.is_runtime_state(
        Path("results/reviewer_runtime/unexpected.json")
    )


def test_non_git_public_file_enumeration_prunes_virtual_environments(monkeypatch, tmp_path):
    tracked = tmp_path / "README.md"
    tracked.write_text("public\n", encoding="utf-8")
    cached = tmp_path / ".venv" / "secret.txt"
    cached.parent.mkdir()
    cached.write_text("private\n", encoding="utf-8")

    monkeypatch.setattr(check_public_surface, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(check_public_surface, "is_git_worktree", lambda: False)

    assert check_public_surface.iter_public_files() == [tracked]


def test_empty_runtime_directory_is_not_reported_as_materialized(monkeypatch, tmp_path):
    runtime_directory = tmp_path / "evidence" / "qemu-multi"
    runtime_directory.mkdir(parents=True)

    monkeypatch.setattr(check_public_surface, "PROJECT_ROOT", tmp_path)

    assert "evidence/qemu-multi" not in check_public_surface.find_local_runtime_artifacts()

    (runtime_directory / "state.json").write_text("{}\n", encoding="utf-8")
    assert "evidence/qemu-multi" in check_public_surface.find_local_runtime_artifacts()


def test_public_surface_rejects_stale_reviewer_contract_language(monkeypatch, tmp_path):
    document = tmp_path / "README.md"
    document.write_text(
        "This STICKS artifact runs one representative campaign.\n"
        "See results/CAMPAIGN_SUT_FIDELITY_MATRIX.md.\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(check_public_surface, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(check_public_surface, "PUBLIC_DOCS", ["README.md"])

    hits = check_public_surface.find_forbidden_hits()

    assert {hit["snippet"] for hit in hits} >= {
        "STICKS artifact",
        "one representative campaign",
        "CAMPAIGN_SUT_FIDELITY_MATRIX",
    }


def test_public_surface_requires_architecture_claim_boundaries(monkeypatch, tmp_path):
    architecture = tmp_path / "ARCHITECTURE.md"
    architecture.write_text("bash run_review_check.sh\n", encoding="utf-8")
    boundary = tmp_path / "docs" / "architecture" / "PROPOSAL_ADMISSION_BOUNDARY.md"
    boundary.parent.mkdir(parents=True)
    boundary.write_text("D2: fixed catalog and deterministic binding\n", encoding="utf-8")
    monkeypatch.setattr(check_public_surface, "PROJECT_ROOT", tmp_path)

    missing = check_public_surface.find_missing_documentation_snippets()

    assert {item["snippet"] for item in missing} == {
        "Docker is required for the live replay.",
        "D3: bounded proposal with deterministic admission",
    }


def test_administrative_terms_are_matched_by_digest_as_tokens_and_phrases(monkeypatch) -> None:
    digests = frozenset({
        check_public_surface.term_digest("Zebra-Venue"),
        check_public_surface.term_digest("Quiet Forum"),
    })
    monkeypatch.setattr(check_public_surface, "ADMINISTRATIVE_TERM_DIGESTS", digests)

    assert check_public_surface.contains_administrative_term("Accepted at Zebra-Venue.")
    assert check_public_surface.contains_administrative_term("presented at the Quiet Forum")
    assert not check_public_surface.contains_administrative_term("a Zebra venue and a quiet forum")


def test_secret_tokens_are_reported_by_label() -> None:
    fake_key = "sk-" + "proj-" + "A" * 24
    pattern = check_public_surface.SENSITIVE_TEXT_PATTERNS["OpenAI/Anthropic secret-key token"]
    assert pattern.search(f"OPENAI_API_KEY={fake_key}")


def test_binary_utf16_secret_is_a_public_surface_failure(monkeypatch, tmp_path) -> None:
    fake_key = "sk-" + "proj-" + "A" * 24
    (tmp_path / "diagram.bin").write_bytes(f"key={fake_key}".encode("utf-16le"))
    monkeypatch.setattr(check_public_surface, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(check_public_surface, "is_git_worktree", lambda: False)

    hits = check_public_surface.find_sensitive_text_hits()

    assert hits == [{
        "path": "diagram.bin", "snippet": "OpenAI/Anthropic secret-key token",
    }]
    assert fake_key not in str(hits)


def test_gzip_secret_is_a_public_surface_failure(monkeypatch, tmp_path) -> None:
    fake_key = "sk-" + "proj-" + "B" * 24
    (tmp_path / "archive.gz").write_bytes(gzip.compress(fake_key.encode()))
    monkeypatch.setattr(check_public_surface, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(check_public_surface, "is_git_worktree", lambda: False)

    hits = check_public_surface.find_sensitive_text_hits()

    assert hits == [{
        "path": "archive.gz", "snippet": "OpenAI/Anthropic secret-key token",
    }]


def test_gzip_audit_fails_closed_when_expansion_exceeds_limit(monkeypatch, tmp_path) -> None:
    archive = tmp_path / "archive.gz"
    archive.write_bytes(gzip.compress(b"expanded payload"))
    monkeypatch.setattr(check_public_surface, "MAX_EXPANDED_GZIP_BYTES", 8)

    with pytest.raises(ValueError, match="exceeds audit limit"):
        check_public_surface.public_file_payload(archive)


def test_xz_secret_is_a_public_surface_failure(monkeypatch, tmp_path) -> None:
    fake_key = "sk-" + "proj-" + "C" * 24
    (tmp_path / "data.tar.xz").write_bytes(lzma.compress(fake_key.encode()))
    monkeypatch.setattr(check_public_surface, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(check_public_surface, "is_git_worktree", lambda: False)

    hits = check_public_surface.find_sensitive_text_hits()

    assert hits == [{
        "path": "data.tar.xz", "snippet": "OpenAI/Anthropic secret-key token",
    }]


def test_xz_audit_fails_closed_when_expansion_exceeds_limit(monkeypatch, tmp_path) -> None:
    archive = tmp_path / "data.tar.xz"
    archive.write_bytes(lzma.compress(b"expanded payload"))
    monkeypatch.setattr(check_public_surface, "MAX_EXPANDED_XZ_BYTES", 8)

    with pytest.raises(ValueError, match="exceeds audit limit"):
        list(check_public_surface.public_file_views(archive))
