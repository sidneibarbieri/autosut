"""Windows run outputs must not retain the ephemeral credential."""

from __future__ import annotations

import base64
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from infra import windows_secret_audit
from render_windows_unattend import (
    WindowsGuestArchitecture,
    render_answer_file,
    template_for_architecture,
)


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16le", "utf-16be"])
def test_secret_audit_detects_credential_escaped_by_real_answer_renderer(tmp_path, encoding):
    secret = "Aa9!synthetic&<>only"
    answer = render_answer_file(
        template_for_architecture(WindowsGuestArchitecture.ARM64),
        tmp_path / "answer.xml", secret, WindowsGuestArchitecture.ARM64,
    )
    rendered = answer.read_text(encoding="utf-8")
    assert "Aa9!synthetic&amp;&lt;&gt;only" in rendered
    answer.write_bytes(rendered.encode(encoding))

    with pytest.raises(windows_secret_audit.SecretResidueDetected) as error:
        windows_secret_audit.assert_no_secret(tmp_path, secret)

    assert secret not in str(error.value)
    assert "synthetic&amp;" not in str(error.value)


def test_secret_audit_detects_all_run_output_encodings(tmp_path):
    secret = "Aa9!synthetic-only"
    for encoding in ("utf-8", "utf-16le", "utf-16be"):
        output = tmp_path / encoding
        output.mkdir()
        (output / "run.log").write_bytes(secret.encode(encoding))

        with pytest.raises(windows_secret_audit.SecretResidueDetected) as error:
            windows_secret_audit.assert_no_secret(output, secret)

        assert secret not in str(error.value)


def test_secret_audit_detects_match_across_read_boundary(tmp_path, monkeypatch):
    secret = "Aa9!synthetic-only"
    (tmp_path / "run.log").write_bytes(b"X" * 7 + secret.encode())
    monkeypatch.setattr(windows_secret_audit, "CHUNK_SIZE", 8)

    with pytest.raises(windows_secret_audit.SecretResidueDetected):
        windows_secret_audit.assert_no_secret(tmp_path, secret)


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16le", "utf-16be"])
@pytest.mark.parametrize("storage_encoding", ["utf-8", "utf-16le", "utf-16be"])
def test_secret_audit_detects_base64_credential_without_echoing_it(
    tmp_path, encoding, storage_encoding,
):
    secret = "Aa9!synthetic-only"
    encoded = base64.b64encode(secret.encode(encoding))
    text = "<Value>" + encoded.decode("ascii") + "</Value>"
    (tmp_path / "answer.xml").write_bytes(text.encode(storage_encoding))

    with pytest.raises(windows_secret_audit.SecretResidueDetected) as error:
        windows_secret_audit.assert_no_secret(tmp_path, secret)

    assert secret not in str(error.value)
    assert encoded.decode("ascii") not in str(error.value)


def test_secret_audit_detects_base64_across_read_boundary(tmp_path, monkeypatch):
    secret = "Aa9!synthetic-only"
    encoded = base64.b64encode(secret.encode("utf-16le"))
    (tmp_path / "answer.xml").write_bytes(b"X" * 7 + encoded)
    monkeypatch.setattr(windows_secret_audit, "CHUNK_SIZE", 8)

    with pytest.raises(windows_secret_audit.SecretResidueDetected):
        windows_secret_audit.assert_no_secret(tmp_path, secret)


@pytest.mark.parametrize("suffix", ["Password", "AdministratorPassword"])
@pytest.mark.parametrize("storage_encoding", ["utf-8", "utf-16le", "utf-16be"])
def test_secret_audit_detects_windows_hidden_answer_value(tmp_path, suffix, storage_encoding):
    secret = "Aa9!xyz"
    encoded = base64.b64encode((secret + suffix).encode("utf-16le")).decode("ascii")
    (tmp_path / "answer.xml").write_bytes(
        ("<Value>" + encoded + "</Value><PlainText>false</PlainText>").encode(storage_encoding)
    )

    with pytest.raises(windows_secret_audit.SecretResidueDetected) as error:
        windows_secret_audit.assert_no_secret(tmp_path, secret)

    assert secret not in str(error.value)
    assert encoded not in str(error.value)


def test_secret_audit_detects_official_hidden_administrator_example_across_chunks(tmp_path, monkeypatch):
    encoded = b"cAB3AEEAZABtAGkAbgBpAHMAdAByAGEAdABvAHIAUABhAHMAcwB3AG8AcgBkAA=="
    (tmp_path / "answer.xml").write_bytes(b"<Value>" + encoded + b"</Value>")
    monkeypatch.setattr(windows_secret_audit, "CHUNK_SIZE", 8)

    with pytest.raises(windows_secret_audit.SecretResidueDetected):
        windows_secret_audit.assert_no_secret(tmp_path, "pw")


def test_secret_audit_rejects_symlinks_and_missing_roots(tmp_path):
    outside = tmp_path.parent / "outside.log"
    root = tmp_path / "run"
    root.mkdir()
    (root / "linked.log").symlink_to(outside)

    with pytest.raises(RuntimeError, match="symlink"):
        windows_secret_audit.assert_no_secret(root, "Aa9!synthetic-only")
    with pytest.raises(FileNotFoundError):
        windows_secret_audit.assert_no_secret(tmp_path / "missing", "Aa9!synthetic-only")


def test_secret_audit_reports_number_of_clean_files(tmp_path):
    (tmp_path / "first.log").write_bytes(b"clean")
    (tmp_path / "second.log").write_bytes(b"clean too")

    assert windows_secret_audit.assert_no_secret(tmp_path, "Aa9!synthetic-only") == 2


@pytest.mark.parametrize("create_root", [True, False])
def test_secret_audit_rejects_credential_in_root_path_without_echoing_it(
    tmp_path, create_root,
):
    secret = "Aa9!synthetic-only"
    root = tmp_path / secret / "retained-output"
    if create_root:
        root.mkdir(parents=True)
        (root / "run.log").write_text("clean", encoding="utf-8")

    with pytest.raises(windows_secret_audit.SecretResidueDetected) as error:
        windows_secret_audit.assert_no_secret(root, secret)

    assert secret not in str(error.value)


def test_secret_audit_rejects_credential_in_empty_directory_name(tmp_path):
    secret = "Aa9!synthetic-only"
    (tmp_path / secret).mkdir()

    with pytest.raises(windows_secret_audit.SecretResidueDetected) as error:
        windows_secret_audit.assert_no_secret(tmp_path, secret)

    assert secret not in str(error.value)


def test_secret_audit_rejects_credential_in_nested_empty_directory_name(tmp_path):
    secret = "Aa9!synthetic-only"
    (tmp_path / "diagnostics" / secret).mkdir(parents=True)

    with pytest.raises(windows_secret_audit.SecretResidueDetected):
        windows_secret_audit.assert_no_secret(tmp_path, secret)


def test_secret_audit_fails_when_a_nested_directory_cannot_be_enumerated(
    tmp_path, monkeypatch,
):
    hidden = tmp_path / "hidden"
    hidden.mkdir()
    (hidden / "run.log").write_bytes(b"clean")
    real_scandir = os.scandir

    def inaccessible_scandir(path):
        if Path(path) == hidden:
            raise PermissionError("synthetic directory denial")
        return real_scandir(path)

    monkeypatch.setattr(os, "scandir", inaccessible_scandir)

    with pytest.raises(PermissionError, match="synthetic directory denial"):
        windows_secret_audit.assert_no_secret(tmp_path, "Aa9!synthetic-only")
