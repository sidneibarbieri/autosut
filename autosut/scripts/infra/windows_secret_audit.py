"""Fail closed if a Windows run retains its ephemeral credential."""

from __future__ import annotations

import base64
import os
from pathlib import Path
from xml.sax.saxutils import escape as xml_escape

CHUNK_SIZE = 1024 * 1024
TEXT_ENCODINGS = ("utf-8", "utf-16le", "utf-16be")
UNATTEND_PASSWORD_SUFFIXES = ("Password", "AdministratorPassword")


class SecretResidueDetected(RuntimeError):
    """A run output retained its ephemeral credential."""


def _credential_markers(secret: str) -> tuple[bytes, ...]:
    literal_markers = tuple(secret.encode(encoding) for encoding in TEXT_ENCODINGS)
    xml_markers = tuple(xml_escape(secret).encode(encoding) for encoding in TEXT_ENCODINGS)
    base64_texts = tuple(
        base64.b64encode(marker).decode("ascii") for marker in literal_markers
    )
    hidden_answer_texts = tuple(
        base64.b64encode((secret + suffix).encode("utf-16le")).decode("ascii")
        for suffix in UNATTEND_PASSWORD_SUFFIXES
    )
    encoded_markers = tuple(
        text.encode(encoding)
        for text in (*base64_texts, *hidden_answer_texts) for encoding in TEXT_ENCODINGS
    )
    return tuple(dict.fromkeys((*literal_markers, *encoded_markers, *xml_markers)))


def _contains_secret(path: Path, encoded_secrets: tuple[bytes, ...]) -> bool:
    overlap = max(len(marker) for marker in encoded_secrets) - 1
    previous = b""
    with path.open("rb") as source:
        while block := source.read(CHUNK_SIZE):
            window = previous + block
            if any(marker in window for marker in encoded_secrets):
                return True
            previous = window[-overlap:] if overlap else b""
    return False


def contains_secret_file(path: Path, secret: str) -> bool:
    """Check a regular file for the bounded Windows credential representations."""
    if not secret:
        raise ValueError("empty credential cannot be audited")
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("credential audit requires a regular file")
    return _contains_secret(path, _credential_markers(secret))


def _raise_walk_error(error: OSError) -> None:
    raise error


def assert_no_secret(root: Path, secret: str) -> int:
    """Scan known credential forms, including hidden Windows answer values."""
    if not secret:
        raise ValueError("empty credential cannot be audited")
    if secret in root.as_posix():
        raise SecretResidueDetected("credential residue detected in audit root path")
    if root.is_symlink():
        raise RuntimeError("credential audit root is a symlink")
    if not root.is_dir():
        raise FileNotFoundError("credential audit root is missing")

    encoded_secrets = _credential_markers(secret)
    files_scanned = 0
    for directory, names, filenames in os.walk(root, onerror=_raise_walk_error):
        for name in (*names, *filenames):
            path = Path(directory) / name
            if path.is_symlink():
                raise RuntimeError("credential audit found a symlink")
            if secret in path.relative_to(root).as_posix():
                raise SecretResidueDetected("credential residue detected in retained output")
            if path.is_dir():
                continue
            if not path.is_file():
                raise RuntimeError("credential audit found a nonregular file")
            if _contains_secret(path, encoded_secrets):
                raise SecretResidueDetected("credential residue detected in retained output")
            files_scanned += 1
    return files_scanned
