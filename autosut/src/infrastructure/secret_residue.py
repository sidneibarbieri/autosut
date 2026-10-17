"""Scan retained regular files for an exact per-run secret in UTF-8 and UTF-16.

The ephemeral-credential contract is only real if it is verified, not asserted. A run mints a unique
sentinel secret; after the guest and its secret state are destroyed, this scans the places a secret
could survive -- the evidence bundle, logs, the source tree, host temporary state, and any collected
guest artifacts -- for that exact sentinel. The report is clean only when the scan completed AND no
match was found: a root that exists but cannot be fully read makes ``scan_completed`` false, so an
uninspectable area fails the check instead of being assumed clean. A root that is simply absent (a
provisioning medium destroyed on teardown) is recorded, not treated as a failure; the caller asserts
required absences separately.

The report redacts the target secret in metadata and never copies matched file content.
Paths and line numbers locate matches without exposing adjacent credentials. This byte scan does not inspect
compressed disk contents, memory, or locations omitted by the caller.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

from pydantic import BaseModel, ConfigDict

_REDACTED = "<REDACTED-SENTINEL>"


class SecretMatch(BaseModel):
    """One place the sentinel was found, with the sentinel itself redacted out of the context."""

    model_config = ConfigDict(extra="forbid")

    path: str
    line: int | None
    redacted_context: str


class SecretResidueReport(BaseModel):
    """Where the scan looked, what it could not read, and any (redacted) matches it found."""

    model_config = ConfigDict(extra="forbid")

    sentinel_label: str
    roots_requested: list[str]
    roots_absent: list[str]
    roots_unreadable: list[str]
    files_scanned: int
    matches: list[SecretMatch]
    scan_completed: bool

    @property
    def clean(self) -> bool:
        return self.scan_completed and not self.matches


def _scan_file(path: Path, sentinel: str, encoded_secrets: tuple[bytes, ...]) -> list[SecretMatch]:
    data = path.read_bytes()
    safe_path = str(path).replace(sentinel, _REDACTED)
    if not any(marker in data for marker in encoded_secrets):
        return []
    if encoded_secrets[0] not in data:
        return [SecretMatch(path=safe_path, line=None, redacted_context="<binary match>")]
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return [SecretMatch(path=safe_path, line=None, redacted_context="<binary match>")]
    matches: list[SecretMatch] = []
    for number, line in enumerate(text.splitlines(), start=1):
        if sentinel in line:
            matches.append(SecretMatch(path=safe_path, line=number,
                                       redacted_context=_REDACTED))
    return matches


def _scan_entry(
    path: Path, sentinel: str, encoded_secrets: tuple[bytes, ...],
    matches: list[SecretMatch], unreadable: list[str],
) -> int:
    safe_path = str(path).replace(sentinel, _REDACTED)
    if sentinel in str(path):
        matches.append(SecretMatch(path=safe_path, line=None, redacted_context="<path match>"))
    try:
        entry_mode = path.lstat().st_mode
        if stat.S_ISLNK(entry_mode):
            unreadable.append(f"{safe_path}: symlink not inspected")
        elif stat.S_ISREG(entry_mode):
            matches.extend(_scan_file(path, sentinel, encoded_secrets))
            return 1
        elif not stat.S_ISDIR(entry_mode):
            unreadable.append(f"{safe_path}: nonregular entry not inspected")
    except OSError as error:
        unreadable.append(f"{safe_path}: {type(error).__name__}: {error}".replace(sentinel, _REDACTED))
    return 0


def _scan_root(
    root: Path, sentinel: str, encoded_secrets: tuple[bytes, ...],
    absent: list[str], matches: list[SecretMatch], unreadable: list[str],
) -> int:
    try:
        root_mode = root.lstat().st_mode
    except FileNotFoundError:
        absent.append(str(root).replace(sentinel, _REDACTED))
        return 0
    except OSError as error:
        unreadable.append(f"{root}: {type(error).__name__}: {error}".replace(sentinel, _REDACTED))
        return 0
    files_scanned = _scan_entry(root, sentinel, encoded_secrets, matches, unreadable)
    if not stat.S_ISDIR(root_mode):
        return files_scanned

    def record_walk_error(error: OSError) -> None:
        unreadable.append(f"{type(error).__name__}: {error}".replace(sentinel, _REDACTED))

    for directory, names, filenames in os.walk(root, onerror=record_walk_error, followlinks=False):
        names.sort()
        for name in sorted((*names, *filenames)):
            files_scanned += _scan_entry(
                Path(directory) / name, sentinel, encoded_secrets, matches, unreadable,
            )
    return files_scanned


def scan_for_secret(sentinel: str, roots: list[Path], sentinel_label: str) -> SecretResidueReport:
    """Scan every file under each root for ``sentinel``; fail closed on anything unreadable.

    ``sentinel`` is the actual per-run secret to hunt for; ``sentinel_label`` is a non-secret name for
    the report. An empty sentinel is rejected: scanning for nothing would trivially "pass".
    """
    if not sentinel:
        raise ValueError("refusing to scan for an empty sentinel")
    encoded_secrets = tuple(sentinel.encode(encoding) for encoding in (
        "utf-8", "utf-16le", "utf-16be",
    ))
    absent: list[str] = []
    unreadable: list[str] = []
    matches: list[SecretMatch] = []
    files_scanned = 0

    for root in roots:
        files_scanned += _scan_root(root, sentinel, encoded_secrets, absent, matches, unreadable)

    return SecretResidueReport(
        sentinel_label=sentinel_label.replace(sentinel, _REDACTED),
        roots_requested=[str(root).replace(sentinel, _REDACTED) for root in roots],
        roots_absent=absent,
        roots_unreadable=unreadable,
        files_scanned=files_scanned,
        matches=matches,
        scan_completed=not unreadable,
    )
