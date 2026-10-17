"""Acquire stopped Windows Panther files through a read-only runtime disk chain."""

from __future__ import annotations

import hashlib
import json
import subprocess
import tarfile
import xml.etree.ElementTree as ET
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Literal

from infra.windows_secret_audit import (
    SecretResidueDetected,
    assert_no_secret,
    contains_secret_file,
)
from pydantic import BaseModel, ConfigDict, Field


class PantherAcquisition(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    archive_sha256: str
    regular_files: int
    content_bytes: int
    unattend_password_values: int = Field(ge=0)
    secret_audit_performed: bool = False


class PantherSecretAudit(BaseModel):
    """Bounded known-credential check of a retained, uncompressed archive."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    scope: Literal["acquired-active-panther"] = "acquired-active-panther"
    archive_sha256: str
    regular_files: int
    answer_password_values: int
    marker_leak_found: bool
    leak_found: bool
    completed: bool = True


def _backing_chain(overlay: Path) -> list[Path]:
    result = subprocess.run(
        ["qemu-img", "info", "--backing-chain", "--output=json", str(overlay)],
        check=True, capture_output=True, text=True, timeout=120,
    )
    paths = [Path(entry["filename"]).resolve(strict=True) for entry in json.loads(result.stdout)]
    if not paths or paths[0] != overlay or len(set(paths)) != len(paths):
        raise ValueError("invalid runtime backing chain")
    if any(not path.is_file() or ":" in str(path) for path in paths):
        raise ValueError("backing chain contains an unsupported mount path")
    return paths


def _count_answer_password_values(stream: BinaryIO) -> int:
    root = ET.parse(stream).getroot()
    count = 0
    for element in root.iter():
        if element.tag.rpartition("}")[2].casefold() not in {"password", "administratorpassword"}:
            continue
        values = [element.text]
        values.extend(
            child.text for child in element.iter()
            if child is not element and child.tag.rpartition("}")[2].casefold() == "value"
        )
        count += any(value and value.strip() for value in values)
    return count


def _inspect_acquisition(archive_path: Path) -> PantherAcquisition:
    if archive_path.is_symlink():
        raise ValueError("acquisition archive is a symlink")
    files = 0
    content_bytes = 0
    password_values = 0
    seen_paths: set[str] = set()
    with tarfile.open(archive_path, "r:") as archive:
        for member in archive:
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts:
                raise ValueError("unsafe acquisition member")
            if member.isdir():
                continue
            normalized = path.as_posix()
            if not member.isfile() or normalized in seen_paths:
                raise ValueError("nonregular or duplicate acquisition member")
            seen_paths.add(normalized)
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError("unreadable acquisition member")
            with stream:
                size = 0
                while block := stream.read(1024 * 1024):
                    size += len(block)
            if size != member.size:
                raise ValueError("truncated acquisition member")
            files += 1
            content_bytes += size
            if path.name.casefold() in {"unattend.xml", "unattend-original.xml", "autounattend.xml"}:
                answer_stream = archive.extractfile(member)
                if answer_stream is None:
                    raise ValueError("unreadable answer-file member")
                with answer_stream:
                    password_values += _count_answer_password_values(answer_stream)
    if not files:
        raise ValueError("empty acquisition")
    digest = hashlib.sha256()
    with archive_path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return PantherAcquisition(
        archive_sha256=digest.hexdigest(),
        regular_files=files,
        content_bytes=content_bytes,
        unattend_password_values=password_values,
    )


def audit_acquired_panther(output: Path, secret: str) -> PantherSecretAudit:
    """Verify the acquisition and check active answer fields and known secret forms."""
    if output.is_symlink() or not output.is_dir():
        raise ValueError("Panther acquisition directory is not regular")
    receipt_path = output / "acquisition.json"
    if receipt_path.is_symlink() or not receipt_path.is_file():
        raise ValueError("Panther acquisition receipt is missing or symlinked")
    recorded = PantherAcquisition.model_validate_json(receipt_path.read_text(encoding="utf-8"))
    archive_path = output / "panther.tar"
    observed = _inspect_acquisition(archive_path)
    if recorded != observed:
        raise ValueError("Panther acquisition receipt does not match the archive")
    marker_leak_found = contains_secret_file(archive_path, secret)
    return PantherSecretAudit(
        archive_sha256=observed.archive_sha256,
        regular_files=observed.regular_files,
        answer_password_values=observed.unattend_password_values,
        marker_leak_found=marker_leak_found,
        leak_found=marker_leak_found or observed.unattend_password_values > 0,
    )


def collect_stopped_panther(
    overlay: Path, output: Path, guestfish_image: str, *, secret: str | None = None,
) -> PantherAcquisition:
    """Require delivered archive bytes, not just a successful container exit."""
    overlay = overlay.resolve(strict=True)
    chain = _backing_chain(overlay)
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    output = output.resolve(strict=True)
    archive_path = output / "panther.tar"
    command = [
        "docker", "run", "--rm", "-i", "--network", "none", "--platform", "linux/arm64",
        "--privileged", "-e", "LIBGUESTFS_BACKEND=direct",
        "-e", "LIBGUESTFS_BACKEND_SETTINGS=force_tcg",
    ]
    for path in chain:
        command.extend(["-v", f"{path}:{path}:ro"])
    command.extend(["-v", f"{output}:{output}:rw", guestfish_image, "--ro", "-a", str(overlay)])
    commands = "run\nmount-ro /dev/sda3 /\ntar-out /Windows/Panther " + json.dumps(str(archive_path)) + "\n"
    try:
        subprocess.run(command, input=commands, check=True, capture_output=True, text=True, timeout=300)
    except subprocess.CalledProcessError as error:
        if secret is not None:
            diagnostic = output / "guestfish.stderr.log"
            diagnostic.write_text(error.stderr or "", encoding="utf-8")
            diagnostic.chmod(0o600)
            try:
                assert_no_secret(output, secret)
            except SecretResidueDetected:
                diagnostic.unlink(missing_ok=True)
                archive_path.unlink(missing_ok=True)
                raise
        raise
    archive_path.chmod(0o600)
    receipt = _inspect_acquisition(archive_path)
    (output / "acquisition.json").write_text(receipt.model_dump_json(indent=2) + "\n", encoding="utf-8")
    return receipt
