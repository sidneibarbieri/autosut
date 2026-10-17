"""Qualify two disposable Windows clones with independent credentials."""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
import tempfile
from pathlib import Path

from pydantic import BaseModel, ConfigDict

SCRIPTS_DIR = Path(__file__).resolve().parents[1]
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from infra.windows_ephemeral_gate import PreparedClone, prepare_overlay  # noqa: E402
from infra.windows_secret_audit import SecretResidueDetected, assert_no_secret  # noqa: E402
from orchestrator.models import SUTProfile  # noqa: E402
from orchestrator.windows_qemu_environment import WindowsQemuEnvironment  # noqa: E402

_IDENTITY_COMMAND = (
    "$account=(New-Object System.Security.Principal.NTAccount('labadmin'))."
    "Translate([System.Security.Principal.SecurityIdentifier]).Value\n"
    "$machine=$account -replace '-[0-9]+$',''\n"
    "$guid=(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Cryptography' "
    "-Name MachineGuid).MachineGuid\n"
    "Write-Output ($env:COMPUTERNAME + '|' + $machine + '|' + $guid)"
)


class GuestIdentity(BaseModel):
    """Machine-specific values assigned during specialize."""

    model_config = ConfigDict(extra="forbid")

    hostname: str
    machine_sid: str
    machine_guid: str


class CloneResult(GuestIdentity):
    """Authentication and teardown observations for one clone."""

    label: str
    own_credential_accepted: bool
    other_credential_rejected: bool
    clean_teardown: bool


class PairReceipt(BaseModel):
    """Private, password-free outcome for both clones."""

    model_config = ConfigDict(extra="forbid")

    base_sha256_before: str
    base_sha256_after: str
    credentials_distinct: bool
    first: CloneResult
    second: CloneResult
    residue_free: bool
    passed: bool


def parse_identity(output: str) -> GuestIdentity:
    """Reject incomplete WinRM responses instead of inventing an identity."""
    fields = [field.strip() for field in output.strip().split("|")]
    if len(fields) != 3 or not all(fields):
        raise ValueError("invalid Windows identity response")
    return GuestIdentity(hostname=fields[0], machine_sid=fields[1], machine_guid=fields[2])


def pair_passed(
    first: CloneResult, second: CloneResult,
    base_immutable: bool, credentials_distinct: bool,
) -> bool:
    """Require positive, cross-negative, identity, and cleanup controls."""
    return all((
        base_immutable,
        credentials_distinct,
        first.own_credential_accepted,
        first.other_credential_rejected,
        first.clean_teardown,
        second.own_credential_accepted,
        second.other_credential_rejected,
        second.clean_teardown,
        first.hostname != second.hostname,
        first.machine_sid != second.machine_sid,
        first.machine_guid != second.machine_guid,
    ))


def _sha256(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def _wrong_credential_rejected(port: int, password: str) -> bool:
    import winrm
    from winrm.exceptions import InvalidCredentialsError

    session = winrm.Session(
        f"http://127.0.0.1:{port}/wsman", auth=("labadmin", password),
        transport="ntlm", operation_timeout_sec=25, read_timeout_sec=55,
    )
    try:
        session.run_ps("$env:COMPUTERNAME")
    except InvalidCredentialsError:
        return True
    return False


def clone_profile(label: str, overlay: Path) -> SUTProfile:
    """Use the same VM resources as the observed Windows integration gate."""
    return SUTProfile(
        sut_id=f"credential-{label}", backend="windows-qemu",
        base_image=str(overlay), memory_mb=6144, smp=4,
    )


def _run_clone(
    label: str, prepared: PreparedClone, other_password: str, output_dir: Path,
) -> CloneResult:
    run_dir = output_dir / label
    run_dir.mkdir(mode=0o700)
    profile = clone_profile(label, prepared.overlay)
    if "AUTOSUT_WIN_PASSWORD" in os.environ:
        raise RuntimeError("unset AUTOSUT_WIN_PASSWORD before pair qualification")
    os.environ["AUTOSUT_WIN_PASSWORD"] = prepared.password.get_secret_value()
    try:
        backend = WindowsQemuEnvironment.bring_up(profile, run_dir)
    finally:
        os.environ.pop("AUTOSUT_WIN_PASSWORD", None)

    try:
        identity_response = backend.run_shell(_IDENTITY_COMMAND, timeout=60)
        if not identity_response.ok:
            raise RuntimeError(f"{label} identity query failed")
        identity = parse_identity(identity_response.stdout)
        rejected = _wrong_credential_rejected(backend.winrm_port, other_password)
    finally:
        clean = backend.teardown()
    return CloneResult(
        label=label, **identity.model_dump(),
        own_credential_accepted=True,
        other_credential_rejected=rejected,
        clean_teardown=clean,
    )


def qualify_pair(base: Path, output_dir: Path, guestfish_image: str) -> PairReceipt:
    """Run two clones sequentially and keep only password-free evidence."""
    base = base.resolve(strict=True)
    output_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    before = _sha256(base)
    with tempfile.TemporaryDirectory(prefix="pair-overlays-", dir=output_dir) as scratch:
        first_dir = Path(scratch) / "first"
        second_dir = Path(scratch) / "second"
        first_dir.mkdir(mode=0o700)
        second_dir.mkdir(mode=0o700)
        first_prepared = prepare_overlay(
            base, first_dir, guestfish_image, computer_name="AUTOSUT-A",
        )
        second_prepared = prepare_overlay(
            base, second_dir, guestfish_image, computer_name="AUTOSUT-B",
        )
        first_password = first_prepared.password.get_secret_value()
        second_password = second_prepared.password.get_secret_value()
        distinct = first_password != second_password
        if not distinct:
            raise RuntimeError("two clones received the same credential")
        first = _run_clone("first", first_prepared, second_password, output_dir)
        second = _run_clone("second", second_prepared, first_password, output_dir)
    after = _sha256(base)
    try:
        assert_no_secret(output_dir, first_password)
        assert_no_secret(output_dir, second_password)
        residue_free = True
    except SecretResidueDetected:
        residue_free = False
    passed = pair_passed(first, second, before == after, distinct) and residue_free
    receipt = PairReceipt(
        base_sha256_before=before, base_sha256_after=after,
        credentials_distinct=distinct, first=first, second=second,
        residue_free=residue_free, passed=passed,
    )
    (output_dir / "pair-receipt.json").write_text(
        receipt.model_dump_json(indent=2) + "\n", encoding="utf-8",
    )
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--guestfish-image", default="autosut-guestfish:bookworm")
    arguments = parser.parse_args()
    receipt = qualify_pair(arguments.base, arguments.output_dir, arguments.guestfish_image)
    print(f"Windows clone credential pair passed: {receipt.passed}")
    print(f"Private receipt: {arguments.output_dir / 'pair-receipt.json'}")
    return 0 if receipt.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
