"""Run the Windows integration gate with a new credential in each disposable clone.

This repairs authentication against an aged local base. It does not qualify a base that still
contains a standing credential; the emitted bundle remains integration evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Literal

if __name__ == "__main__":
    sys.dont_write_bytecode = True

SCRIPTS_DIR = Path(__file__).resolve().parents[1]
PROJECT_ROOT = SCRIPTS_DIR.parent
for import_root in (SCRIPTS_DIR, PROJECT_ROOT / "src"):
    if str(import_root) not in sys.path:
        sys.path.insert(0, str(import_root))

from infra.windows_cyber_gate import run_cyber_gate  # noqa: E402
from infra.windows_panther_acquisition import (  # noqa: E402
    audit_acquired_panther,
    collect_stopped_panther,
)
from infra.windows_open_handles import require_closed_provisioning_files  # noqa: E402
from infra.windows_secret_audit import SecretResidueDetected  # noqa: E402
from infra.windows_surface_scan import produce_scan  # noqa: E402
from infrastructure.windows_surface_scan import sha256_file  # noqa: E402
from infrastructure.windows_overlay_disposal import PreparedOverlayDisposal  # noqa: E402
from infrastructure.windows_crash_recovery import PreparationLink  # noqa: E402
from pydantic import BaseModel, ConfigDict, SecretStr  # noqa: E402
from render_windows_unattend import (  # noqa: E402
    WindowsGuestArchitecture,
    render_answer_file,
    template_for_architecture,
)

GUEST_BASE_DIR = Path("/mnt/base")
GUEST_WORK_DIR = Path("/mnt/work")


class PreparedClone(BaseModel):
    """Private overlay and runtime-only credential for one integration run."""

    model_config = ConfigDict(extra="forbid")

    overlay: Path
    password: SecretStr
    base_image: Path | None = None


class RetainedEvidenceAudit(BaseModel):
    """Post-teardown scan of retained files, bound to the run manifest."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    scope: Literal["retained-run-files"] = "retained-run-files"
    files_scanned: int
    manifest_sha256: str
    overlay_removed: bool
    environment_cleared: bool
    encodings: tuple[str, ...] = ("utf-8", "utf-16le", "utf-16be")
    file_representations: tuple[str, ...] = (
        "literal", "base64", "xml-escaped", "windows-unattend-obfuscated",
    )


def new_password() -> str:
    """Mint a strong credential with each Windows character class represented."""
    return "Aa9!" + secrets.token_urlsafe(28)


def require_docker_visible_evidence_root(root: Path, guestfish_image: str) -> None:
    """Fail before VM creation when Docker cannot read the run's disk directory."""
    root = root.resolve(strict=True)
    with tempfile.NamedTemporaryFile(prefix=".docker-share-probe-", dir=root) as probe:
        result = subprocess.run(
            [
                "docker", "run", "--rm", "--network", "none", "--platform", "linux/arm64",
                "--entrypoint", "test", "-v", f"{root}:{root}:ro", guestfish_image,
                "-f", probe.name,
            ],
            capture_output=True, text=True, timeout=30, check=False,
        )
        if result.returncode:
            raise RuntimeError(
                "Windows evidence root is not visible to Docker as regular files; "
                "choose a directory shared with Docker Desktop"
            )


def prepare_overlay(
    base: Path, workdir: Path, guestfish_image: str,
    computer_name: str | None = None,
) -> PreparedClone:
    """Replace only the clone's cached answer file, never the immutable base."""
    base = base.resolve(strict=True)
    workdir = workdir.resolve(strict=True)
    overlay = workdir / "prepared.qcow2"
    answer = workdir / "answer.xml"
    if overlay.exists() or overlay.is_symlink() or answer.exists() or answer.is_symlink():
        raise FileExistsError("credential workdir already contains a prepared clone")

    password = new_password()
    with tempfile.TemporaryDirectory(prefix="guestfish-overlay-", dir=base.parent) as directory:
        staging_dir = Path(directory)
        staging_overlay = staging_dir / overlay.name
        staging_answer = staging_dir / answer.name
        container_backing_path = GUEST_BASE_DIR / base.name
        host_backing_path = str(base)
        rebased_for_container = False
        committed = False
        try:
            subprocess.run(
                [
                    "qemu-img", "create", "-f", "qcow2", "-b", str(base),
                    "-F", "qcow2", str(staging_overlay),
                ],
                check=True, capture_output=True, text=True, timeout=120,
            )
            render_answer_file(
                template_for_architecture(WindowsGuestArchitecture.ARM64),
                staging_answer, password, WindowsGuestArchitecture.ARM64,
                computer_name=computer_name,
            )
            subprocess.run(
                [
                    "qemu-img", "rebase", "-u", "-b", str(container_backing_path),
                    "-F", "qcow2", str(staging_overlay),
                ],
                check=True, capture_output=True, text=True, timeout=120,
            )
            rebased_for_container = True
            commands = (
                "run\nmount /dev/sda3 /\n"
                f"upload {GUEST_WORK_DIR / staging_answer.name} /Windows/Panther/unattend.xml\n"
                "is-file /Windows/Panther/unattend.xml\n"
            )
            result = subprocess.run(
                [
                    "docker", "run", "--rm", "-i", "--network", "none",
                    "--platform", "linux/arm64", "--privileged",
                    "-e", "LIBGUESTFS_BACKEND=direct",
                    "-e", "LIBGUESTFS_BACKEND_SETTINGS=force_tcg",
                    "-v", f"{base.parent}:{GUEST_BASE_DIR}:ro",
                    "-v", f"{staging_dir}:{GUEST_WORK_DIR}:rw",
                    guestfish_image, "--rw", "-a", str(GUEST_WORK_DIR / staging_overlay.name),
                ],
                input=commands, capture_output=True, text=True, check=True, timeout=300,
            )
            if result.stdout.strip() != "true":
                raise RuntimeError("guestfish did not confirm the clone answer file")
            subprocess.run(
                [
                    "qemu-img", "rebase", "-u", "-b", host_backing_path,
                    "-F", "qcow2", str(staging_overlay),
                ],
                check=True, capture_output=True, text=True, timeout=120,
            )
            rebased_for_container = False
            shutil.copyfile(staging_overlay, overlay)
            overlay.chmod(0o600)
            committed = True
            return PreparedClone(overlay=overlay, password=password, base_image=base)
        finally:
            if rebased_for_container and staging_overlay.exists():
                subprocess.run(
                    [
                        "qemu-img", "rebase", "-u", "-b", host_backing_path,
                        "-F", "qcow2", str(staging_overlay),
                    ],
                    check=True, capture_output=True, text=True, timeout=120,
                )
            if not committed:
                overlay.unlink(missing_ok=True)
            answer.unlink(missing_ok=True)


def run_prepared_gate(prepared: PreparedClone, agent: Path, evidence_root: Path,
                      label: str, *, stopped_disk_observer: Callable[[Path], None] | None = None,
                      stopped_disk_observer_factory: Callable[[Path], Callable[[Path], None]] | None = None,
                      clear_panther_answer: bool = False) -> bool:
    """Retire the preparation credential after execution and retained-file audit."""
    try:
        return _execute_and_audit_prepared_gate(
            prepared, agent, evidence_root, label,
            stopped_disk_observer=stopped_disk_observer,
            stopped_disk_observer_factory=stopped_disk_observer_factory,
            clear_panther_answer=clear_panther_answer,
        )
    finally:
        prepared.password = SecretStr("")


def _audit_retained_panther(run_directory: Path, secret: str) -> None:
    acquisition = run_directory / "windows-qemu" / "panther-acquisition"
    if not acquisition.is_dir() and not acquisition.is_symlink():
        return
    audit = audit_acquired_panther(acquisition, secret)
    audit_path = run_directory.with_name(run_directory.name + ".panther-secret-audit.json")
    with audit_path.open("x", encoding="utf-8") as output:
        output.write(audit.model_dump_json(indent=2) + "\n")
    if audit.leak_found:
        raise SecretResidueDetected("credential residue detected in acquired Panther")
    produce_scan(
        surface="guest_panther", run_id=run_directory.name, input_root=acquisition,
        receipt_path=run_directory.with_name(run_directory.name + ".guest-panther-scan.json"),
        secret=secret,
    )


def _execute_and_audit_prepared_gate(
    prepared: PreparedClone, agent: Path, evidence_root: Path, label: str,
    *, stopped_disk_observer: Callable[[Path], None] | None = None,
    stopped_disk_observer_factory: Callable[[Path], Callable[[Path], None]] | None = None,
    clear_panther_answer: bool = False,
) -> bool:
    """Scope the password to one run and remove the secret-bearing overlay afterward."""
    if prepared.overlay.is_symlink() or not prepared.overlay.is_file():
        raise FileNotFoundError("prepared Windows overlay is missing or not a regular file")
    overlay_sha256_before = sha256_file(prepared.overlay)
    owns_password = False
    gate_returned = False

    def link_preparation(run_directory: Path) -> None:
        link = PreparationLink(
            run_id=run_directory.name,
            credential_directory=prepared.overlay.parent.name,
            prepared_overlay_sha256=overlay_sha256_before,
        )
        with (run_directory / "preparation-link.json").open("x", encoding="utf-8") as output:
            output.write(link.model_dump_json(indent=2) + "\n")

    try:
        if "AUTOSUT_WIN_PASSWORD" in os.environ:
            raise RuntimeError("unset AUTOSUT_WIN_PASSWORD before using per-run provisioning")
        os.environ["AUTOSUT_WIN_PASSWORD"] = prepared.password.get_secret_value()
        owns_password = True
        gate_options = {}
        if stopped_disk_observer is not None:
            gate_options["stopped_disk_observer"] = stopped_disk_observer
        if stopped_disk_observer_factory is not None:
            gate_options["stopped_disk_observer_factory"] = stopped_disk_observer_factory
        if clear_panther_answer:
            gate_options["clear_panther_answer"] = True
        if prepared.base_image is not None:
            gate_options["immutable_base_image"] = prepared.base_image
        gate_options["on_run_created"] = link_preparation
        result, verdict, bundle, validation = run_cyber_gate(
            prepared.overlay, agent, evidence_root, label, **gate_options,
        )
        gate_returned = True
    finally:
        if owns_password:
            os.environ.pop("AUTOSUT_WIN_PASSWORD", None)
        if gate_returned:
            prepared.overlay.unlink()
        else:
            prepared.overlay.unlink(missing_ok=True)

    run_directory = Path(result.evidence_dir).resolve(strict=True)
    if run_directory.parent != evidence_root.resolve(strict=True):
        raise RuntimeError("Windows evidence directory escaped its root")
    if prepared.overlay.exists() or prepared.overlay.is_symlink() or (
        "AUTOSUT_WIN_PASSWORD" in os.environ
    ):
        raise RuntimeError("ephemeral Windows credential state remains active")
    _audit_retained_panther(run_directory, prepared.password.get_secret_value())
    manifest_sha256 = hashlib.sha256((run_directory / "manifest.json").read_bytes()).hexdigest()
    disposal = PreparedOverlayDisposal(
        run_id=run_directory.name,
        overlay_path=str(prepared.overlay),
        overlay_sha256_before=overlay_sha256_before,
        manifest_sha256=manifest_sha256,
        removed=True,
    )
    disposal_path = run_directory.with_name(run_directory.name + ".overlay-disposal.json")
    with disposal_path.open("x", encoding="utf-8") as output:
        output.write(disposal.model_dump_json(indent=2) + "\n")
    scan = produce_scan(
        surface="run_logs", run_id=run_directory.name, input_root=run_directory,
        receipt_path=run_directory.with_name(run_directory.name + ".run-logs-scan.json"),
        secret=prepared.password.get_secret_value(),
    )
    produce_scan(
        surface="evidence_bundle", run_id=run_directory.name,
        input_root=run_directory / "bundle.json",
        receipt_path=run_directory.with_name(run_directory.name + ".evidence-bundle-scan.json"),
        secret=prepared.password.get_secret_value(),
    )
    if prepared.base_image is not None:
        produce_scan(
            surface="base_image", run_id=run_directory.name,
            input_root=prepared.base_image,
            receipt_path=run_directory.with_name(run_directory.name + ".base-image-scan.json"),
            secret=prepared.password.get_secret_value(),
        )
    if (PROJECT_ROOT / "IMPLEMENTATION_REVISION.json").is_file():
        produce_scan(
            surface="source_tree", run_id=run_directory.name, input_root=PROJECT_ROOT,
            receipt_path=run_directory.with_name(run_directory.name + ".source-tree-scan.json"),
            secret=prepared.password.get_secret_value(),
        )
    audit = RetainedEvidenceAudit(
        files_scanned=scan.files_scanned,
        manifest_sha256=manifest_sha256,
        overlay_removed=True,
        environment_cleared=True,
    )
    audit_path = run_directory.with_name(run_directory.name + ".secret-audit.json")
    with audit_path.open("x", encoding="utf-8") as output:
        output.write(audit.model_dump_json(indent=2) + "\n")
    return (
        result.final_state.value == "clean"
        and verdict is not None
        and verdict.science_passed
        and validation.admissible
        and bundle.classification.evidence_role == "integration"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", type=Path, required=True)
    parser.add_argument("--agent", type=Path, required=True)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--label", default="windows-ephemeral-integration")
    parser.add_argument("--guestfish-image", default="autosut-guestfish:bookworm")
    parser.add_argument("--acquire-panther", action="store_true",
                        help="Acquire stopped guest Panther files before disk removal; integration evidence only")
    parser.add_argument("--clear-panther-answer", action="store_true",
                        help="Remove the active guest answer after execution and verify absence before acquisition")
    arguments = parser.parse_args()

    if arguments.clear_panther_answer and not arguments.acquire_panther:
        parser.error("--clear-panther-answer requires --acquire-panther")

    base_directory = arguments.base.resolve(strict=True).parent
    require_closed_provisioning_files(base_directory)

    arguments.evidence_root.mkdir(parents=True, exist_ok=True)
    if arguments.acquire_panther:
        require_docker_visible_evidence_root(
            arguments.evidence_root, arguments.guestfish_image,
        )

    acquisitions = []

    def acquire_stopped_disk_for_run(run_directory: Path) -> Callable[[Path], None]:
        def acquire_stopped_disk(overlay: Path) -> None:
            receipt = collect_stopped_panther(
                overlay, run_directory / "windows-qemu" / "panther-acquisition",
                arguments.guestfish_image, secret=prepared.password.get_secret_value(),
            )
            acquisitions.append(receipt)
        return acquire_stopped_disk

    with tempfile.TemporaryDirectory(prefix="windows-credential-",
                                     dir=arguments.evidence_root) as temporary:
        prepared = prepare_overlay(
            arguments.base, Path(temporary), arguments.guestfish_image,
        )
        gate_options = {"clear_panther_answer": True} if arguments.clear_panther_answer else {}
        passed = run_prepared_gate(
            prepared, arguments.agent, arguments.evidence_root, arguments.label,
            stopped_disk_observer_factory=(acquire_stopped_disk_for_run
                                           if arguments.acquire_panther else None),
            **gate_options,
        )
    require_closed_provisioning_files(base_directory)
    if arguments.acquire_panther:
        if len(acquisitions) != 1:
            raise RuntimeError("Windows Panther acquisition did not produce exactly one receipt")
        if acquisitions[0].unattend_password_values:
            print("Windows answer-file credential values remain in Panther acquisition")
            passed = False
    print(f"Windows integration gate passed: {passed}")
    print("Evidence role: integration; not credential-free-base qualification")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
