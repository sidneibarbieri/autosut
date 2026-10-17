"""Exercise bounded supply-chain operations with separate filesystem observers."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict

from .procedural_plan import load_procedural_plan

TECHNIQUE_SEQUENCE = ("T1583.003", "T1587.003", "T1588.001", "T1036.005")
BENIGN_PROGRAM = b'print("Synthetic research fixture")\n'
WORKSPACE = "/tmp/supply-chain-qualification"


class OperationWitness(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    technique_id: str
    fidelity: Literal["adapted", "inspired"]
    observations: dict[str, str | bool]


class QualificationReceipt(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = "autosut-supply-chain-qualification/v1"
    source_campaign_id: str
    source_plan_sha256: str
    source_file_sha256: str
    implementation_sha256: str
    image_id: str
    witnesses: tuple[OperationWitness, ...]
    teardown_clean: bool
    campaign_execution_certified: bool = False
    scope: str = (
        "Isolated operation qualification; no historical campaign replay "
        "or compiled pair certification."
    )


def _command(arguments: list[str], log: Path) -> str:
    result = subprocess.run(arguments, capture_output=True, text=True, timeout=60)
    log.write_text(result.stdout + result.stderr, encoding="utf-8")
    result.check_returncode()
    return result.stdout.strip()


def _observe_hash(container: str, filename: str, evidence: Path) -> str:
    source = (
        "import hashlib,pathlib; "
        f"print(hashlib.sha256(pathlib.Path({filename!r}).read_bytes()).hexdigest())"
    )
    return _command(["docker", "exec", container, "python3", "-c", source], evidence)


def qualify_supply_chain(plan_path: Path, evidence: Path, image: str) -> QualificationReceipt:
    plan = load_procedural_plan(plan_path)
    if tuple(step.technique_id for step in plan.steps) != TECHNIQUE_SEQUENCE:
        raise ValueError("qualification recipe does not match the complete source sequence")
    if evidence.exists():
        raise ValueError("evidence directory must be new")
    evidence.mkdir(parents=True)
    implementation_sha256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    shutil.copyfile(plan_path, evidence / "source-plan.json")
    image_id = _command(
        ["docker", "image", "inspect", image, "--format", "{{.Id}}"],
        evidence / "image-inspection.log",
    )
    container = "autosut-supply-" + uuid.uuid4().hex[:12]
    witnesses = []
    try:
        witnesses.append(_provision_witness(container, image_id, evidence))
        witnesses.append(_certificate_witness(container, evidence))
        witnesses.append(_signed_fixture_witness(container, evidence))
        witnesses.append(_rename_witness(container, evidence))
    finally:
        # Removal addresses only this uniquely named container, including partial startup.
        active_failure = sys.exc_info()[1]
        try:
            cleanup = subprocess.run(
                ["docker", "rm", "-f", container], capture_output=True, text=True, timeout=60
            )
            (evidence / "teardown.log").write_text(cleanup.stdout + cleanup.stderr)
            if cleanup.returncode and active_failure is None:
                cleanup.check_returncode()
        except subprocess.TimeoutExpired:
            (evidence / "teardown.log").write_text("Container removal timed out.\n")
            if active_failure is None:
                raise
    remaining = _command(
        ["docker", "ps", "-a", "--filter", "name=^/" + container + "$", "--format", "{{.ID}}"],
        evidence / "teardown-observer.log",
    )
    if remaining:
        raise ValueError("qualification container remains after teardown")
    if hashlib.sha256(Path(__file__).read_bytes()).hexdigest() != implementation_sha256:
        raise ValueError("qualification implementation changed during execution")
    receipt = QualificationReceipt(
        source_campaign_id=plan.campaign_id,
        source_plan_sha256=plan.content_sha256,
        source_file_sha256=hashlib.sha256(plan_path.read_bytes()).hexdigest(),
        implementation_sha256=implementation_sha256,
        image_id=image_id,
        witnesses=tuple(witnesses),
        teardown_clean=True,
    )
    (evidence / "qualification-receipt.json").write_text(receipt.model_dump_json(indent=2) + "\n")
    return receipt


def _provision_witness(container: str, image_id: str, evidence: Path) -> OperationWitness:
    _command(
        [
            "docker",
            "run",
            "-d",
            "--name",
            container,
            "--network",
            "none",
            "--memory",
            "256m",
            "--cpus",
            "1",
            "--pids-limit",
            "64",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            image_id,
            "sleep",
            "infinity",
        ],
        evidence / "provision.log",
    )
    state = json.loads(
        _command(["docker", "inspect", container], evidence / "resource-observer.json")
    )[0]
    if not state["State"]["Running"] or state["HostConfig"]["NetworkMode"] != "none":
        raise ValueError("resource observer rejected the isolated substrate")
    return OperationWitness(
        technique_id="T1583.003",
        fidelity="inspired",
        observations={"running": True, "network": "none", "image_id": image_id},
    )


def _certificate_witness(container: str, evidence: Path) -> OperationWitness:
    _command(["docker", "exec", container, "mkdir", "-p", WORKSPACE], evidence / "workspace.log")
    certificate = WORKSPACE + "/certificate.pem"
    private_key = WORKSPACE + "/private-key.pem"
    _command(
        [
            "docker",
            "exec",
            container,
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=Synthetic Research Signer",
            "-addext",
            "extendedKeyUsage=codeSigning",
            "-keyout",
            private_key,
            "-out",
            certificate,
        ],
        evidence / "certificate-operation.log",
    )
    _command(
        ["docker", "exec", container, "openssl", "verify", "-CAfile", certificate, certificate],
        evidence / "certificate-verification.log",
    )
    metadata = _command(
        [
            "docker",
            "exec",
            container,
            "openssl",
            "x509",
            "-in",
            certificate,
            "-noout",
            "-subject",
            "-ext",
            "extendedKeyUsage",
        ],
        evidence / "certificate-observer.log",
    )
    if "Synthetic Research Signer" not in metadata or "Code Signing" not in metadata:
        raise ValueError("certificate observer rejected subject or usage")
    return OperationWitness(
        technique_id="T1587.003",
        fidelity="inspired",
        observations={
            "certificate_sha256": _observe_hash(
                container, certificate, evidence / "certificate-hash.log"
            ),
            "self_signed_certificate_valid": True,
            "trusted_issuer_claimed": False,
        },
    )


def _signed_fixture_witness(container: str, evidence: Path) -> OperationWitness:
    certificate = WORKSPACE + "/certificate.pem"
    private_key = WORKSPACE + "/private-key.pem"
    program = WORKSPACE + "/benign-program.py"
    _command(
        [
            "docker",
            "exec",
            container,
            "python3",
            "-c",
            f"import pathlib; pathlib.Path({program!r}).write_bytes({BENIGN_PROGRAM!r})",
        ],
        evidence / "fixture-operation.log",
    )
    expected = hashlib.sha256(BENIGN_PROGRAM).hexdigest()
    if _observe_hash(container, program, evidence / "fixture-observer.log") != expected:
        raise ValueError("fixture observer rejected program content")
    signature = WORKSPACE + "/signature.bin"
    public_key = WORKSPACE + "/public-key.pem"
    _command(
        [
            "docker",
            "exec",
            container,
            "openssl",
            "dgst",
            "-sha256",
            "-sign",
            private_key,
            "-out",
            signature,
            program,
        ],
        evidence / "signing-operation.log",
    )
    _command(
        [
            "docker",
            "exec",
            container,
            "openssl",
            "x509",
            "-in",
            certificate,
            "-pubkey",
            "-noout",
            "-out",
            public_key,
        ],
        evidence / "public-key.log",
    )
    _command(
        [
            "docker",
            "exec",
            container,
            "openssl",
            "dgst",
            "-sha256",
            "-verify",
            public_key,
            "-signature",
            signature,
            program,
        ],
        evidence / "signature-observer.log",
    )
    altered_program = WORKSPACE + "/altered-program.py"
    _command(
        [
            "docker",
            "exec",
            container,
            "python3",
            "-c",
            "import pathlib; "
            f"pathlib.Path({altered_program!r}).write_bytes("
            f"{BENIGN_PROGRAM + b'# changed content'!r})",
        ],
        evidence / "negative-control-setup.log",
    )
    negative = subprocess.run(
        [
            "docker",
            "exec",
            container,
            "openssl",
            "dgst",
            "-sha256",
            "-verify",
            public_key,
            "-signature",
            signature,
            altered_program,
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    (evidence / "negative-control-observer.log").write_text(negative.stdout + negative.stderr)
    if negative.returncode != 1 or "Verification failure" not in negative.stdout:
        raise ValueError("signature observer did not reject altered content")
    return OperationWitness(
        technique_id="T1588.001",
        fidelity="inspired",
        observations={
            "program_sha256": expected,
            "signature_verified": True,
            "altered_program_rejected": True,
            "malware_acquired": False,
        },
    )


def _rename_witness(container: str, evidence: Path) -> OperationWitness:
    program = WORKSPACE + "/benign-program.py"
    expected = hashlib.sha256(BENIGN_PROGRAM).hexdigest()
    renamed = WORKSPACE + "/systemd-helper"
    _command(
        ["docker", "exec", container, "mv", program, renamed], evidence / "rename-operation.log"
    )
    if _observe_hash(container, renamed, evidence / "rename-observer.log") != expected:
        raise ValueError("rename observer rejected unchanged content")
    _command(
        ["docker", "exec", container, "test", "!", "-e", program], evidence / "source-absence.log"
    )
    return OperationWitness(
        technique_id="T1036.005",
        fidelity="adapted",
        observations={
            "destination": renamed,
            "program_sha256": expected,
            "source_absent": True,
            "system_file_overwritten": False,
        },
    )
