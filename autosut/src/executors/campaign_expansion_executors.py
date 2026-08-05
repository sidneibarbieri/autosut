#!/usr/bin/env python3
"""Campaign-expansion executors for adapted Linux data-collection flows."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import tarfile
import threading
import urllib.request
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import List, Tuple

from .executor_registry import (
    ExecutionFidelity,
    ExecutionMode,
    ExecutorMetadata,
    register_executor,
)

ARTIFACTS_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "artifacts"


def _campaign_dir(campaign_id: str) -> Path:
    campaign_dir = ARTIFACTS_DIR / campaign_id
    campaign_dir.mkdir(parents=True, exist_ok=True)
    return campaign_dir


def _write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _bounded_collection_files(campaign_id: str) -> List[Path]:
    collection_dir = _campaign_dir(campaign_id) / "bounded_collection"
    collection_dir.mkdir(parents=True, exist_ok=True)

    documents = {
        "accounts.csv": (
            "account_id,name,region,owner\n"
            "1001,Northwind Logistics,NA,alice\n"
            "1002,Blue Solar,EMEA,bob\n"
            "1003,River Analytics,APAC,carol\n"
        ),
        "opportunities.txt": (
            "Q2 pipeline summary\n"
            "- Northwind Logistics renewal: $125000\n"
            "- Blue Solar expansion: $98000\n"
            "- River Analytics migration: $143000\n"
        ),
        "operator_notes.txt": (
            "Exported from adapted STICKS collection flow.\n"
            f"timestamp={datetime.now().isoformat()}\n"
        ),
    }

    paths = []
    for filename, content in documents.items():
        file_path = collection_dir / filename
        file_path.write_text(content, encoding="utf-8")
        paths.append(file_path)
    return paths


def _ensure_collection_archive(campaign_id: str) -> Path:
    campaign_dir = _campaign_dir(campaign_id)
    archive_path = campaign_dir / "collection_bundle.tar.gz"
    source_files = _bounded_collection_files(campaign_id)

    with tarfile.open(archive_path, "w:gz") as archive:
        for source_file in source_files:
            archive.add(source_file, arcname=source_file.name)

    return archive_path


@register_executor(
    technique_id="T1078.003",
    metadata=ExecutorMetadata(
        technique_id="T1078.003",
        technique_name="Valid Accounts: Cloud Accounts",
        execution_mode=ExecutionMode.REAL_CONTROLLED,
        produces=["access:initial"],
        requires=["network:ssh_available"],
        safe_simulation=True,
        cleanup_supported=True,
        description="Use bounded operator credentials in an adapted Linux substrate",
        platform="linux",
        execution_fidelity=ExecutionFidelity.ADAPTED,
        fidelity_justification=(
            "T1078.003 abuses valid cloud accounts. In this adapted execution, "
            "bounded operator credentials are materialized as a controlled local "
            "access log for the Linux-hosted substrate used by the published "
            "campaign. The credential-abuse intent is preserved without touching "
            "external SaaS infrastructure."
        ),
        original_platform="cloud",
        requires_privilege="user",
    ),
)
def execute_t1078_003_real(
    campaign_id: str,
    sut_profile_id: str,
    **kwargs,
) -> Tuple[bool, str, str, List[str]]:
    campaign_dir = _campaign_dir(campaign_id)
    access_log = campaign_dir / "valid_accounts_access.json"
    _write_json(
        access_log,
        {
            "campaign_id": campaign_id,
            "sut_profile_id": sut_profile_id,
            "account": "salesops",
            "access_mode": "bounded_local_operator_credentials",
            "timestamp": datetime.now().isoformat(),
        },
    )
    return True, "Valid account access recorded for adapted substrate", "", [str(access_log)]


@register_executor(
    technique_id="T1033",
    metadata=ExecutorMetadata(
        technique_id="T1033",
        technique_name="System Owner/User Discovery",
        execution_mode=ExecutionMode.REAL_CONTROLLED,
        produces=["discovery:user_context"],
        requires=["code_execution"],
        safe_simulation=True,
        cleanup_supported=True,
        description="Discover the active user and ownership context",
        platform="linux",
        execution_fidelity=ExecutionFidelity.ADAPTED,
        fidelity_justification=(
            "T1033 discovers current users or ownership context. This execution "
            "runs real local discovery commands in a bounded environment and "
            "records the resulting user context."
        ),
        original_platform="any",
        requires_privilege="user",
    ),
)
def execute_t1033_real(
    campaign_id: str,
    sut_profile_id: str,
    **kwargs,
) -> Tuple[bool, str, str, List[str]]:
    campaign_dir = _campaign_dir(campaign_id)
    whoami = subprocess.run(
        ["whoami"],
        capture_output=True,
        text=True,
        check=True,
    )
    identity = subprocess.run(
        ["id"],
        capture_output=True,
        text=True,
        check=True,
    )
    discovery_log = campaign_dir / "user_discovery.log"
    discovery_log.write_text(
        "=== WHOAMI ===\n"
        f"{whoami.stdout}\n"
        "=== ID ===\n"
        f"{identity.stdout}\n",
        encoding="utf-8",
    )
    return True, "User discovery completed", "", [str(discovery_log)]


@register_executor(
    technique_id="T1056.001",
    metadata=ExecutorMetadata(
        technique_id="T1056.001",
        technique_name="Input Capture: Keylogging",
        execution_mode=ExecutionMode.REAL_CONTROLLED,
        produces=["collection:credential_capture"],
        requires=["code_execution"],
        safe_simulation=True,
        cleanup_supported=True,
        description="Capture bounded operator input as a controlled keylog artifact",
        platform="linux",
        execution_fidelity=ExecutionFidelity.ADAPTED,
        fidelity_justification=(
            "T1056.001 records typed input. This execution creates a controlled "
            "keystroke log representing bounded operator input rather than "
            "hooking a live user session."
        ),
        original_platform="any",
        requires_privilege="user",
    ),
)
def execute_t1056_001_real(
    campaign_id: str,
    sut_profile_id: str,
    **kwargs,
) -> Tuple[bool, str, str, List[str]]:
    campaign_dir = _campaign_dir(campaign_id)
    keylog_path = campaign_dir / "keylogging_capture.log"
    keylog_path.write_text(
        "timestamp,input\n"
        f"{datetime.now().isoformat()},salesops\n"
        f"{datetime.now().isoformat()},SalesOps123!\n",
        encoding="utf-8",
    )
    return True, "Controlled keylogging artifact captured", "", [str(keylog_path)]


@register_executor(
    technique_id="T1113",
    metadata=ExecutorMetadata(
        technique_id="T1113",
        technique_name="Screen Capture",
        execution_mode=ExecutionMode.REAL_CONTROLLED,
        produces=["collection:screen_capture"],
        requires=["code_execution"],
        safe_simulation=True,
        cleanup_supported=True,
        description="Create a bounded HTML capture representing on-screen business data",
        platform="linux",
        execution_fidelity=ExecutionFidelity.ADAPTED,
        fidelity_justification=(
            "T1113 captures screen content. This execution emits a bounded visual "
            "artifact representing the sensitive business view exposed by the "
            "adapted campaign substrate."
        ),
        original_platform="any",
        requires_privilege="user",
    ),
)
def execute_t1113_real(
    campaign_id: str,
    sut_profile_id: str,
    **kwargs,
) -> Tuple[bool, str, str, List[str]]:
    campaign_dir = _campaign_dir(campaign_id)
    capture_path = campaign_dir / "screen_capture.html"
    capture_path.write_text(
        "<html><body>"
        "<h1>Sales Pipeline Snapshot</h1>"
        "<ul>"
        "<li>Northwind Logistics renewal: $125000</li>"
        "<li>Blue Solar expansion: $98000</li>"
        "<li>River Analytics migration: $143000</li>"
        "</ul>"
        f"<p>captured_at={datetime.now().isoformat()}</p>"
        "</body></html>\n",
        encoding="utf-8",
    )
    return True, "Bounded screen capture artifact created", "", [str(capture_path)]


@register_executor(
    technique_id="T1119",
    metadata=ExecutorMetadata(
        technique_id="T1119",
        technique_name="Automated Collection",
        execution_mode=ExecutionMode.REAL_CONTROLLED,
        produces=["collection:local_data", "collection:archive"],
        requires=["discovery:file_listing"],
        safe_simulation=True,
        cleanup_supported=True,
        description="Collect bounded campaign data and archive it automatically",
        platform="linux",
        execution_fidelity=ExecutionFidelity.ADAPTED,
        fidelity_justification=(
            "T1119 automates local data collection. This execution gathers bounded "
            "business documents into a real compressed archive, preserving the "
            "collection-and-staging behavior without touching uncontrolled data."
        ),
        original_platform="any",
        requires_privilege="user",
    ),
)
def execute_t1119_real(
    campaign_id: str,
    sut_profile_id: str,
    **kwargs,
) -> Tuple[bool, str, str, List[str]]:
    campaign_dir = _campaign_dir(campaign_id)
    archive_path = _ensure_collection_archive(campaign_id)
    manifest_path = campaign_dir / "automated_collection_manifest.json"
    source_files = _bounded_collection_files(campaign_id)
    _write_json(
        manifest_path,
        {
            "campaign_id": campaign_id,
            "archive": str(archive_path),
            "sources": [str(path) for path in source_files],
            "timestamp": datetime.now().isoformat(),
        },
    )
    artifacts = [str(archive_path), str(manifest_path)] + [str(path) for path in source_files]
    return True, "Automated collection archive created", "", artifacts


@register_executor(
    technique_id="T1020",
    metadata=ExecutorMetadata(
        technique_id="T1020",
        technique_name="Automated Exfiltration",
        execution_mode=ExecutionMode.REAL_CONTROLLED,
        produces=["exfiltration:automated"],
        requires=["collection:archive"],
        safe_simulation=True,
        cleanup_supported=True,
        description="Stage a bounded archive for automated transfer",
        platform="linux",
        execution_fidelity=ExecutionFidelity.ADAPTED,
        fidelity_justification=(
            "T1020 automates exfiltration after data is staged. This execution "
            "moves a bounded archive into an exfiltration queue and records a "
            "transfer manifest."
        ),
        original_platform="any",
        requires_privilege="user",
    ),
)
def execute_t1020_real(
    campaign_id: str,
    sut_profile_id: str,
    **kwargs,
) -> Tuple[bool, str, str, List[str]]:
    campaign_dir = _campaign_dir(campaign_id)
    archive_path = _ensure_collection_archive(campaign_id)
    queue_dir = campaign_dir / "automated_exfil_queue"
    queue_dir.mkdir(parents=True, exist_ok=True)
    queued_archive = queue_dir / archive_path.name
    shutil.copy2(archive_path, queued_archive)
    manifest_path = queue_dir / "transfer_manifest.json"
    _write_json(
        manifest_path,
        {
            "campaign_id": campaign_id,
            "queued_archive": str(queued_archive),
            "sha256": hashlib.sha256(queued_archive.read_bytes()).hexdigest(),
            "timestamp": datetime.now().isoformat(),
        },
    )
    return True, "Automated exfiltration queue populated", "", [str(queued_archive), str(manifest_path)]


@register_executor(
    technique_id="T1567.002",
    metadata=ExecutorMetadata(
        technique_id="T1567.002",
        technique_name="Exfiltration to Cloud Storage",
        execution_mode=ExecutionMode.REAL_CONTROLLED,
        produces=["exfiltration:web_service"],
        requires=["collection:archive"],
        safe_simulation=True,
        cleanup_supported=True,
        description="Upload a bounded archive to a local HTTP receiver",
        platform="linux",
        execution_fidelity=ExecutionFidelity.ADAPTED,
        fidelity_justification=(
            "T1567.002 exfiltrates data over a web service. This execution posts a "
            "bounded archive to a local HTTP receiver, preserving the web-service "
            "transfer behavior without using external infrastructure."
        ),
        original_platform="cloud",
        requires_privilege="user",
    ),
)
def execute_t1567_002_real(
    campaign_id: str,
    sut_profile_id: str,
    **kwargs,
) -> Tuple[bool, str, str, List[str]]:
    campaign_dir = _campaign_dir(campaign_id)
    archive_path = _ensure_collection_archive(campaign_id)
    upload_path = campaign_dir / "web_service_upload.bin"

    class UploadHandler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            payload = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            upload_path.write_bytes(payload)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"OK")

        def log_message(self, format: str, *args) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), UploadHandler)
    worker = threading.Thread(target=server.handle_request)
    worker.start()
    try:
        request = urllib.request.Request(
            url=f"http://127.0.0.1:{server.server_port}/upload",
            data=archive_path.read_bytes(),
            method="POST",
            headers={"Content-Type": "application/octet-stream"},
        )
        with urllib.request.urlopen(request, timeout=15) as response:
            response_body = response.read().decode("utf-8")
    finally:
        worker.join(timeout=15)
        server.server_close()

    transfer_log = campaign_dir / "web_service_transfer.json"
    _write_json(
        transfer_log,
        {
            "campaign_id": campaign_id,
            "endpoint": f"http://127.0.0.1:{server.server_port}/upload",
            "bytes_uploaded": upload_path.stat().st_size,
            "sha256": hashlib.sha256(upload_path.read_bytes()).hexdigest(),
            "response": response_body,
            "timestamp": datetime.now().isoformat(),
        },
    )
    return True, "Archive uploaded to bounded web-service receiver", "", [str(upload_path), str(transfer_log)]


@register_executor(
    technique_id="T1486",
    metadata=ExecutorMetadata(
        technique_id="T1486",
        technique_name="Data Encrypted for Impact",
        execution_mode=ExecutionMode.REAL_CONTROLLED,
        produces=["impact:encrypted_data"],
        requires=["collection:archive", "resources:openssl_available"],
        safe_simulation=True,
        cleanup_supported=True,
        description="Encrypt a bounded archive with OpenSSL for impact simulation",
        platform="linux",
        execution_fidelity=ExecutionFidelity.ADAPTED,
        fidelity_justification=(
            "T1486 encrypts data for impact. This execution performs real "
            "encryption over bounded collected data using OpenSSL, preserving the "
            "impact mechanism without affecting uncontrolled files."
        ),
        original_platform="any",
        requires_privilege="user",
    ),
)
def execute_t1486_real(
    campaign_id: str,
    sut_profile_id: str,
    **kwargs,
) -> Tuple[bool, str, str, List[str]]:
    campaign_dir = _campaign_dir(campaign_id)
    archive_path = _ensure_collection_archive(campaign_id)
    encrypted_path = campaign_dir / f"{archive_path.name}.enc"
    subprocess.run(
        [
            "openssl",
            "enc",
            "-aes-256-cbc",
            "-pbkdf2",
            "-salt",
            "-in",
            str(archive_path),
            "-out",
            str(encrypted_path),
            "-pass",
            "pass:sticks-impact-demo",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    impact_log = campaign_dir / "impact_encryption.json"
    _write_json(
        impact_log,
        {
            "campaign_id": campaign_id,
            "source_archive": str(archive_path),
            "encrypted_archive": str(encrypted_path),
            "sha256": hashlib.sha256(encrypted_path.read_bytes()).hexdigest(),
            "timestamp": datetime.now().isoformat(),
        },
    )
    return True, "Bounded archive encrypted for impact simulation", "", [str(encrypted_path), str(impact_log)]


@register_executor(
    technique_id="T1490",
    metadata=ExecutorMetadata(
        technique_id="T1490",
        technique_name="Inhibit System Recovery",
        execution_mode=ExecutionMode.NAIVE_SIMULATED,
        produces=["impact:recovery_inhibited"],
        requires=["code_execution"],
        safe_simulation=True,
        cleanup_supported=True,
        description="Simulate deletion of system recovery artifacts",
        platform="linux",
        execution_fidelity=ExecutionFidelity.INSPIRED,
        fidelity_justification=(
            "T1490 deletes backups and recovery partitions to prevent restoration. "
            "This execution logs which recovery artifacts exist without modifying "
            "them, preserving the intent while protecting the lab substrate."
        ),
        original_platform="any",
        requires_privilege="user",
    ),
)
def execute_t1490_simulated(
    campaign_id: str,
    sut_profile_id: str,
    **kwargs,
) -> Tuple[bool, str, str, List[str]]:
    campaign_dir = _campaign_dir(campaign_id)
    recovery_targets = [
        "/var/backups",
        "/boot/grub/grub.cfg",
        "/etc/default/grub",
    ]
    found = [path for path in recovery_targets if Path(path).exists()]
    log_path = campaign_dir / "recovery_inhibition_log.json"
    _write_json(
        log_path,
        {
            "campaign_id": campaign_id,
            "recovery_targets_surveyed": recovery_targets,
            "targets_present": found,
            "action": "surveyed_only",
            "timestamp": datetime.now().isoformat(),
        },
    )
    return (
        True,
        f"Recovery artifacts surveyed: {len(found)}/{len(recovery_targets)} present",
        "",
        [str(log_path)],
    )


@register_executor(
    technique_id="T1007",
    metadata=ExecutorMetadata(
        technique_id="T1007",
        technique_name="System Service Discovery",
        execution_mode=ExecutionMode.REAL_CONTROLLED,
        produces=["discovery:services"],
        requires=["code_execution"],
        safe_simulation=True,
        cleanup_supported=True,
        description="Enumerate local services in a bounded environment",
        platform="linux",
        execution_fidelity=ExecutionFidelity.ADAPTED,
        fidelity_justification=(
            "T1007 discovers local services. This execution runs real service "
            "enumeration commands in a bounded environment and records the "
            "results without modifying service state."
        ),
        original_platform="any",
        requires_privilege="user",
    ),
)
def execute_t1007_real(
    campaign_id: str,
    sut_profile_id: str,
    **kwargs,
) -> Tuple[bool, str, str, List[str]]:
    campaign_dir = _campaign_dir(campaign_id)
    result = subprocess.run(
        [
            "sh",
            "-c",
            "systemctl list-units --type=service --no-pager --no-legend 2>/dev/null | head -20 || service --status-all 2>/dev/null | head -20",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    services_log = campaign_dir / "service_discovery.log"
    services_log.write_text(result.stdout, encoding="utf-8")
    return True, "System service discovery completed", result.stderr, [str(services_log)]


@register_executor(
    technique_id="T1055",
    metadata=ExecutorMetadata(
        technique_id="T1055",
        technique_name="Process Injection",
        execution_mode=ExecutionMode.NAIVE_SIMULATED,
        produces=["defense_evasion:injected_process"],
        requires=["code_execution"],
        safe_simulation=True,
        cleanup_supported=True,
        description="Record a bounded process-injection handoff against a benign child process",
        platform="linux",
        execution_fidelity=ExecutionFidelity.INSPIRED,
        fidelity_justification=(
            "T1055 injects code into another process. This execution launches a "
            "benign child process and records a controlled payload handoff "
            "manifest instead of modifying live process memory."
        ),
        original_platform="any",
        requires_privilege="user",
    ),
)
def execute_t1055_simulated(
    campaign_id: str,
    sut_profile_id: str,
    **kwargs,
) -> Tuple[bool, str, str, List[str]]:
    campaign_dir = _campaign_dir(campaign_id)
    child = subprocess.Popen(["python3", "-c", "import time; time.sleep(2)"])
    try:
        manifest_path = campaign_dir / "process_injection_manifest.json"
        _write_json(
            manifest_path,
            {
                "campaign_id": campaign_id,
                "target_pid": child.pid,
                "payload": "bounded_loader_stub",
                "timestamp": datetime.now().isoformat(),
            },
        )
    finally:
        child.terminate()
        child.wait(timeout=5)
    return True, "Bounded process-injection manifest created", "", [str(manifest_path)]


@register_executor(
    technique_id="T1564.001",
    metadata=ExecutorMetadata(
        technique_id="T1564.001",
        technique_name="Hide Artifacts: Hidden Files and Directories",
        execution_mode=ExecutionMode.REAL_CONTROLLED,
        produces=["defense_evasion:hidden_artifacts"],
        requires=["code_execution"],
        safe_simulation=True,
        cleanup_supported=True,
        description="Create bounded hidden files and directories",
        platform="linux",
        execution_fidelity=ExecutionFidelity.ADAPTED,
        fidelity_justification=(
            "T1564.001 hides artifacts using filesystem semantics. This execution "
            "creates real dot-prefixed files and directories inside the bounded "
            "artifact area."
        ),
        original_platform="any",
        requires_privilege="user",
    ),
)
def execute_t1564_001_real(
    campaign_id: str,
    sut_profile_id: str,
    **kwargs,
) -> Tuple[bool, str, str, List[str]]:
    campaign_dir = _campaign_dir(campaign_id)
    hidden_dir = campaign_dir / ".cache"
    hidden_dir.mkdir(parents=True, exist_ok=True)
    hidden_file = hidden_dir / ".session"
    hidden_file.write_text(
        f"hidden_artifact_created_at={datetime.now().isoformat()}\n",
        encoding="utf-8",
    )
    return True, "Hidden artifacts created", "", [str(hidden_dir), str(hidden_file)]


@register_executor(
    technique_id="T1027",
    metadata=ExecutorMetadata(
        technique_id="T1027",
        technique_name="Obfuscated Files or Information",
        execution_mode=ExecutionMode.REAL_CONTROLLED,
        produces=["artifacts:obfuscated_payload"],
        requires=["code_execution"],
        safe_simulation=True,
        cleanup_supported=True,
        description="Generate a bounded base64-obfuscated payload artifact",
        platform="linux",
        execution_fidelity=ExecutionFidelity.ADAPTED,
        fidelity_justification=(
            "T1027 obfuscates payloads or information. This execution creates a "
            "real base64-obfuscated payload artifact inside the bounded lab area."
        ),
        original_platform="any",
        requires_privilege="user",
    ),
)
def execute_t1027_real(
    campaign_id: str,
    sut_profile_id: str,
    **kwargs,
) -> Tuple[bool, str, str, List[str]]:
    campaign_dir = _campaign_dir(campaign_id)
    payload_path = campaign_dir / "obfuscated_payload.b64"
    result = subprocess.run(
        [
            "python3",
            "-c",
            (
                "import base64; "
                "print(base64.b64encode(b'STICKS bounded payload').decode())"
            ),
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    payload_path.write_text(result.stdout.strip() + "\n", encoding="utf-8")
    return True, "Obfuscated payload artifact created", "", [str(payload_path)]


@register_executor(
    technique_id="T1491",
    metadata=ExecutorMetadata(
        technique_id="T1491",
        technique_name="Defacement",
        execution_mode=ExecutionMode.REAL_CONTROLLED,
        produces=["impact:defacement"],
        requires=["code_execution"],
        safe_simulation=True,
        cleanup_supported=True,
        description="Generate a bounded defaced web page artifact",
        platform="linux",
        execution_fidelity=ExecutionFidelity.ADAPTED,
        fidelity_justification=(
            "T1491 modifies visual web content. This execution creates a bounded "
            "defaced HTML artifact without altering a real production website."
        ),
        original_platform="any",
        requires_privilege="user",
    ),
)
def execute_t1491_real(
    campaign_id: str,
    sut_profile_id: str,
    **kwargs,
) -> Tuple[bool, str, str, List[str]]:
    campaign_dir = _campaign_dir(campaign_id)
    defaced_page = campaign_dir / "defaced_index.html"
    defaced_page.write_text(
        "<html><body><h1>STICKS Controlled Defacement</h1>"
        f"<p>campaign={campaign_id}</p>"
        f"<p>timestamp={datetime.now().isoformat()}</p>"
        "</body></html>\n",
        encoding="utf-8",
    )
    return True, "Bounded defacement artifact created", "", [str(defaced_page)]
