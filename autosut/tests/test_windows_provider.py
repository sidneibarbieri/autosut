"""Windows provider planning and lifecycle tests. No test starts Vagrant or a VM."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(PROJECT_ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from orchestrator.windows_provider import (  # noqa: E402
    WindowsImageReference,
    WindowsMaterializationError,
    WindowsProviderError,
    WindowsProviderKind,
    WindowsVagrantMaterializer,
    WindowsVagrantProvider,
    WindowsVagrantSession,
)
from src.infrastructure.windows_architecture import WindowsGuestArchitecture  # noqa: E402
from src.planning.campaign_requirements import (  # noqa: E402
    CampaignRequirements,
    IdentityModel,
    PlatformFamily,
)
from src.planning.requirements_admission import (  # noqa: E402
    AdmittedCampaignRequirements,
    RequirementsAdmissionReceipt,
)


def _requirements() -> CampaignRequirements:
    return CampaignRequirements(
        campaign_id="C-EXAMPLE",
        source_bundle_sha256="c" * 64,
        target_platforms=[PlatformFamily.WINDOWS],
        identity_model=IdentityModel.WORKGROUP,
        network_segments=[
            {
                "segment_id": "labnet",
                "cidr": "192.168.56.0/24",
                "provenance_refs": ["lab-policy"],
            }
        ],
        hosts=[
            {
                "host_id": "host-a",
                "hostname": "host-a",
                "role": "workstation",
                "platform": "windows",
                "network_segment_id": "labnet",
                "ipv4_address": "192.168.56.30",
                "memory_mib": 4096,
                "cpus": 2,
                "provenance_refs": ["lab-policy"],
            },
            {
                "host_id": "host-b",
                "hostname": "host-b",
                "role": "peer-workstation",
                "platform": "windows",
                "network_segment_id": "labnet",
                "ipv4_address": "192.168.56.31",
                "memory_mib": 4096,
                "cpus": 2,
                "provenance_refs": ["lab-policy"],
            },
        ],
        identities=[
            {
                "principal_id": "host-a-admin",
                "host_id": "host-a",
                "username": "autosutadmin",
                "privilege": "local_administrator",
                "runtime_secret_environment_variable": "AUTOSUT_WINDOWS_HOST_A_ADMIN_PASSWORD",
                "purpose": "provider administration",
                "provenance_refs": ["lab-policy"],
            },
            {
                "principal_id": "host-b-admin",
                "host_id": "host-b",
                "username": "autosutadmin",
                "privilege": "local_administrator",
                "runtime_secret_environment_variable": "AUTOSUT_WINDOWS_HOST_B_ADMIN_PASSWORD",
                "purpose": "provider administration",
                "provenance_refs": ["lab-policy"],
            },
        ],
        procedure_requirements=[
            {
                "technique_id": "T1021.002",
                "execution_domain": "target",
                "required_host_ids": ["host-a", "host-b"],
                "required_principal_ids": ["host-a-admin"],
                "evidence_predicates": ["remote-service-session-observed"],
                "provenance_refs": ["stix-plan"],
            }
        ],
        provenance=[
            {
                "provenance_id": "stix-plan",
                "kind": "stix",
                "source_sha256": "a" * 64,
                "locator": "relationship--example",
            },
            {
                "provenance_id": "lab-policy",
                "kind": "analyst_decision",
                "source_sha256": "b" * 64,
                "locator": "policy/windows-workgroup-v1",
            },
        ],
    )


def _image() -> WindowsImageReference:
    return WindowsImageReference(
        box_name="autosut/windows-server-evaluation",
        box_version="2022.1",
        source_uri="https://example.invalid/autosut/windows-server-evaluation.box",
        sha256="d" * 64,
    )


def _admitted(
    requirements: CampaignRequirements | None = None,
    *,
    verified: bool = True,
) -> AdmittedCampaignRequirements:
    requirements = requirements or _requirements()
    manifest_sha256 = "e" * 64 if verified else None
    receipt = RequirementsAdmissionReceipt(
        procedural_plan_sha256="f" * 64,
        semantic_input_sha256="1" * 64,
        semantic_admission_sha256="2" * 64,
        semantic_evidence_manifest_sha256=manifest_sha256,
        semantic_evidence_verified=verified,
        requirements_sha256=requirements.content_sha256(),
        qualification_blockers=["admission is planning-only, not execution evidence"],
    )
    return AdmittedCampaignRequirements(requirements=requirements, receipt=receipt)


def _session(tmp_path: Path) -> WindowsVagrantSession:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    plan = WindowsVagrantProvider(WindowsProviderKind.LIBVIRT).render(
        _requirements(), _image()
    ).manifest
    return WindowsVagrantSession(
        run_dir=run_dir,
        plan=plan,
        image_box_sha256="9" * 64,
        vagrant_binary="/opt/autosut/bin/vagrant",
        environment={"PATH": "/opt/autosut/bin"},
    )


def test_provider_renders_secret_free_plan_with_explicit_architecture_and_boundaries(
    tmp_path: Path,
) -> None:
    manifest = WindowsVagrantProvider(WindowsProviderKind.LIBVIRT).write_plan(
        _requirements(), _image(), tmp_path
    )

    vagrantfile = (tmp_path / "Vagrantfile").read_text(encoding="utf-8")
    plan = json.loads((tmp_path / "windows-vagrant-plan.json").read_text(encoding="utf-8"))
    assert 'config.vm.define "host-a"' in vagrantfile
    assert 'config.vm.define "host-b"' in vagrantfile
    assert 'ENV.fetch("AUTOSUT_WINDOWS_BOX_FILE")' in vagrantfile
    assert "node.winrm.password" not in vagrantfile
    assert "AUTOSUT_WINDOWS_HOST_A_ADMIN_PASSWORD" not in vagrantfile
    assert "private_network alone does not establish network isolation" in vagrantfile
    assert manifest.qualification_status == "development_in_progress"
    assert plan["requirements_sha256"] == _requirements().content_sha256()
    assert plan["guest_architecture"] == "x86_64"
    assert plan["unattend_processor_architecture"] == "amd64"
    assert plan["unattended_template_filename"] == "autounattend.host_a.x86_64.xml"
    assert plan["network_isolation_status"] == "unqualified"
    assert plan["realization_binding_status"] == "absent"
    assert plan["per_host_unattend_binding_status"] == "absent"
    assert "does not establish" in plan["non_claim"]


def test_vagrant_provider_rejects_an_arm64_image_contract() -> None:
    with pytest.raises(ValidationError, match="x86_64 images only"):
        WindowsImageReference(
            box_name="autosut/windows-server-evaluation",
            box_version="2022.1",
            source_uri="https://example.invalid/autosut/windows-server-evaluation.box",
            sha256="d" * 64,
            architecture=WindowsGuestArchitecture.ARM64,
        )


@pytest.mark.parametrize(
    "source_uri",
    [
        "https://example.invalid/box?temporary-token=secret",
        "https://example.invalid/box#temporary-token",
        "https://user:password@example.invalid/box",
    ],
)
def test_image_reference_rejects_persisted_credentials_or_signed_url_parts(source_uri: str) -> None:
    with pytest.raises(ValidationError, match="without credentials, query, or fragment"):
        WindowsImageReference(
            box_name="autosut/windows-server-evaluation",
            box_version="2022.1",
            source_uri=source_uri,
            sha256="d" * 64,
        )


def test_same_inputs_render_byte_identical_files(tmp_path: Path) -> None:
    provider = WindowsVagrantProvider(WindowsProviderKind.HYPERV)
    first = tmp_path / "first"
    second = tmp_path / "second"
    provider.write_plan(_requirements(), _image(), first)
    provider.write_plan(_requirements(), _image(), second)

    for filename in ("campaign-requirements.json", "Vagrantfile", "windows-vagrant-plan.json"):
        assert (first / filename).read_bytes() == (second / filename).read_bytes()


def test_write_refuses_to_overwrite_divergent_plan(tmp_path: Path) -> None:
    provider = WindowsVagrantProvider(WindowsProviderKind.LIBVIRT)
    provider.write_plan(_requirements(), _image(), tmp_path)
    (tmp_path / "Vagrantfile").write_text("divergent", encoding="utf-8")

    with pytest.raises(FileExistsError, match="divergent provider plan"):
        provider.write_plan(_requirements(), _image(), tmp_path)


def test_provider_rejects_active_directory_instead_of_downgrading_it() -> None:
    payload = _requirements().model_dump(mode="json")
    payload["identity_model"] = "active_directory"
    requirements = CampaignRequirements.model_validate(payload)

    with pytest.raises(WindowsProviderError, match="does not substitute a workgroup"):
        WindowsVagrantProvider(WindowsProviderKind.LIBVIRT).render(requirements, _image())


def test_admitted_one_host_bridge_output_is_not_treated_as_a_windows_workgroup() -> None:
    payload = _requirements().model_dump(mode="json")
    payload["hosts"] = payload["hosts"][:1]
    payload["identities"] = payload["identities"][:1]
    payload["procedure_requirements"][0]["required_host_ids"] = ["host-a"]
    requirements = CampaignRequirements.model_validate(payload)

    with pytest.raises(WindowsProviderError, match="at least two hosts"):
        WindowsVagrantProvider(WindowsProviderKind.LIBVIRT).render_admitted(
            _admitted(requirements), _image()
        )


def test_provider_check_never_reports_planning_as_execution_ready() -> None:
    readiness = WindowsVagrantProvider.check()

    assert readiness.backend_name == "windows_vagrant_plan"
    assert readiness.ready is False
    assert any("no-egress" in gap for gap in readiness.gaps)
    assert any("materialization is blocked" in gap for gap in readiness.gaps)


def test_materializer_rejects_a_naked_requirements_plan_before_any_vagrant_lookup(
    monkeypatch, tmp_path: Path
) -> None:
    import orchestrator.windows_provider as module

    WindowsVagrantProvider(WindowsProviderKind.LIBVIRT).write_plan(
        _requirements(), _image(), tmp_path / "plan"
    )
    monkeypatch.setattr(
        module.shutil,
        "which",
        lambda name: (_ for _ in ()).throw(AssertionError("vagrant lookup must not occur")),
    )

    with pytest.raises(WindowsMaterializationError, match="AdmittedCampaignRequirements"):
        WindowsVagrantMaterializer().prepare(
            plan_directory=tmp_path / "plan",
            box_file=tmp_path / "unused.box",
            run_root=tmp_path,
        )


def test_materializer_requires_verified_admission_before_any_vagrant_lookup(
    monkeypatch, tmp_path: Path
) -> None:
    import orchestrator.windows_provider as module

    WindowsVagrantProvider(WindowsProviderKind.LIBVIRT).write_admitted_plan(
        _admitted(verified=False), _image(), tmp_path / "plan"
    )
    monkeypatch.setattr(
        module.shutil,
        "which",
        lambda name: (_ for _ in ()).throw(AssertionError("vagrant lookup must not occur")),
    )

    with pytest.raises(WindowsMaterializationError, match="verified semantic admission"):
        WindowsVagrantMaterializer().prepare(
            plan_directory=tmp_path / "plan",
            box_file=tmp_path / "unused.box",
            run_root=tmp_path,
        )


def test_materializer_rejects_blocking_requirements_before_realization_or_vagrant(
    monkeypatch, tmp_path: Path
) -> None:
    import orchestrator.windows_provider as module

    payload = _requirements().model_dump(mode="json")
    payload["unresolved_items"] = [
        {
            "item_id": "missing-winrm-proof",
            "category": "procedure-precondition",
            "description": "The source does not establish the required remote-management service.",
            "blocks_materialization": True,
            "provenance_refs": ["stix-plan"],
        }
    ]
    requirements = CampaignRequirements.model_validate(payload)
    WindowsVagrantProvider(WindowsProviderKind.LIBVIRT).write_admitted_plan(
        _admitted(requirements), _image(), tmp_path / "plan"
    )
    monkeypatch.setattr(
        module.shutil,
        "which",
        lambda name: (_ for _ in ()).throw(AssertionError("vagrant lookup must not occur")),
    )

    with pytest.raises(WindowsMaterializationError, match="blocked by unresolved requirements"):
        WindowsVagrantMaterializer().prepare(
            plan_directory=tmp_path / "plan",
            box_file=tmp_path / "unused.box",
            run_root=tmp_path,
        )


def test_materializer_blocks_an_admitted_plan_without_realization_bindings(
    monkeypatch, tmp_path: Path
) -> None:
    import orchestrator.windows_provider as module

    WindowsVagrantProvider(WindowsProviderKind.LIBVIRT).write_admitted_plan(
        _admitted(), _image(), tmp_path / "plan"
    )
    monkeypatch.setattr(
        module.shutil,
        "which",
        lambda name: (_ for _ in ()).throw(AssertionError("vagrant lookup must not occur")),
    )

    with pytest.raises(WindowsMaterializationError, match="realization catalog/provisioner"):
        WindowsVagrantMaterializer().prepare(
            plan_directory=tmp_path / "plan",
            box_file=tmp_path / "unused.box",
            run_root=tmp_path,
        )


def test_materializer_rejects_tampered_admitted_vagrantfile(tmp_path: Path) -> None:
    plan_directory = tmp_path / "plan"
    WindowsVagrantProvider(WindowsProviderKind.LIBVIRT).write_admitted_plan(
        _admitted(), _image(), plan_directory
    )
    (plan_directory / "Vagrantfile").write_text("system('unexpected')\n", encoding="utf-8")

    with pytest.raises(WindowsMaterializationError, match="Vagrantfile does not match"):
        WindowsVagrantMaterializer().prepare(
            plan_directory=plan_directory,
            box_file=tmp_path / "unused.box",
            run_root=tmp_path,
        )


def test_runtime_environment_isolated_from_global_home_plugins_and_unrelated_tokens(
    tmp_path: Path,
) -> None:
    box_file = tmp_path / "operator-supplied-windows.box"
    box_file.write_bytes(b"controlled test Vagrant box")
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    plan = WindowsVagrantProvider(WindowsProviderKind.LIBVIRT).render(
        _requirements(), _image()
    ).manifest

    environment = WindowsVagrantMaterializer._runtime_environment(
        plan=plan,
        box_file=box_file,
        run_dir=run_dir,
        supplied={
            "PATH": "/safe/bin",
            "HOME": "/global/home",
            "VAGRANT_HOME": "/global/vagrant-home",
            "XDG_CONFIG_HOME": "/global/config",
            "OPENAI_API_KEY": "must-not-reach-vagrant",
            "AUTOSUT_WINDOWS_HOST_A_ADMIN_PASSWORD": "must-not-reach-vagrant",
        },
    )

    assert environment["PATH"] == "/safe/bin"
    assert environment["HOME"] == str(run_dir / ".home")
    assert environment["VAGRANT_HOME"] == str(run_dir / ".vagrant-home")
    assert environment["AUTOSUT_WINDOWS_BOX_FILE"] == str(box_file)
    assert "OPENAI_API_KEY" not in environment
    assert "AUTOSUT_WINDOWS_HOST_A_ADMIN_PASSWORD" not in environment
    assert "XDG_CONFIG_HOME" not in environment
    assert (run_dir / ".home").stat().st_mode & 0o777 == 0o700
    assert (run_dir / ".vagrant-home").stat().st_mode & 0o777 == 0o700


def test_vagrant_binary_is_resolved_once_to_an_absolute_path(monkeypatch, tmp_path: Path) -> None:
    import orchestrator.windows_provider as module

    candidate = tmp_path / "bin" / "vagrant"
    candidate.parent.mkdir()
    candidate.write_text("placeholder", encoding="utf-8")
    monkeypatch.setattr(module.shutil, "which", lambda name: str(candidate))

    assert WindowsVagrantMaterializer._resolve_vagrant_binary() == str(candidate.resolve())


def test_session_receipt_never_persists_output_hashes_lengths_or_password_oracles(
    monkeypatch, tmp_path: Path
) -> None:
    import orchestrator.windows_provider as module

    session = _session(tmp_path)
    secret = "test-only-password-" + ("x" * 1337)
    secret_digest = hashlib.sha256(secret.encode("utf-8")).hexdigest()

    def fake_run(command, **kwargs):
        return subprocess.CompletedProcess(command, 0, secret, secret)

    monkeypatch.setattr(module.subprocess, "run", fake_run)
    session.start()
    session.teardown()

    receipt = (session.run_dir / "windows-materialization-receipt.json").read_text(encoding="utf-8")
    assert secret not in receipt
    assert secret_digest not in receipt
    assert '"stdout_sha256"' not in receipt
    assert '"stderr_sha256"' not in receipt
    assert '"stdout_bytes"' not in receipt
    assert '"stderr_bytes"' not in receipt
    assert "1337" not in receipt
    assert '"stdout_present": true' in receipt
    assert '"stderr_present": true' in receipt
    assert session.teardown_clean is True


def test_up_timeout_records_a_redacted_failure_then_attempts_scoped_destroy(
    monkeypatch, tmp_path: Path
) -> None:
    import orchestrator.windows_provider as module

    session = _session(tmp_path)
    calls: list[list[str]] = []
    secret = "test-only-timeout-password"

    def fake_run(command, **kwargs):
        calls.append(command)
        if command[1] == "up":
            raise subprocess.TimeoutExpired(command, timeout=1, output=secret, stderr=secret)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(module.subprocess, "run", fake_run)
    with pytest.raises(WindowsMaterializationError, match="TimeoutExpired"):
        session.start(timeout_seconds=1)

    assert calls == [
        ["/opt/autosut/bin/vagrant", "up", "--provider", "libvirt"],
        ["/opt/autosut/bin/vagrant", "destroy", "-f"],
    ]
    receipt = (session.run_dir / "windows-materialization-receipt.json").read_text(encoding="utf-8")
    assert '"error_kind": "TimeoutExpired"' in receipt
    assert secret not in receipt
    assert hashlib.sha256(secret.encode("utf-8")).hexdigest() not in receipt
    assert session.teardown_clean is True


def test_failed_up_and_nonzero_destroy_remain_a_dirty_failure(monkeypatch, tmp_path: Path) -> None:
    import orchestrator.windows_provider as module

    session = _session(tmp_path)

    def fake_run(command, **kwargs):
        returncode = 1 if command[1] == "up" else 7
        return subprocess.CompletedProcess(command, returncode, "", "failed")

    monkeypatch.setattr(module.subprocess, "run", fake_run)
    with pytest.raises(WindowsMaterializationError, match="scoped vagrant destroy attempt also failed"):
        session.start()

    receipt = (session.run_dir / "windows-materialization-receipt.json").read_text(encoding="utf-8")
    assert '"returncode": 7' in receipt
    assert session.teardown_clean is False


def test_nonzero_teardown_never_returns_a_clean_session(monkeypatch, tmp_path: Path) -> None:
    import orchestrator.windows_provider as module

    session = _session(tmp_path)

    def fake_run(command, **kwargs):
        returncode = 0 if command[1] == "up" else 9
        return subprocess.CompletedProcess(command, returncode, "", "destroy failed")

    monkeypatch.setattr(module.subprocess, "run", fake_run)
    session.start()
    with pytest.raises(WindowsMaterializationError, match="vagrant destroy failed"):
        session.teardown()

    assert session.teardown_clean is False


def test_direct_keyboard_interrupt_records_and_cleans_up_without_masking_interrupt(
    monkeypatch, tmp_path: Path
) -> None:
    import orchestrator.windows_provider as module

    session = _session(tmp_path)
    calls: list[list[str]] = []

    def fake_run(command, **kwargs):
        calls.append(command)
        if command[1] == "up":
            raise KeyboardInterrupt()
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(module.subprocess, "run", fake_run)
    with pytest.raises(KeyboardInterrupt):
        session.start()

    assert calls[-1] == ["/opt/autosut/bin/vagrant", "destroy", "-f"]
    receipt = (session.run_dir / "windows-materialization-receipt.json").read_text(encoding="utf-8")
    assert '"error_kind": "KeyboardInterrupt"' in receipt
    assert session.teardown_clean is True


def test_context_manager_raises_on_failed_teardown_when_body_succeeds(
    monkeypatch, tmp_path: Path
) -> None:
    import orchestrator.windows_provider as module

    session = _session(tmp_path)

    def fake_run(command, **kwargs):
        returncode = 0 if command[1] == "up" else 3
        return subprocess.CompletedProcess(command, returncode, "", "")

    monkeypatch.setattr(module.subprocess, "run", fake_run)
    with pytest.raises(WindowsMaterializationError, match="vagrant destroy failed"):
        with session:
            session.start()

    assert session.teardown_clean is False


def test_context_manager_preserves_original_keyboard_interrupt_when_teardown_fails(
    monkeypatch, tmp_path: Path
) -> None:
    import orchestrator.windows_provider as module

    session = _session(tmp_path)

    def fake_run(command, **kwargs):
        returncode = 0 if command[1] == "up" else 3
        return subprocess.CompletedProcess(command, returncode, "", "")

    monkeypatch.setattr(module.subprocess, "run", fake_run)
    with pytest.raises(KeyboardInterrupt):
        with session:
            session.start()
            raise KeyboardInterrupt()

    assert session.teardown_clean is False
