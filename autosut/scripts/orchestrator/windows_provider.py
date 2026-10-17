"""Deterministic planning adapter for a campaign-specific Windows workgroup.

This module deliberately renders a Vagrant plan rather than booting a guest.
The current repository has not qualified an x86_64 Windows guest through the
full boot, agent-enrolment, procedure, observation, and teardown chain.  A
rendered plan is therefore useful engineering input, not execution evidence.

The provider accepts ``CampaignRequirements`` instead of a fixed imported
laboratory.  It refuses Active Directory and non-Windows topologies rather
than silently substituting a workgroup.  It deliberately does not bind a
credential, answer-file, or provisioner until a requirements-bound Windows
realization interface exists.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Literal, Mapping
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from src.infrastructure.windows_architecture import (
    WindowsGuestArchitecture,
    unattend_processor_architecture,
    unattended_template_filename,
)
from src.planning.campaign_requirements import (
    CampaignRequirements,
    IdentityRequirement,
    IdentityModel,
    PlatformFamily,
    PrivilegeLevel,
)
from src.planning.requirements_admission import (
    AdmittedCampaignRequirements,
    RequirementsAdmissionReceipt,
)

from .environment_base import BackendReadiness

_BOX_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$")
_BOX_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SAFE_VAGRANT_ENVIRONMENT_VARIABLES = (
    "PATH",
    "TMPDIR",
    "TMP",
    "TEMP",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
)


class WindowsProviderKind(str, Enum):
    """Vagrant backends this plan knows how to describe."""

    LIBVIRT = "libvirt"
    HYPERV = "hyperv"


class WindowsProviderError(ValueError):
    """Raised when requirements cannot safely be rendered as a workgroup plan."""


class WindowsImageReference(BaseModel):
    """A hash-pinned, operator-supplied Windows Vagrant image reference."""

    model_config = ConfigDict(extra="forbid")

    box_name: str
    box_version: str
    source_uri: str
    sha256: str
    architecture: WindowsGuestArchitecture = WindowsGuestArchitecture.X86_64

    @field_validator("box_name")
    @classmethod
    def _validate_box_name(cls, value: str) -> str:
        if not _BOX_NAME_RE.fullmatch(value):
            raise ValueError("box_name contains unsupported characters")
        return value

    @field_validator("box_version")
    @classmethod
    def _validate_box_version(cls, value: str) -> str:
        if not _BOX_VERSION_RE.fullmatch(value):
            raise ValueError("box_version contains unsupported characters")
        return value

    @field_validator("source_uri")
    @classmethod
    def _validate_source_uri(cls, value: str) -> str:
        parsed = urlsplit(value)
        if (
            parsed.scheme != "https"
            or not parsed.netloc
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError(
                "source_uri must be an HTTPS origin/path without credentials, query, or fragment"
            )
        return value

    @field_validator("sha256")
    @classmethod
    def _validate_sha256(cls, value: str) -> str:
        normalized = value.lower()
        if not _SHA256_RE.fullmatch(normalized):
            raise ValueError("sha256 must be a lowercase SHA-256 digest")
        return normalized

    @field_validator("architecture")
    @classmethod
    def _validate_architecture(cls, value: WindowsGuestArchitecture) -> WindowsGuestArchitecture:
        if value is not WindowsGuestArchitecture.X86_64:
            raise ValueError("Windows workgroup provider currently plans x86_64 images only")
        return value


class WindowsVagrantPlan(BaseModel):
    """Secret-free manifest for one rendered, not-yet-qualified provider plan."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = "windows-vagrant-plan/v1"
    campaign_id: str
    provider: WindowsProviderKind
    qualification_status: str = "development_in_progress"
    requirements_sha256: str
    image: WindowsImageReference
    guest_architecture: WindowsGuestArchitecture
    unattend_processor_architecture: str
    unattended_template_filename: str
    host_ids: list[str] = Field(min_length=2)
    runtime_secret_environment_variables: list[str] = Field(min_length=2)
    runtime_box_environment_variable: str = "AUTOSUT_WINDOWS_BOX_FILE"
    admission_receipt_sha256: str | None = None
    realization_binding_status: Literal["absent"] = "absent"
    per_host_unattend_binding_status: Literal["absent"] = "absent"
    network_isolation_status: Literal["unqualified"] = "unqualified"
    network_isolation_blockers: list[str] = Field(min_length=1)
    materialization_blockers: list[str] = Field(min_length=1)
    rendered_files: dict[str, str]
    non_claim: str
    qualification_prerequisites: list[str]

    @model_validator(mode="after")
    def _validate_architecture_and_receipt_contract(self) -> "WindowsVagrantPlan":
        if self.guest_architecture is not self.image.architecture:
            raise ValueError("plan guest architecture does not match the image architecture")
        if self.unattend_processor_architecture != unattend_processor_architecture(
            self.guest_architecture
        ):
            raise ValueError("plan unattended processor architecture is inconsistent")
        if self.unattended_template_filename != unattended_template_filename(
            self.guest_architecture
        ):
            raise ValueError("plan unattended template filename is inconsistent")
        if self.admission_receipt_sha256 is not None and not _SHA256_RE.fullmatch(
            self.admission_receipt_sha256
        ):
            raise ValueError("plan admission receipt digest is invalid")
        return self


@dataclass(frozen=True)
class RenderedWindowsPlan:
    """In-memory result. ``write_plan`` persists these three deterministic files."""

    requirements_json: str
    vagrantfile: str
    admission_receipt_json: str | None
    manifest_json: str
    manifest: WindowsVagrantPlan


class VagrantCommandReceipt(BaseModel):
    """Secret-free metadata about one Vagrant command invocation."""

    model_config = ConfigDict(extra="forbid")

    command: list[str]
    returncode: int | None
    stdout_present: bool
    stderr_present: bool
    error_kind: str | None = None


class WindowsMaterializationReceipt(BaseModel):
    """Diagnostic record for a run directory; not a qualification result."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = "windows-materialization-receipt/v2"
    campaign_id: str
    requirements_sha256: str
    image_box_sha256: str
    provider: WindowsProviderKind
    commands: list[VagrantCommandReceipt] = Field(default_factory=list)
    teardown_clean: bool | None = None
    materialization_status: Literal["unqualified"] = "unqualified"
    network_isolation_status: Literal["unqualified"] = "unqualified"
    non_claim: str = (
        "This diagnostic receipt does not establish guest boot, agent enrolment, procedure "
        "execution, observed effect, no-egress network isolation, or qualification."
    )


class WindowsVagrantProvider:
    """Render a two-or-more-host Windows workgroup Vagrant plan.

    This is intentionally not an ``EnvironmentBackend`` implementation yet.
    The generic backend contract promises ``bring_up`` and ``run_shell``;
    implementing those methods before a qualified Windows substrate exists
    would let callers mistake a plan for a successful execution.
    """

    backend_name = "windows_vagrant_plan"

    def __init__(self, provider: WindowsProviderKind) -> None:
        self.provider = provider

    @classmethod
    def check(cls) -> BackendReadiness:
        """Report the honest boundary: planning is available, execution is not qualified."""
        return BackendReadiness(
            backend_name=cls.backend_name,
            ready=False,
            gaps=[
                "Windows provider renders a plan only and is not qualified for execution; no x86_64 "
                "Windows boot/enrolment/procedure/observation/teardown qualification has passed.",
                "Vagrant private_network does not establish no-egress isolation; provider-specific "
                "network verification has not been qualified.",
                "No requirements-bound realization catalog, provisioner, or per-host unattended "
                "renderer is implemented, so materialization is blocked.",
            ],
        )

    def render(
        self, requirements: CampaignRequirements, image: WindowsImageReference
    ) -> RenderedWindowsPlan:
        """Render a deterministic, secret-free Vagrant workgroup plan.

        This development-only form deliberately has no Step-2 admission receipt,
        realization catalog, provisioner, or per-host unattended binding.  It
        cannot be materialized.  The method does not read the environment and
        does not launch Vagrant, a VM, or a container.
        """
        return self._render(requirements, image, admission_receipt=None)

    def render_admitted(
        self,
        admitted: AdmittedCampaignRequirements,
        image: WindowsImageReference,
    ) -> RenderedWindowsPlan:
        """Render a planning-only plan bound to an admitted requirements receipt.

        Admission establishes the origin of the requirements, not that a SUT
        is realizable or executable.  The rendered plan therefore remains
        materialization-blocked until a separate realization interface exists.
        """
        return self._render(admitted.requirements, image, admission_receipt=admitted.receipt)

    def _render(
        self,
        requirements: CampaignRequirements,
        image: WindowsImageReference,
        *,
        admission_receipt: RequirementsAdmissionReceipt | None,
    ) -> RenderedWindowsPlan:
        self._validate_supported_requirements(requirements)
        requirements_json = _canonical_json(requirements.canonical_payload())
        vagrantfile = self._render_vagrantfile(requirements, image)
        rendered_files = {
            "campaign-requirements.json": _sha256_text(requirements_json),
            "Vagrantfile": _sha256_text(vagrantfile),
        }
        admission_receipt_json = (
            _canonical_json(admission_receipt.model_dump(mode="json"))
            if admission_receipt is not None
            else None
        )
        if admission_receipt_json is not None:
            rendered_files["requirements-admission-receipt.json"] = _sha256_text(
                admission_receipt_json
            )
        administrator_identities = self._administrator_identities(requirements)
        manifest = WindowsVagrantPlan(
            campaign_id=requirements.campaign_id,
            provider=self.provider,
            requirements_sha256=requirements.content_sha256(),
            image=image,
            guest_architecture=image.architecture,
            unattend_processor_architecture=unattend_processor_architecture(image.architecture),
            unattended_template_filename=unattended_template_filename(image.architecture),
            host_ids=[host.host_id for host in requirements.hosts],
            runtime_secret_environment_variables=sorted(
                identity.runtime_secret_environment_variable
                for identity in administrator_identities
                if identity.runtime_secret_environment_variable is not None
            ),
            admission_receipt_sha256=(
                _sha256_text(admission_receipt_json)
                if admission_receipt_json is not None
                else None
            ),
            network_isolation_blockers=[
                "The Vagrant private_network declaration does not verify provider-specific no-egress isolation."
            ],
            materialization_blockers=[
                "No requirements-bound realization catalog and provisioner are implemented.",
                "No per-host requirements-bound unattended renderer binds local identities to the image.",
            ],
            rendered_files=rendered_files,
            non_claim=(
                "This plan is a development input only. It does not establish that a Windows "
                "guest booted, enrolled an agent, executed a procedure, produced an observed "
                "effect, had no network egress, or tore down cleanly."
            ),
            qualification_prerequisites=[
                "Use an x86_64 host with the selected Vagrant provider and hardware virtualization.",
                "Verify the declared image hash before any boot attempt.",
                "Bind every non-empty requirement to a versioned realization catalog and provisioner.",
                "Bind each host identity to a per-host unattended renderer before passing a credential to Vagrant.",
                "Verify provider-specific no-egress isolation independently of private_network.",
                "Bind a cold-start run to this requirements hash and record independent observation.",
                "Promote execution capability only after evidence-backed teardown qualification passes.",
            ],
        )
        manifest_json = _canonical_json(manifest.model_dump(mode="json"))
        return RenderedWindowsPlan(
            requirements_json=requirements_json,
            vagrantfile=vagrantfile,
            admission_receipt_json=admission_receipt_json,
            manifest_json=manifest_json,
            manifest=manifest,
        )

    def write_plan(
        self,
        requirements: CampaignRequirements,
        image: WindowsImageReference,
        destination: Path,
    ) -> WindowsVagrantPlan:
        """Persist a plan atomically, refusing a pre-existing divergent plan."""
        rendered = self.render(requirements, image)
        destination.mkdir(parents=True, exist_ok=True)
        _write_deterministic(destination / "campaign-requirements.json", rendered.requirements_json)
        _write_deterministic(destination / "Vagrantfile", rendered.vagrantfile)
        _write_deterministic(destination / "windows-vagrant-plan.json", rendered.manifest_json)
        return rendered.manifest

    def write_admitted_plan(
        self,
        admitted: AdmittedCampaignRequirements,
        image: WindowsImageReference,
        destination: Path,
    ) -> WindowsVagrantPlan:
        """Persist an admission-bound planning plan without making it materializable."""
        rendered = self.render_admitted(admitted, image)
        assert rendered.admission_receipt_json is not None
        destination.mkdir(parents=True, exist_ok=True)
        _write_deterministic(destination / "campaign-requirements.json", rendered.requirements_json)
        _write_deterministic(destination / "Vagrantfile", rendered.vagrantfile)
        _write_deterministic(
            destination / "requirements-admission-receipt.json", rendered.admission_receipt_json
        )
        _write_deterministic(destination / "windows-vagrant-plan.json", rendered.manifest_json)
        return rendered.manifest

    def _validate_supported_requirements(self, requirements: CampaignRequirements) -> None:
        if PlatformFamily.WINDOWS not in requirements.target_platforms:
            raise WindowsProviderError("Windows Vagrant provider requires Windows target_platforms")
        if requirements.identity_model is not IdentityModel.WORKGROUP:
            raise WindowsProviderError(
                "Windows Vagrant provider supports workgroup identity only; "
                "it does not substitute a workgroup for Active Directory"
            )
        if len(requirements.hosts) < 2:
            raise WindowsProviderError("Windows workgroup plan requires at least two hosts")
        non_windows = [
            host.host_id
            for host in requirements.hosts
            if host.platform is not PlatformFamily.WINDOWS
        ]
        if non_windows:
            raise WindowsProviderError(
                "Windows workgroup plan cannot silently materialize non-Windows hosts: "
                + ", ".join(non_windows)
            )
        administrator_identities = self._administrator_identities(requirements)
        if len(administrator_identities) != len(requirements.hosts):
            raise WindowsProviderError(
                "each Windows host needs exactly one local_administrator identity with a runtime secret reference"
            )
        administrator_hosts = {identity.host_id for identity in administrator_identities}
        if administrator_hosts != {host.host_id for host in requirements.hosts}:
            raise WindowsProviderError("each Windows host needs one local_administrator identity")
        for identity in administrator_identities:
            variable = identity.runtime_secret_environment_variable
            if variable is None or not variable.startswith("AUTOSUT_WINDOWS_"):
                raise WindowsProviderError(
                    "Windows administrator secrets must be referenced by AUTOSUT_WINDOWS_* environment variables"
                )
        variable_names = [
            identity.runtime_secret_environment_variable for identity in administrator_identities
        ]
        if len(variable_names) != len(set(variable_names)):
            raise WindowsProviderError(
                "each Windows host must use a distinct administrator secret environment variable"
            )

    @staticmethod
    def _administrator_identities(
        requirements: CampaignRequirements,
    ) -> list[IdentityRequirement]:
        return [
            identity
            for identity in requirements.identities
            if identity.privilege is PrivilegeLevel.LOCAL_ADMINISTRATOR
        ]

    def _render_vagrantfile(
        self,
        requirements: CampaignRequirements,
        image: WindowsImageReference,
    ) -> str:
        lines = [
            "# -*- mode: ruby -*-",
            "# AutoSUT Windows workgroup plan. Rendering this file is not execution evidence.",
            "# Guest architecture is x86_64; use autounattend.host_a.x86_64.xml (amd64) only.",
            "# No WinRM identity, secret, unattended file, provisioner, or no-egress policy is bound here.",
            "# private_network alone does not establish network isolation.",
            "",
            f"expected_provider = {_ruby_string(self.provider.value)}",
            'if ENV.key?("VAGRANT_DEFAULT_PROVIDER") && ENV.fetch("VAGRANT_DEFAULT_PROVIDER") != expected_provider',
            '  raise "VAGRANT_DEFAULT_PROVIDER does not match this plan"',
            "end",
            'ENV["VAGRANT_DEFAULT_PROVIDER"] = expected_provider',
            "",
            'Vagrant.configure("2") do |config|',
            "  config.vm.box_check_update = false",
            '  config.vm.synced_folder ".", "/vagrant", disabled: true',
            "",
        ]
        for host in requirements.hosts:
            lines.extend(
                [
                    f"  config.vm.define {_ruby_string(host.host_id)} do |node|",
                    f"    node.vm.box = {_ruby_string(image.box_name)}",
                    f"    node.vm.box_version = {_ruby_string(image.box_version)}",
                    '    node.vm.box_url = ENV.fetch("AUTOSUT_WINDOWS_BOX_FILE")',
                    f"    node.vm.hostname = {_ruby_string(host.hostname)}",
                    "    node.vm.guest = :windows",
                    f'    node.vm.network "private_network", ip: {_ruby_string(host.ipv4_address)}',
                    f'    node.vm.provider "libvirt" do |provider|',
                    f"      provider.memory = {host.memory_mib}",
                    f"      provider.cpus = {host.cpus}",
                    "    end",
                    '    node.vm.provider "hyperv" do |provider|',
                    f"      provider.memory = {host.memory_mib}",
                    f"      provider.cpus = {host.cpus}",
                    "    end",
                    "  end",
                    "",
                ]
            )
        lines.extend(
            [
                "end",
                "",
                "# No provisioning command is emitted here. A future qualified protocol must bind",
                "# realization, per-host identity rendering, independent observation, isolation, and teardown.",
                "",
            ]
        )
        return "\n".join(lines)


def _ruby_string(value: str) -> str:
    """Use JSON's escaped string grammar, which is compatible with Ruby strings here."""
    return json.dumps(value, ensure_ascii=True)


def _canonical_json(payload: object) -> str:
    return json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=True) + "\n"


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _write_deterministic(path: Path, content: str) -> None:
    """Write one public, secret-free plan file without silently changing an existing plan."""
    if path.exists():
        existing = path.read_text(encoding="utf-8")
        if existing != content:
            raise FileExistsError(f"refusing to overwrite divergent provider plan file: {path}")
        return
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=path.parent, prefix=f".{path.name}.", delete=False
    ) as handle:
        handle.write(content)
        temporary = Path(handle.name)
    temporary.chmod(0o644)
    temporary.replace(path)


class WindowsMaterializationError(RuntimeError):
    """A safe materialization precondition or Vagrant command did not succeed."""


class WindowsVagrantSession:
    """One isolated Vagrant attempt, with explicit start and teardown operations.

    The session has no procedure-execution API. It only owns provider lifecycle
    actions so an orchestration layer can later bind execution and independent
    observation to a separately qualified protocol.
    """

    def __init__(
        self,
        *,
        run_dir: Path,
        plan: WindowsVagrantPlan,
        image_box_sha256: str,
        vagrant_binary: str,
        environment: dict[str, str],
    ) -> None:
        self.run_dir = run_dir
        self.plan = plan
        if not Path(vagrant_binary).is_absolute():
            raise WindowsMaterializationError("vagrant binary must be an absolute path")
        self._vagrant_binary = vagrant_binary
        self._environment = environment
        self._receipt = WindowsMaterializationReceipt(
            campaign_id=plan.campaign_id,
            requirements_sha256=plan.requirements_sha256,
            image_box_sha256=image_box_sha256,
            provider=plan.provider,
        )
        self._started = False
        self._up_attempted = False
        self._teardown_attempted = False
        self._write_receipt()

    @property
    def started(self) -> bool:
        """Whether ``vagrant up`` returned success for this attempt."""
        return self._started

    @property
    def teardown_clean(self) -> bool | None:
        """The latest teardown result, if teardown was attempted."""
        return self._receipt.teardown_clean

    def start(self, *, timeout_seconds: int = 1_800) -> VagrantCommandReceipt:
        """Run a hash-verified Vagrant ``up`` without logging output or secrets."""
        if self._up_attempted:
            raise WindowsMaterializationError("vagrant up was already attempted for this session")
        if self._teardown_attempted:
            raise WindowsMaterializationError("cannot start a session after teardown was requested")
        self._up_attempted = True
        try:
            receipt = self._run_vagrant(
                [self._vagrant_binary, "up", "--provider", self.plan.provider.value], timeout_seconds
            )
        except WindowsMaterializationError as error:
            self._teardown_after_start_failure(error, timeout_seconds)
            raise
        except KeyboardInterrupt as interruption:
            self._teardown_after_interruption(interruption, timeout_seconds)
            raise
        if receipt.returncode != 0:
            self._teardown_after_start_failure(None, timeout_seconds)
            raise WindowsMaterializationError(
                "vagrant up failed; an isolated vagrant destroy attempt was recorded in "
                f"{self.run_dir / 'windows-materialization-receipt.json'}"
            )
        self._started = True
        return receipt

    def teardown(self, *, timeout_seconds: int = 900) -> VagrantCommandReceipt | None:
        """Destroy only the VM state owned by this generated run directory."""
        if self._teardown_attempted:
            return None
        self._teardown_attempted = True
        if not self._up_attempted:
            self._receipt.teardown_clean = None
            self._write_receipt()
            return None
        try:
            receipt = self._run_vagrant([self._vagrant_binary, "destroy", "-f"], timeout_seconds)
        except WindowsMaterializationError:
            self._receipt.teardown_clean = False
            self._write_receipt()
            raise
        if receipt.returncode != 0:
            self._receipt.teardown_clean = False
            self._write_receipt()
            raise WindowsMaterializationError(
                "vagrant destroy failed; the failed teardown is recorded in "
                f"{self.run_dir / 'windows-materialization-receipt.json'}"
            )
        self._receipt.teardown_clean = True
        self._write_receipt()
        return receipt

    def __enter__(self) -> "WindowsVagrantSession":
        return self

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> bool | None:
        try:
            self.teardown()
        except WindowsMaterializationError as teardown_error:
            if isinstance(exc_value, BaseException):
                exc_value.add_note(
                    "Windows Vagrant teardown also failed; inspect the redacted materialization receipt: "
                    f"{self.run_dir / 'windows-materialization-receipt.json'}"
                )
                return False
            raise teardown_error
        return None

    def _run_vagrant(self, command: list[str], timeout_seconds: int) -> VagrantCommandReceipt:
        try:
            completed = subprocess.run(
                command,
                cwd=self.run_dir,
                env=self._environment,
                capture_output=True,
                text=True,
                check=False,
                timeout=timeout_seconds,
            )
        except (subprocess.TimeoutExpired, OSError, KeyboardInterrupt) as error:
            receipt = _failure_receipt(command, error)
            self._receipt.commands.append(receipt)
            self._write_receipt()
            if isinstance(error, KeyboardInterrupt):
                raise
            raise WindowsMaterializationError(
                f"vagrant command did not complete ({type(error).__name__}); see the redacted receipt"
            ) from error
        receipt = VagrantCommandReceipt(
            command=command,
            returncode=completed.returncode,
            stdout_present=bool(completed.stdout),
            stderr_present=bool(completed.stderr),
        )
        self._receipt.commands.append(receipt)
        self._write_receipt()
        return receipt

    def _teardown_after_start_failure(
        self, start_error: WindowsMaterializationError | None, timeout_seconds: int
    ) -> None:
        """Attempt scoped cleanup while retaining an explicit failure if cleanup also fails."""
        try:
            self.teardown(timeout_seconds=timeout_seconds)
        except WindowsMaterializationError as teardown_error:
            if start_error is None:
                raise WindowsMaterializationError(
                    "vagrant up failed and the scoped vagrant destroy attempt also failed; "
                    f"see {self.run_dir / 'windows-materialization-receipt.json'}"
                ) from teardown_error
            combined_error = WindowsMaterializationError(
                "vagrant up did not complete and the scoped vagrant destroy attempt also failed; "
                f"see {self.run_dir / 'windows-materialization-receipt.json'}"
            )
            combined_error.add_note(f"teardown failure: {teardown_error}")
            raise combined_error from start_error

    def _teardown_after_interruption(
        self, interruption: KeyboardInterrupt, timeout_seconds: int
    ) -> None:
        """Attempt scoped cleanup without masking a user interruption."""
        try:
            self.teardown(timeout_seconds=timeout_seconds)
        except WindowsMaterializationError as teardown_error:
            interruption.add_note(
                "Windows Vagrant teardown also failed after interruption; inspect the redacted "
                f"materialization receipt: {self.run_dir / 'windows-materialization-receipt.json'}"
            )
            interruption.add_note(f"teardown failure: {teardown_error}")

    def _write_receipt(self) -> None:
        _write_deterministic_or_replace(
            self.run_dir / "windows-materialization-receipt.json",
            _canonical_json(self._receipt.model_dump(mode="json")),
        )


class WindowsVagrantMaterializer:
    """Verify a future materialization request without pretending it is runnable.

    ``prepare`` accepts only a plan bound to an admitted requirements receipt.
    It then fails closed until the repository has a requirements-bound
    realization catalog, provisioner, and per-host unattended renderer.  The
    remaining image, binary, environment, and lifecycle checks are retained
    behind that boundary so a later implementation does not silently revive
    the old unsafe behavior.
    """

    def prepare(
        self,
        *,
        plan_directory: Path,
        box_file: Path,
        run_root: Path,
        runtime_environment: Mapping[str, str] | None = None,
    ) -> WindowsVagrantSession:
        """Validate admission and fail closed until realization binding exists."""
        admitted, plan = self._load_and_verify_plan(plan_directory)
        self._require_realization_bindings(admitted, plan)
        vagrant_binary = self._resolve_vagrant_binary()
        resolved_box = box_file.expanduser().resolve(strict=True)
        if not resolved_box.is_file():
            raise WindowsMaterializationError("box_file must resolve to a regular file")
        observed_box_hash = _sha256_file(resolved_box)
        if observed_box_hash != plan.image.sha256:
            raise WindowsMaterializationError("caller-supplied box SHA-256 does not match the plan")
        destination_root = run_root.expanduser().resolve(strict=True)
        if not destination_root.is_dir():
            raise WindowsMaterializationError("run_root must be an existing directory")
        run_dir = Path(tempfile.mkdtemp(prefix="autosut-windows-", dir=destination_root))
        environment = self._runtime_environment(
            plan=plan,
            box_file=resolved_box,
            supplied=runtime_environment,
            run_dir=run_dir,
        )
        rendered = WindowsVagrantProvider(plan.provider).render_admitted(admitted, plan.image)
        assert rendered.admission_receipt_json is not None
        _write_deterministic(run_dir / "campaign-requirements.json", rendered.requirements_json)
        _write_deterministic(run_dir / "Vagrantfile", rendered.vagrantfile)
        _write_deterministic(
            run_dir / "requirements-admission-receipt.json", rendered.admission_receipt_json
        )
        _write_deterministic(run_dir / "windows-vagrant-plan.json", rendered.manifest_json)
        return WindowsVagrantSession(
            run_dir=run_dir,
            plan=plan,
            image_box_sha256=observed_box_hash,
            vagrant_binary=vagrant_binary,
            environment=environment,
        )

    def _load_and_verify_plan(
        self, plan_directory: Path
    ) -> tuple[AdmittedCampaignRequirements, WindowsVagrantPlan]:
        directory = plan_directory.expanduser().resolve(strict=True)
        if not directory.is_dir():
            raise WindowsMaterializationError("plan_directory must be a directory")
        requirements_path = directory / "campaign-requirements.json"
        vagrantfile_path = directory / "Vagrantfile"
        manifest_path = directory / "windows-vagrant-plan.json"
        try:
            requirements = CampaignRequirements.model_validate_json(
                requirements_path.read_text(encoding="utf-8")
            )
            plan = WindowsVagrantPlan.model_validate_json(manifest_path.read_text(encoding="utf-8"))
            supplied_vagrantfile = vagrantfile_path.read_text(encoding="utf-8")
        except FileNotFoundError as error:
            raise WindowsMaterializationError(f"plan file is missing: {error.filename}") from error
        if plan.admission_receipt_sha256 is None:
            raise WindowsMaterializationError(
                "materialization requires an AdmittedCampaignRequirements receipt binding; "
                "a naked CampaignRequirements plan is development-only"
            )
        receipt_path = directory / "requirements-admission-receipt.json"
        try:
            receipt_text = receipt_path.read_text(encoding="utf-8")
        except FileNotFoundError as error:
            raise WindowsMaterializationError(
                "materialization requires the admission receipt file bound by the plan"
            ) from error
        receipt = RequirementsAdmissionReceipt.model_validate_json(receipt_text)
        admitted = AdmittedCampaignRequirements(requirements=requirements, receipt=receipt)
        if not receipt.semantic_evidence_verified:
            raise WindowsMaterializationError(
                "materialization requires a verified semantic admission receipt"
            )
        expected = WindowsVagrantProvider(plan.provider).render_admitted(admitted, plan.image)
        assert expected.admission_receipt_json is not None
        blocking_items = [
            item.item_id for item in requirements.unresolved_items if item.blocks_materialization
        ]
        if blocking_items:
            raise WindowsMaterializationError(
                "materialization is blocked by unresolved requirements: "
                + ", ".join(blocking_items)
            )
        if requirements.content_sha256() != plan.requirements_sha256:
            raise WindowsMaterializationError("plan requirements SHA-256 does not match its DTO")
        if _sha256_text(expected.admission_receipt_json) != plan.admission_receipt_sha256:
            raise WindowsMaterializationError("plan admission receipt SHA-256 does not match its receipt")
        if requirements_path.read_text(encoding="utf-8") != expected.requirements_json:
            raise WindowsMaterializationError(
                "requirements file does not match the canonical renderer"
            )
        if supplied_vagrantfile != expected.vagrantfile:
            raise WindowsMaterializationError("Vagrantfile does not match the canonical renderer")
        if receipt_text != expected.admission_receipt_json:
            raise WindowsMaterializationError(
                "admission receipt does not match the canonical renderer"
            )
        if manifest_path.read_text(encoding="utf-8") != expected.manifest_json:
            raise WindowsMaterializationError("plan manifest does not match the canonical renderer")
        return admitted, plan

    @staticmethod
    def _require_realization_bindings(
        admitted: AdmittedCampaignRequirements, plan: WindowsVagrantPlan
    ) -> None:
        """Reject every current plan before an arbitrary base box can look like a SUT."""
        requirements = admitted.requirements
        required_categories = [
            category
            for category, values in (
                ("network", requirements.network_exposures),
                ("software", requirements.software_requirements),
                ("privilege", requirements.privilege_requirements),
                ("procedure", requirements.procedure_requirements),
            )
            if values
        ]
        if required_categories:
            raise WindowsMaterializationError(
                "materialization is blocked: no requirements-bound realization catalog/provisioner "
                "exists for "
                + ", ".join(required_categories)
                + "; no arbitrary base box may be treated as the SUT"
            )
        raise WindowsMaterializationError(
            "materialization is blocked: no per-host requirements-bound unattended renderer "
            "binds identities and runtime secrets to the selected image"
        )

    @staticmethod
    def _resolve_vagrant_binary() -> str:
        """Resolve the executable once before any future provider subprocess call."""
        discovered = shutil.which("vagrant")
        if discovered is None:
            raise WindowsMaterializationError("vagrant is not on PATH")
        resolved = Path(discovered).expanduser().resolve()
        if not resolved.is_absolute():
            raise WindowsMaterializationError("resolved vagrant binary is not absolute")
        return str(resolved)

    @staticmethod
    def _runtime_environment(
        *,
        plan: WindowsVagrantPlan,
        box_file: Path,
        supplied: Mapping[str, str] | None,
        run_dir: Path,
    ) -> dict[str, str]:
        source_environment = os.environ if supplied is None else supplied
        environment = {
            name: value
            for name in _SAFE_VAGRANT_ENVIRONMENT_VARIABLES
            if (value := source_environment.get(name, ""))
        }
        isolated_home = run_dir / ".home"
        isolated_vagrant_home = run_dir / ".vagrant-home"
        isolated_home.mkdir(mode=0o700)
        isolated_vagrant_home.mkdir(mode=0o700)
        environment["HOME"] = str(isolated_home)
        environment["VAGRANT_HOME"] = str(isolated_vagrant_home)
        environment[plan.runtime_box_environment_variable] = str(box_file)
        environment["VAGRANT_DEFAULT_PROVIDER"] = plan.provider.value
        return environment


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1_048_576), b""):
            digest.update(block)
    return digest.hexdigest()


def _failure_receipt(
    command: list[str], error: subprocess.TimeoutExpired | OSError | KeyboardInterrupt
) -> VagrantCommandReceipt:
    """Record only categorical process state; streams may contain runtime secrets."""
    return VagrantCommandReceipt(
        command=command,
        returncode=None,
        stdout_present=False,
        stderr_present=False,
        error_kind=type(error).__name__,
    )


def _write_deterministic_or_replace(path: Path, content: str) -> None:
    """Atomically update a run-local receipt; it is not a source plan."""
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=path.parent, prefix=f".{path.name}.", delete=False
    ) as handle:
        handle.write(content)
        temporary = Path(handle.name)
    temporary.chmod(0o600)
    temporary.replace(path)
