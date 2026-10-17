"""Admit one closed Step-2 proposal into non-executing campaign requirements.

This module is deliberately a narrow boundary.  It converts a verified STICKS
procedural-plan record and a *deterministically accepted* closed semantic
proposal into :class:`CampaignRequirements`.  It does not call a model, choose
an image, materialize a machine, execute a procedure, or turn a planned
environment into campaign-execution evidence.

The only variable values crossing the semantic boundary are the categorical
values defined by ``cti.semantic_concretizer``.  Host labels, network layout,
ports, account references, and evidence labels come from this versioned local
policy; raw STIX prose and model output never flow into the requirements DTO.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ..cti.semantic_concretizer import (
    ConcretizationInput,
    ConcretizationResult,
    CredentialRequirement,
    CredentialRequirementField,
    Decision,
    NetworkExposure,
    NetworkExposureField,
    PlatformField,
    PrivilegeField,
    PrivilegeRequirement as SemanticPrivilegeRequirement,
    SemanticConcretizer,
    SemanticFieldKind,
    SoftwareRole,
    SoftwareRoleField,
    build_prompt,
    response_schema_sha256,
)
from ..cti.semantic_provenance import SemanticEvidenceStore
from .campaign_requirements import (
    CampaignRequirements,
    HostRequirement,
    IdentityModel,
    IdentityRequirement,
    NetworkExposureRequirement,
    NetworkSegmentRequirement,
    PlatformFamily,
    PrivilegeLevel,
    PrivilegeRequirement,
    ProcedureRequirement,
    ProvenanceKind,
    RequirementProvenance,
    UnresolvedRequirement,
)
from .procedural_plan import ProceduralPlanInput, ProcedureStepInput


_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_PLAN_SCHEMA_VERSION = "autosut.requirements-admission/v1"
_REQUIREMENTS_POLICY = {
    "policy_id": "minimal-isolated-requirements",
    "schema_version": "v1",
    "identity_model": "workgroup",
    "network": {"cidr": "192.168.56.0/24", "segment_id": "labnet"},
    "host": {"host_id": "sut-1", "hostname": "sut-1", "ipv4_address": "192.168.56.20"},
    "host_role_catalog": {
        "default": "generic-target",
        "web_service": "web-service",
        "file_service": "file-service",
        "database_service": "database-service",
        "directory_service": "directory-service",
        "user_workstation": "user-workstation",
        "mail_service": "mail-service",
    },
    "service_catalog": {
        "web_service": {"service_name": "web-service", "port": 8443},
        "file_service": {"service_name": "file-service", "port": 9443},
        "database_service": {"service_name": "database-service", "port": 15432},
        "directory_service": {"service_name": "directory-service", "port": 16389},
        "mail_service": {"service_name": "mail-service", "port": 1025},
    },
    "identity_catalog": {
        "valid_account": {
            "principal_id": "sut-user",
            "username": "autosutuser",
            "privilege": "user",
            "runtime_secret_environment_variable": "AUTOSUT_SUT_USER_PASSWORD",
        },
        "privileged_account": {
            "principal_id": "sut-admin",
            "username": "autosutadmin",
            "privilege": "local_administrator",
            "runtime_secret_environment_variable": "AUTOSUT_SUT_ADMIN_PASSWORD",
        },
    },
    "execution_domain_catalog": {
        "target": "target",
        "boundary": "network",
        "network": "network",
        "controller": "controller",
    },
    "evidence_predicates": ["environment-requirement-satisfied"],
}
_POLICY_SHA256 = hashlib.sha256(
    json.dumps(_REQUIREMENTS_POLICY, sort_keys=True, separators=(",", ":")).encode("utf-8")
).hexdigest()
_STEP_PLATFORM_MAP = {
    "Linux": PlatformFamily.LINUX,
    "Windows": PlatformFamily.WINDOWS,
    "macOS": PlatformFamily.MACOS,
}
_HOST_ROLE_BY_SOFTWARE_ROLE = {
    SoftwareRole.WEB_SERVICE: _REQUIREMENTS_POLICY["host_role_catalog"]["web_service"],
    SoftwareRole.FILE_SERVICE: _REQUIREMENTS_POLICY["host_role_catalog"]["file_service"],
    SoftwareRole.DATABASE_SERVICE: _REQUIREMENTS_POLICY["host_role_catalog"]["database_service"],
    SoftwareRole.DIRECTORY_SERVICE: _REQUIREMENTS_POLICY["host_role_catalog"]["directory_service"],
    SoftwareRole.USER_WORKSTATION: _REQUIREMENTS_POLICY["host_role_catalog"]["user_workstation"],
    SoftwareRole.MAIL_SERVICE: _REQUIREMENTS_POLICY["host_role_catalog"]["mail_service"],
}
_SERVICE_CATALOG = {
    SoftwareRole.WEB_SERVICE: (
        _REQUIREMENTS_POLICY["service_catalog"]["web_service"]["service_name"],
        _REQUIREMENTS_POLICY["service_catalog"]["web_service"]["port"],
    ),
    SoftwareRole.FILE_SERVICE: (
        _REQUIREMENTS_POLICY["service_catalog"]["file_service"]["service_name"],
        _REQUIREMENTS_POLICY["service_catalog"]["file_service"]["port"],
    ),
    SoftwareRole.DATABASE_SERVICE: (
        _REQUIREMENTS_POLICY["service_catalog"]["database_service"]["service_name"],
        _REQUIREMENTS_POLICY["service_catalog"]["database_service"]["port"],
    ),
    SoftwareRole.DIRECTORY_SERVICE: (
        _REQUIREMENTS_POLICY["service_catalog"]["directory_service"]["service_name"],
        _REQUIREMENTS_POLICY["service_catalog"]["directory_service"]["port"],
    ),
    SoftwareRole.MAIL_SERVICE: (
        _REQUIREMENTS_POLICY["service_catalog"]["mail_service"]["service_name"],
        _REQUIREMENTS_POLICY["service_catalog"]["mail_service"]["port"],
    ),
}


class RequirementsAdmissionError(ValueError):
    """Raised when a semantic proposal cannot safely inform requirements."""


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RequirementsAdmissionReceipt(_StrictModel):
    """Hash-bound record of a planning-only admission decision."""

    schema_version: Literal["autosut.requirements-admission/v1"] = _PLAN_SCHEMA_VERSION
    decision: Literal["admitted_for_planning_only"] = "admitted_for_planning_only"
    procedural_plan_sha256: str
    semantic_input_sha256: str
    semantic_admission_sha256: str
    semantic_evidence_manifest_sha256: str | None = None
    semantic_evidence_verified: bool = False
    requirements_sha256: str
    is_execution_evidence: Literal[False] = False
    qualification_blockers: list[str] = Field(min_length=1)

    @model_validator(mode="after")
    def _validate_digests_and_evidence_state(self) -> "RequirementsAdmissionReceipt":
        for digest in (
            self.procedural_plan_sha256,
            self.semantic_input_sha256,
            self.semantic_admission_sha256,
            self.requirements_sha256,
        ):
            if not _SHA256_PATTERN.fullmatch(digest):
                raise ValueError("requirements-admission receipt contains an invalid digest")
        if self.semantic_evidence_manifest_sha256 is not None and not _SHA256_PATTERN.fullmatch(
            self.semantic_evidence_manifest_sha256
        ):
            raise ValueError("requirements-admission receipt has an invalid semantic manifest digest")
        if self.semantic_evidence_verified != (self.semantic_evidence_manifest_sha256 is not None):
            raise ValueError("receipt semantic evidence state does not match manifest presence")
        return self


class AdmittedCampaignRequirements(_StrictModel):
    """Requirements plus the decision receipt required to inspect their origin."""

    requirements: CampaignRequirements
    receipt: RequirementsAdmissionReceipt

    @model_validator(mode="after")
    def _bind_receipt_to_requirements(self) -> "AdmittedCampaignRequirements":
        if self.receipt.requirements_sha256 != self.requirements.content_sha256():
            raise ValueError("requirements-admission receipt does not bind its requirements")
        return self


def compile_admitted_campaign_requirements(
    procedural_plan: ProceduralPlanInput,
    semantic_input: ConcretizationInput,
    admission: ConcretizationResult,
    *,
    semantic_evidence_manifest_sha256: str | None = None,
) -> AdmittedCampaignRequirements:
    """Compile one accepted proposal into a partial, planning-only requirements DTO.

    A campaign may contain more than one environment-relevant procedure.  This
    focused bridge admits exactly one Step-2 proposal and records every other
    relevant procedure as materialization-blocking unresolved work.  That makes
    it useful for a vertical slice without misrepresenting a partial resolution
    as a complete campaign reconstruction.  Call
    :func:`compile_from_verified_semantic_evidence` for persisted evidence;
    this lower-level form adds a materialization blocker when no sealed run was
    replay-verified.
    """
    if semantic_evidence_manifest_sha256 is not None and not _SHA256_PATTERN.fullmatch(
        semantic_evidence_manifest_sha256
    ):
        raise RequirementsAdmissionError("semantic evidence manifest digest is invalid")
    plan_sha256 = _verify_procedural_plan(procedural_plan)
    step = _verify_admission_binding(procedural_plan, semantic_input, admission)
    proposal = admission.proposal
    assert proposal is not None

    fields = {field.kind: field for field in proposal.fields}
    selected_platform = _select_platform(step, semantic_input, fields)
    identity, privilege = _build_identity_and_privilege(
        fields,
        selected_platform,
        technique_id=step.technique_id,
    )
    software_role = _software_role(fields)
    network_exposures = _build_network_exposures(fields, software_role)

    stix_provenance = RequirementProvenance(
        provenance_id="stix-plan",
        kind=ProvenanceKind.STIX,
        source_sha256=plan_sha256,
        locator=f"procedural-plan/{procedural_plan.campaign_id}/{step.technique_id}",
        note="verified procedural-plan provenance",
    )
    semantic_provenance = RequirementProvenance(
        provenance_id="semantic-admission",
        kind=ProvenanceKind.SEMANTIC_ENRICHMENT,
        source_sha256=semantic_evidence_manifest_sha256
        or _semantic_admission_sha256(semantic_input, admission),
        locator=(
            f"sealed-semantic-evidence/{semantic_evidence_manifest_sha256}"
            if semantic_evidence_manifest_sha256 is not None
            else f"semantic-admission/{semantic_input.input_sha256}"
        ),
        note="accepted closed semantic proposal; planning input only",
    )
    policy_provenance = RequirementProvenance(
        provenance_id="requirements-policy",
        kind=ProvenanceKind.DEPLOYMENT_CATALOG,
        source_sha256=_POLICY_SHA256,
        locator="minimal-isolated-requirements/v1",
        note="fixed isolated planning catalog",
    )
    provenance_refs = [
        stix_provenance.provenance_id,
        semantic_provenance.provenance_id,
        policy_provenance.provenance_id,
    ]

    host = HostRequirement(
        host_id=_REQUIREMENTS_POLICY["host"]["host_id"],
        hostname=_REQUIREMENTS_POLICY["host"]["hostname"],
        role=_host_role(software_role),
        platform=selected_platform,
        network_segment_id=_REQUIREMENTS_POLICY["network"]["segment_id"],
        ipv4_address=_REQUIREMENTS_POLICY["host"]["ipv4_address"],
        memory_mib=4096,
        cpus=2,
        provenance_refs=provenance_refs,
    )
    procedure = ProcedureRequirement(
        technique_id=step.technique_id,
        execution_domain=_execution_domain(step),
        required_host_ids=[host.host_id],
        required_principal_ids=[identity.principal_id] if identity is not None else [],
        evidence_predicates=list(_REQUIREMENTS_POLICY["evidence_predicates"]),
        provenance_refs=provenance_refs,
    )
    requirements = CampaignRequirements(
        campaign_id=procedural_plan.campaign_id,
        source_bundle_sha256=procedural_plan.source.bundle_sha256,
        target_platforms=[selected_platform],
        identity_model=IdentityModel.WORKGROUP,
        network_segments=[
            NetworkSegmentRequirement(
                segment_id=_REQUIREMENTS_POLICY["network"]["segment_id"],
                cidr=_REQUIREMENTS_POLICY["network"]["cidr"],
                provenance_refs=[policy_provenance.provenance_id],
            )
        ],
        hosts=[host],
        identities=[identity] if identity is not None else [],
        network_exposures=network_exposures,
        privilege_requirements=[privilege] if privilege is not None else [],
        procedure_requirements=[procedure],
        provenance=[stix_provenance, semantic_provenance, policy_provenance],
        unresolved_items=_unresolved_items(
            procedural_plan,
            step,
            software_role,
            admission,
            semantic_evidence_verified=semantic_evidence_manifest_sha256 is not None,
        ),
    )
    receipt = RequirementsAdmissionReceipt(
        procedural_plan_sha256=plan_sha256,
        semantic_input_sha256=semantic_input.input_sha256,
        semantic_admission_sha256=_semantic_admission_sha256(semantic_input, admission),
        semantic_evidence_manifest_sha256=semantic_evidence_manifest_sha256,
        semantic_evidence_verified=semantic_evidence_manifest_sha256 is not None,
        requirements_sha256=requirements.content_sha256(),
        qualification_blockers=_receipt_blockers(
            admission,
            semantic_evidence_verified=semantic_evidence_manifest_sha256 is not None,
        ),
    )
    return AdmittedCampaignRequirements(requirements=requirements, receipt=receipt)


def compile_from_verified_semantic_evidence(
    procedural_plan: ProceduralPlanInput,
    evidence_store: SemanticEvidenceStore,
    run_directory: Path,
    *,
    source_bundle_path: Path,
) -> AdmittedCampaignRequirements:
    """Compile requirements only after replay-verifying a sealed semantic run.

    This is the preferred consumer entry point.  Verification binds the stored
    input, raw response, parsed proposal, deterministic admission, and pinned
    STIX bundle before any categorical value is allowed to influence planning.
    It still produces planning input only, never execution or claim evidence.
    """
    semantic_input, admission, _ = evidence_store.load_verified_admission(
        run_directory,
        source_bundle_path=source_bundle_path,
    )
    manifest_path = run_directory.resolve() / "manifest.json"
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise RequirementsAdmissionError("verified semantic evidence manifest is missing or unsafe")
    return compile_admitted_campaign_requirements(
        procedural_plan,
        semantic_input,
        admission,
        semantic_evidence_manifest_sha256=_sha256_bytes(manifest_path.read_bytes()),
    )


def _verify_procedural_plan(plan: ProceduralPlanInput) -> str:
    """Reject a plan whose declared content hash or internal identifiers drifted."""
    payload = plan.model_dump(mode="json", exclude={"content_sha256"})
    actual_sha256 = _sha256_json(payload)
    if plan.content_sha256 != actual_sha256:
        raise RequirementsAdmissionError("procedural plan content_sha256 does not match its payload")
    if not _SHA256_PATTERN.fullmatch(plan.source.bundle_sha256):
        raise RequirementsAdmissionError("procedural plan source bundle digest is invalid")
    if plan.source.campaign_external_id != plan.campaign_id:
        raise RequirementsAdmissionError("procedural plan campaign source does not match campaign_id")
    technique_ids = [step.technique_id for step in plan.steps]
    if len(technique_ids) != len(set(technique_ids)):
        raise RequirementsAdmissionError("procedural plan has duplicate technique identifiers")
    if any(not step.technique_stix_id or not step.relationship_ids for step in plan.steps):
        raise RequirementsAdmissionError("procedural plan lacks strict step provenance")
    return actual_sha256


def _verify_admission_binding(
    plan: ProceduralPlanInput,
    semantic_input: ConcretizationInput,
    admission: ConcretizationResult,
) -> ProcedureStepInput:
    """Re-evaluate admission and bind its sources to exactly one plan step."""
    if admission.decision is not Decision.ACCEPTED or admission.proposal is None:
        raise RequirementsAdmissionError("only an accepted semantic proposal may inform requirements")
    if admission.rejected_reasons:
        raise RequirementsAdmissionError("accepted semantic admission cannot carry rejection reasons")
    if semantic_input.input_sha256 != _sha256_json(semantic_input.prompt_payload()):
        raise RequirementsAdmissionError("semantic bounded input digest does not match its payload")
    proposal = admission.proposal
    if admission.input_sha256 != semantic_input.input_sha256:
        raise RequirementsAdmissionError("semantic admission input digest differs from bounded input")
    if proposal.provider.input_sha256 != semantic_input.input_sha256:
        raise RequirementsAdmissionError("semantic proposal provider input digest differs")
    if proposal.provider.prompt_sha256 != _sha256_text(build_prompt(semantic_input)):
        raise RequirementsAdmissionError("semantic proposal prompt digest differs from bounded input")
    if proposal.provider.response_schema_sha256 != response_schema_sha256():
        raise RequirementsAdmissionError("semantic proposal response schema digest differs")
    if proposal.provider.requested_model_id != proposal.provider.reported_model_id:
        raise RequirementsAdmissionError("semantic proposal reported a different model identifier")
    replayed = SemanticConcretizer().concretize(semantic_input, proposal)
    if replayed.decision is not Decision.ACCEPTED:
        raise RequirementsAdmissionError("semantic proposal no longer passes deterministic admission")
    if replayed.proposal != proposal:
        raise RequirementsAdmissionError("semantic admission proposal differs from deterministic replay")
    missing_blockers = set(replayed.qualification_blockers) - set(admission.qualification_blockers)
    if missing_blockers:
        raise RequirementsAdmissionError(
            "semantic admission omits deterministic qualification blockers: "
            + ", ".join(sorted(missing_blockers))
        )
    if semantic_input.campaign_id != plan.campaign_id:
        raise RequirementsAdmissionError("semantic input campaign_id differs from procedural plan")
    if semantic_input.source_bundle_sha256 != plan.source.bundle_sha256:
        raise RequirementsAdmissionError("semantic input source bundle digest differs from procedural plan")
    if semantic_input.source_bundle_object_count != plan.source.object_count:
        raise RequirementsAdmissionError("semantic input source object count differs from procedural plan")
    if proposal.campaign_id != plan.campaign_id:
        raise RequirementsAdmissionError("semantic proposal campaign_id differs from procedural plan")
    matching_steps = [step for step in plan.steps if step.technique_id == semantic_input.technique_id]
    if len(matching_steps) != 1 or proposal.technique_id != semantic_input.technique_id:
        raise RequirementsAdmissionError("semantic proposal technique_id is not uniquely present in plan")
    step = matching_steps[0]
    if step.execution_domain == "attacker":
        raise RequirementsAdmissionError("attacker-domain steps do not define a target SUT requirement")
    allowed_source_ids = {step.technique_stix_id, *step.relationship_ids}
    anchor_source_ids = {anchor.source_object_id for anchor in semantic_input.evidence}
    if not anchor_source_ids.issubset(allowed_source_ids):
        raise RequirementsAdmissionError(
            "semantic evidence anchors are not bound to the selected procedural-plan step"
        )
    return step


def _select_platform(
    step: ProcedureStepInput,
    semantic_input: ConcretizationInput,
    fields: dict[SemanticFieldKind, object],
) -> PlatformFamily:
    """Use an admitted platform or one unambiguous plan/input intersection."""
    step_platforms = {
        platform
        for platform_name in step.platforms
        if (platform := _STEP_PLATFORM_MAP.get(platform_name)) is not None
    }
    candidate_platforms = step_platforms.intersection(
        {PlatformFamily(platform.value) for platform in semantic_input.allowed_platforms}
    )
    platform_field = fields.get(SemanticFieldKind.PLATFORM)
    if isinstance(platform_field, PlatformField):
        selected = PlatformFamily(platform_field.value.value)
        if selected not in candidate_platforms:
            raise RequirementsAdmissionError(
                "admitted semantic platform is not supported by the selected procedural-plan step"
            )
        return selected
    if len(candidate_platforms) != 1:
        raise RequirementsAdmissionError(
            "requirements bridge needs one admitted platform or one unambiguous plan/input platform"
        )
    return next(iter(candidate_platforms))


def _build_identity_and_privilege(
    fields: dict[SemanticFieldKind, object],
    platform: PlatformFamily,
    *,
    technique_id: str,
) -> tuple[IdentityRequirement | None, PrivilegeRequirement | None]:
    credential_field = fields.get(SemanticFieldKind.CREDENTIAL_REQUIREMENT)
    if credential_field is None:
        credential = CredentialRequirement.NONE
    elif isinstance(credential_field, CredentialRequirementField):
        credential = credential_field.value
    else:
        raise RequirementsAdmissionError("semantic credential field has an invalid closed type")
    privilege_field = fields.get(SemanticFieldKind.PRIVILEGE)
    if privilege_field is not None and not isinstance(privilege_field, PrivilegeField):
        raise RequirementsAdmissionError("semantic privilege field has an invalid closed type")

    principal: IdentityRequirement | None = None
    if credential is CredentialRequirement.VALID_ACCOUNT:
        identity_policy = _REQUIREMENTS_POLICY["identity_catalog"]["valid_account"]
        principal = IdentityRequirement(
            principal_id=identity_policy["principal_id"],
            host_id=_REQUIREMENTS_POLICY["host"]["host_id"],
            username=identity_policy["username"],
            privilege=PrivilegeLevel(identity_policy["privilege"]),
            runtime_secret_environment_variable=identity_policy[
                "runtime_secret_environment_variable"
            ],
            purpose="controlled-lab-account",
            provenance_refs=["semantic-admission", "requirements-policy"],
        )
    elif credential is CredentialRequirement.PRIVILEGED_ACCOUNT:
        identity_policy = _REQUIREMENTS_POLICY["identity_catalog"]["privileged_account"]
        principal = IdentityRequirement(
            principal_id=identity_policy["principal_id"],
            host_id=_REQUIREMENTS_POLICY["host"]["host_id"],
            username=identity_policy["username"],
            privilege=PrivilegeLevel(identity_policy["privilege"]),
            runtime_secret_environment_variable=identity_policy[
                "runtime_secret_environment_variable"
            ],
            purpose="controlled-lab-account",
            provenance_refs=["semantic-admission", "requirements-policy"],
        )

    if privilege_field is None:
        return principal, None
    semantic_privilege = privilege_field.value
    if semantic_privilege is SemanticPrivilegeRequirement.ROOT:
        raise RequirementsAdmissionError(
            "semantic root privilege is not representable by campaign-requirements/v1"
        )
    if semantic_privilege in {
        SemanticPrivilegeRequirement.UNPRIVILEGED,
        SemanticPrivilegeRequirement.USER,
    }:
        if semantic_privilege is SemanticPrivilegeRequirement.USER and principal is None:
            raise RequirementsAdmissionError("semantic user privilege requires a valid-account category")
        return principal, (
            PrivilegeRequirement(
                technique_id=technique_id,
                host_id=_REQUIREMENTS_POLICY["host"]["host_id"],
                principal_id=principal.principal_id,
                minimum_privilege=PrivilegeLevel.USER,
                provenance_refs=["semantic-admission", "requirements-policy"],
            )
            if semantic_privilege is SemanticPrivilegeRequirement.USER and principal is not None
            else None
        )
    if semantic_privilege is SemanticPrivilegeRequirement.ADMINISTRATOR:
        if credential is not CredentialRequirement.PRIVILEGED_ACCOUNT or principal is None:
            raise RequirementsAdmissionError(
                "semantic administrator privilege requires a privileged-account category"
            )
        return principal, PrivilegeRequirement(
            technique_id=technique_id,
            host_id=_REQUIREMENTS_POLICY["host"]["host_id"],
            principal_id=principal.principal_id,
            minimum_privilege=PrivilegeLevel.LOCAL_ADMINISTRATOR,
            provenance_refs=["semantic-admission", "requirements-policy"],
        )
    if semantic_privilege is SemanticPrivilegeRequirement.SYSTEM:
        if platform is not PlatformFamily.WINDOWS:
            raise RequirementsAdmissionError("semantic system privilege requires a Windows target")
        if credential is not CredentialRequirement.PRIVILEGED_ACCOUNT or principal is None:
            raise RequirementsAdmissionError(
                "semantic system privilege requires a privileged-account category"
            )
        return principal, PrivilegeRequirement(
            technique_id=technique_id,
            host_id=_REQUIREMENTS_POLICY["host"]["host_id"],
            principal_id=principal.principal_id,
            minimum_privilege=PrivilegeLevel.SYSTEM,
            provenance_refs=["semantic-admission", "requirements-policy"],
        )
    raise RequirementsAdmissionError("semantic privilege is not supported by the requirements policy")


def _software_role(fields: dict[SemanticFieldKind, object]) -> SoftwareRole | None:
    field = fields.get(SemanticFieldKind.SOFTWARE_ROLE)
    if field is None:
        return None
    if not isinstance(field, SoftwareRoleField):
        raise RequirementsAdmissionError("semantic software role field has an invalid closed type")
    return field.value


def _build_network_exposures(
    fields: dict[SemanticFieldKind, object],
    software_role: SoftwareRole | None,
) -> list[NetworkExposureRequirement]:
    field = fields.get(SemanticFieldKind.NETWORK_EXPOSURE)
    if field is None:
        return []
    if not isinstance(field, NetworkExposureField):
        raise RequirementsAdmissionError("semantic network exposure field has an invalid closed type")
    exposure = field.value
    if exposure is NetworkExposure.ISOLATED:
        return []
    if exposure not in {NetworkExposure.LAB_INTERNAL, NetworkExposure.CONTROLLED_INGRESS}:
        raise RequirementsAdmissionError("semantic network exposure is not supported by the policy")
    if software_role not in _SERVICE_CATALOG:
        raise RequirementsAdmissionError(
            "network exposure requires an admitted service role with a fixed catalog entry"
        )
    service_name, port = _SERVICE_CATALOG[software_role]
    return [
        NetworkExposureRequirement(
            host_id=_REQUIREMENTS_POLICY["host"]["host_id"],
            service_name=service_name,
            port=port,
            protocol="tcp",
            scope="private_lab",
            provenance_refs=["semantic-admission", "requirements-policy"],
        )
    ]


def _host_role(software_role: SoftwareRole | None) -> str:
    return _HOST_ROLE_BY_SOFTWARE_ROLE.get(
        software_role,
        _REQUIREMENTS_POLICY["host_role_catalog"]["default"],
    )


def _execution_domain(step: ProcedureStepInput) -> str:
    domain = _REQUIREMENTS_POLICY["execution_domain_catalog"].get(step.execution_domain)
    if not isinstance(domain, str):
        raise RequirementsAdmissionError("procedural-plan execution domain is unsupported")
    return domain


def _unresolved_items(
    plan: ProceduralPlanInput,
    admitted_step: ProcedureStepInput,
    software_role: SoftwareRole | None,
    admission: ConcretizationResult,
    *,
    semantic_evidence_verified: bool,
) -> list[UnresolvedRequirement]:
    """Keep incomplete campaign reconstruction explicit and materialization-blocking."""
    items = [
        UnresolvedRequirement(
            item_id="semantic-not-execution-evidence",
            category="evidence-boundary",
            description="admitted semantic proposal is planning input and not execution evidence",
            blocks_materialization=False,
            provenance_refs=["semantic-admission"],
        )
    ]
    if not semantic_evidence_verified:
        items.append(
            UnresolvedRequirement(
                item_id="semantic-evidence-verification",
                category="provenance-verification",
                description="semantic admission was not replay-verified from sealed evidence",
                blocks_materialization=True,
                provenance_refs=["semantic-admission"],
            )
        )
    qualification_blockers = [
        blocker
        for blocker in admission.qualification_blockers
        if blocker != "semantic proposal is not campaign execution evidence"
    ]
    if qualification_blockers:
        items.append(
            UnresolvedRequirement(
                item_id="semantic-qualification",
                category="semantic-qualification",
                description="semantic protocol or model qualification remains incomplete",
                blocks_materialization=True,
                provenance_refs=["semantic-admission"],
            )
        )
    if software_role is not None:
        items.append(
            UnresolvedRequirement(
                item_id="software-catalog-binding",
                category="deployment-catalog",
                description="admitted software role still needs a separately verified deployment binding",
                blocks_materialization=True,
                provenance_refs=["semantic-admission", "requirements-policy"],
            )
        )
    for step in plan.steps:
        if step.technique_id == admitted_step.technique_id or step.execution_domain == "attacker":
            continue
        technique_suffix = step.technique_id.lower().replace(".", "-")
        items.append(
            UnresolvedRequirement(
                item_id=f"unresolved-{technique_suffix}",
                category="step-admission",
                description=f"no accepted semantic admission for technique {step.technique_id}",
                blocks_materialization=True,
                provenance_refs=["stix-plan"],
            )
        )
    return items


def _receipt_blockers(
    admission: ConcretizationResult,
    *,
    semantic_evidence_verified: bool,
) -> list[str]:
    blockers = [
        "admitted requirements are not campaign execution evidence",
        "admitted requirements do not qualify a provider or procedure execution",
        *admission.qualification_blockers,
    ]
    if not semantic_evidence_verified:
        blockers.append("semantic admission was not replay-verified from sealed evidence")
    return _deduplicate(blockers)


def _semantic_admission_sha256(
    semantic_input: ConcretizationInput,
    admission: ConcretizationResult,
) -> str:
    return _sha256_json(
        {
            "semantic_input": semantic_input.model_dump(mode="json"),
            "admission": admission.model_dump(mode="json"),
        }
    )


def _sha256_json(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _deduplicate(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))
