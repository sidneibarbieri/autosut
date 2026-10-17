"""Replay an integrity-checked prepared pair on its synthesized SUT profile."""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path
from typing import Literal

from infrastructure.revision import current_revision
from orchestrator.campaign_state import (
    CampaignStateLedger,
    use_verified_contract,
    validate_ledger,
)
from orchestrator.injector import rebind_ray_after_isolation
from orchestrator.models import Realization
from orchestrator.orchestrator import CampaignOrchestrator
from pydantic import BaseModel, ConfigDict, Field

from .blueprint_materialization import sut_profile_from_blueprint
from .bounded_templates import bounded_executor
from .campaign_pair import PairPreparation, _declared_services
from .executable_contract import ExecutableCampaignContract
from .execution_admission import resolve_template_adapter, validate_template_adapters
from .replay_integrity import begin_replay, seal_replay_evidence
from .replay_network import ReplayNetwork
from .sut_blueprint import SUTBlueprint


class JointReplayReceipt(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["autosut-joint-replay/v1", "autosut-joint-replay/v2"] = "autosut-joint-replay/v1"
    run_id: str | None = Field(default=None, pattern=r"^[a-f0-9]{32}$")
    evidence_manifest_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    campaign_id: str
    source_campaign_id: str
    contract_sha256: str
    blueprint_sha256: str
    pair_manifest_sha256: str
    implementation_revision: str
    revision_stable: bool
    evidence_backed_steps: int
    total_steps: int
    marker_only_steps: int
    adapted_steps: int = 0
    inspired_steps: int = 0
    causal_violations: list[str] = Field(default_factory=list)
    teardown_clean: bool
    execution_complete: bool
    initial_fact_basis: str = "declared_preconditions"
    service_recipe_basis: str = "curated_campaign_injection"
    network_policy_enforcement: str = "internal_network_and_host_input_firewall"
    host_gateway_access: str = "not_certified"
    claim_scope: str = "Controlled adapted and inspired procedures on a synthesized host; historical APT fidelity is not certified."


def load_prepared_pair(pair_dir: Path) -> tuple[PairPreparation, SUTBlueprint, ExecutableCampaignContract]:
    pair = PairPreparation.model_validate_json((pair_dir / "pair.json").read_text())
    if pair.status != "prepared":
        raise ValueError(f"pair is blocked: {', '.join(pair.reasons)}")
    required = {"sut-blueprint.json", "executable-contract.json", "campaign-source.json", "campaign.json"}
    if not required.issubset(pair.files):
        raise ValueError("pair manifest omits required replay inputs")
    for relative, expected in pair.files.items():
        path = (pair_dir / relative).resolve()
        if not path.is_relative_to(pair_dir.resolve()):
            raise ValueError(f"pair input escapes its bundle: {relative}")
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError(f"pair input hash mismatch: {relative}")
    blueprint = SUTBlueprint.model_validate_json((pair_dir / "sut-blueprint.json").read_text())
    contract = ExecutableCampaignContract.model_validate_json((pair_dir / "executable-contract.json").read_text())
    expected_blueprint_hash = blueprint.content_sha256
    blueprint.finalize_hash()
    if blueprint.content_sha256 != expected_blueprint_hash:
        raise ValueError("blueprint content hash mismatch")
    contract.finalize_hash()
    if contract.content_sha256 != pair.contract_sha256:
        raise ValueError("prepared contract hash mismatch")
    if contract.campaign_id != pair.campaign_id or contract.source_campaign_id != blueprint.campaign_id:
        raise ValueError("prepared campaign and blueprint identities disagree")
    validate_template_adapters(contract)
    return pair, blueprint, contract


def replay_prepared_pair(pair_dir: Path, run_dir: Path) -> JointReplayReceipt:
    pair, blueprint, contract = load_prepared_pair(pair_dir)
    recipe_id = resolve_template_adapter(contract)
    campaign_path = Path(__file__).resolve().parents[2] / "campaigns" / f"{pair.campaign_id}.json"
    if campaign_path.exists() and campaign_path.read_bytes() != (pair_dir / "campaign-source.json").read_bytes():
        raise ValueError("installed campaign differs from prepared campaign")
    if run_dir.exists():
        raise ValueError("replay evidence directory already exists")
    profile = sut_profile_from_blueprint(blueprint)
    if profile.backend != "docker" or profile.is_multi_host:
        raise ValueError("prepared replay currently requires a single Docker target")
    run_dir.mkdir(parents=True)
    identity = begin_replay(run_dir, pair.campaign_id)
    inputs = run_dir / "prepared-inputs"
    inputs.mkdir()
    for relative in ["pair.json", *pair.files]:
        destination = inputs / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(pair_dir / relative, destination)
    project_root = Path(__file__).resolve().parents[2]
    revision = current_revision(project_root)
    services = _declared_services(json.loads((pair_dir / "campaign-source.json").read_text()))
    with ReplayNetwork() as network, use_verified_contract(inputs / "executable-contract.json", inputs / "campaign-source.json"):
        def isolate_and_rebind(target, attacker, evidence_dir, realization):
            target_ip = network.isolate(target, attacker, evidence_dir)
            if "ray-dashboard" in services and realization == Realization.real_cve:
                rebind_ray_after_isolation(target)
            return target_ip

        result = CampaignOrchestrator().run_campaign(
            pair.campaign_id, sut_override=profile, run_dir=run_dir,
            before_execution=isolate_and_rebind,
            execution_override=(bounded_executor(contract) if recipe_id in {"0.c0010", "0.c0026"} else None),
            reviewed_recipe_id=recipe_id,
        )
    ledger = CampaignStateLedger.model_validate_json((run_dir / "campaign_state.json").read_text())
    violations = validate_ledger(ledger)
    stable = current_revision(project_root) == revision
    if not stable:
        violations.append("implementation changed during replay")
    if ledger.executable_contract_sha256 != contract.content_sha256:
        violations.append("executed contract differs from prepared contract")
    gateway_access = json.loads((run_dir / "gateway-isolation.json").read_text())["host_gateway_access"]
    if gateway_access != "blocked_observed":
        violations.append("host gateway isolation was not observed")
    (run_dir / "materialized-profile.json").write_text(profile.model_dump_json(indent=2) + "\n")
    _, evidence_digest = seal_replay_evidence(run_dir, identity)
    receipt = JointReplayReceipt(
        schema_version="autosut-joint-replay/v2",
        run_id=identity.run_id,
        evidence_manifest_sha256=evidence_digest,
        campaign_id=pair.campaign_id,
        source_campaign_id=contract.source_campaign_id,
        contract_sha256=contract.content_sha256,
        blueprint_sha256=blueprint.content_sha256,
        pair_manifest_sha256=hashlib.sha256((pair_dir / "pair.json").read_bytes()).hexdigest(),
        implementation_revision=revision,
        revision_stable=stable,
        host_gateway_access=gateway_access,
        evidence_backed_steps=result.evidence_backed_successful,
        total_steps=result.total_techniques,
        marker_only_steps=result.marker_only_successful,
        adapted_steps=sum(step.executed_fidelity.value == "adapted" for step in result.techniques),
        inspired_steps=sum(step.executed_fidelity.value == "inspired" for step in result.techniques),
        service_recipe_basis=("reviewed_bounded_template" if recipe_id in {"0.c0010", "0.c0026"}
                              else "curated_campaign_injection"),
        causal_violations=violations,
        teardown_clean=result.teardown_clean,
        execution_complete=(result.total_techniques > 0 and result.evidence_backed_successful == result.total_techniques and result.teardown_clean and not violations),
    )
    (run_dir / "joint-replay-receipt.json").write_text(receipt.model_dump_json(indent=2) + "\n")
    return receipt
