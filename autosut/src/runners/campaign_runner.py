#!/usr/bin/env python3
"""
Unified Campaign Runner - Orchestrates Campaign -> SUT -> Executor -> Evidence pipeline.
"""

import argparse
import json
import os
import sys
import traceback
from datetime import datetime
from pathlib import Path
from typing import Any, Optional, Set

# Extend path before project imports so the src layout resolves correctly.
sys.path.insert(0, str(Path(__file__).parent.parent))

from executors.campaign_bootstrap import bootstrap_campaign_executors  # noqa: E402
from executors.executor_registry import (  # noqa: E402
    execute_technique,
    registry,
)
from executors.lab_transport import (  # noqa: E402
    detect_lab_infrastructure,
    resolve_target_vm_name,
)
from executors.models import (  # noqa: E402
    ArtifactMetadata,
    CampaignEvidence,
    ExecutionFidelity,
    ExecutionMode,
    FidelityAssessment,
    Platform,
    TechniqueEvidence,
)
from executors.registry_initializer import initialize_registry  # noqa: E402
from apply_sut_profile import apply_step_sut_delta  # noqa: E402
from loaders.campaign_loader import (  # noqa: E402
    list_campaigns,
    load_campaign,
    load_sut_profile,
    validate_campaign_sut_pair,
)

initialize_registry()

# Base capabilities always available on the host (no VM required)
BASE_CAPABILITIES = frozenset(
    {
        "resources:staging_directory",
        "resources:openssl_available",
        "network:ssh_available",
        "network:http_available",
    }
)
DEBUG_ENABLED = os.environ.get("STICKS_DEBUG") == "1"
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
HOME_DIR = Path.home()


class UnifiedCampaignRunner:
    """
    Orchestrates Campaign -> SUT -> Executor -> Evidence pipeline.

    Loads validated Campaign and SUTProfile, executes each step in order,
    tracks capabilities, and produces structured CampaignEvidence.
    """

    def __init__(self, campaign_id: str, output_dir: Optional[Path] = None):
        bootstrap_campaign_executors(campaign_id)

        self.campaign_id = campaign_id
        self.campaign = load_campaign(campaign_id)
        self.sut = load_sut_profile(self.campaign.sut_profile_id)

        self.accumulated_capabilities: Set[str] = set(BASE_CAPABILITIES)
        self._seed_sut_capabilities()
        self.output_dir = Path(output_dir) if output_dir else Path("results/evidence")
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _seed_sut_capabilities(self) -> None:
        """Derive initial capabilities from declared SUT profile weaknesses.

        When a SUT profile declares weak_credentials the lab substrate has
        pre-staged SSH access, so access:initial is operationally available
        before any technique step runs.  code_execution follows once shell
        access is established.
        """
        for host in self.sut.hosts.values():
            has_weak_creds = any(
                w.weakness_type in {"weak_credentials", "weak_ssh_password"}
                for w in host.deliberate_weaknesses
            )
            has_ssh = any(s.name == "ssh" for s in host.services)
            if has_weak_creds and has_ssh:
                self.accumulated_capabilities.add("access:initial")
                self.accumulated_capabilities.add("code_execution")

    def run(self) -> CampaignEvidence:
        """Execute full campaign and return structured evidence."""
        start_time = datetime.now()
        steps = self.campaign.steps
        total = len(steps)

        # Detect lab infrastructure before execution
        self._infrastructure_provider = detect_lab_infrastructure(self.sut.campaign_id)

        print(f"\n{'=' * 70}")
        print(f"  CAMPAIGN: {self.campaign.name}")
        print(f"  ID: {self.campaign.campaign_id}")
        print(f"  SUT: {self.sut.campaign_id}")
        print(f"  Steps: {total}")
        print(f"  Objective: {self.campaign.objective}")
        if self._infrastructure_provider:
            print(f"  Infrastructure: {self._infrastructure_provider}")
        else:
            print("  Infrastructure: local (no lab VMs detected)")
        print(f"{'=' * 70}\n")

        # Pre-flight validation
        error = validate_campaign_sut_pair(self.campaign.campaign_id)
        if error:
            print(f"[WARN] Campaign/SUT validation: {error}")

        evidence = CampaignEvidence(
            campaign_id=self.campaign.campaign_id,
            sut_profile_id=self.sut.campaign_id,
            start_time=start_time,
            infrastructure_provider=self._infrastructure_provider,
            sut_profile_path=str(
                Path("data/sut_profiles") / f"{self.sut.campaign_id}.yml"
            ),
        )

        for i, step in enumerate(steps, start=1):
            if DEBUG_ENABLED:
                print(
                    "[STATE BEFORE]",
                    f"step: {step.technique_id}",
                    f"capabilities: {sorted(self.accumulated_capabilities)}",
                )
            print(f"[{i}/{total}] {step.technique_id} — {step.technique_name}")
            print(
                f"         declared_mode={step.expected_mode.value}  "
                f"declared_fidelity={step.expected_fidelity.value}"
            )

            tech_evidence = self._execute_step(step)
            evidence.technique_results.append(tech_evidence)

            # Accumulate capabilities from successful executions
            if tech_evidence.status == "success":
                self.accumulated_capabilities.update(
                    tech_evidence.capabilities_produced
                )

            if DEBUG_ENABLED:
                print(
                    "[STATE AFTER]",
                    f"step: {step.technique_id}",
                    f"capabilities: {sorted(self.accumulated_capabilities)}",
                )

            status_icon = "OK" if tech_evidence.status == "success" else "FAIL"
            print(
                f"         [{status_icon}] rubric_fidelity={tech_evidence.fidelity.verified.value}"
            )
            print()

        evidence.end_time = datetime.now()
        evidence.compute_summary()

        # Populate ACM-aligned artifact metadata
        import platform as plat

        duration_ms = int(
            (evidence.end_time - evidence.start_time).total_seconds() * 1000
        )
        limitations = []
        if evidence.fidelity_distribution.get("inspired", 0) > 0:
            limitations.append(
                f"{evidence.fidelity_distribution['inspired']} techniques classified "
                f"as INSPIRED due to platform mismatch or mechanism divergence"
            )
        if plat.machine() == "arm64":
            limitations.append(
                "Executed on ARM64 — QEMU provider may ignore private network config"
            )

        evidence.artifact_metadata = ArtifactMetadata(
            automation_level="zero-touch",
            reproducibility_notes=(
                f"Run: python3 scripts/run_campaign.py --campaign {self.campaign.campaign_id}. "
                f"Requires: Python 3.10+, pydantic. "
                f"Full lab mode additionally requires: Vagrant, QEMU/VirtualBox/libvirt."
            ),
            known_limitations=limitations,
            platform_requirements=f"{plat.system()} {plat.machine()}, Python {plat.python_version()}",
            estimated_duration_minutes=max(1, duration_ms // 60000),
            rubric_consistent=True,
        )

        self._save_evidence(evidence)
        self._print_summary(evidence)

        return evidence

    def _execute_step(self, step) -> TechniqueEvidence:
        """Execute a single campaign step and return TechniqueEvidence."""
        start_time = datetime.now()
        sut_adjustments_applied: list[str] = []
        sut_adjustment_errors: list[str] = []

        if step.sut_delta and self._infrastructure_provider:
            delta_result = apply_step_sut_delta(
                campaign_id=self.campaign.campaign_id,
                delta=step.sut_delta.model_dump(by_alias=True),
                base_dir=PROJECT_ROOT,
                provider=self._infrastructure_provider,
            )
            sut_adjustments_applied = delta_result["applied"]
            sut_adjustment_errors = delta_result["errors"]
            if delta_result["notes"]:
                print(f"         sut_delta={delta_result['notes']}")
            if DEBUG_ENABLED and sut_adjustments_applied:
                print(
                    "[SUT DELTA]",
                    f"step: {step.technique_id}",
                    f"applied: {sut_adjustments_applied}",
                )
            if sut_adjustment_errors:
                return self._make_skipped_evidence(
                    step,
                    start_time,
                    "SUT delta application failed: "
                    + "; ".join(sut_adjustment_errors),
                    sut_adjustments_applied=sut_adjustments_applied,
                    sut_adjustment_errors=sut_adjustment_errors,
                )

        try:
            raw_evidence = execute_technique(
                technique_id=step.technique_id,
                available_capabilities=list(self.accumulated_capabilities),
                campaign_id=self.campaign.campaign_id,
                sut_profile_id=self.sut.campaign_id,
            )

            # Build FidelityAssessment from executor metadata + step expectation
            metadata = registry.get_metadata(step.technique_id)
            original_plat = (
                Platform.WINDOWS
                if metadata and metadata.original_platform == "windows"
                else Platform.ANY
            )
            exec_plat = Platform.LINUX

            fidelity = FidelityAssessment(
                declared=ExecutionFidelity(raw_evidence.execution_fidelity),
                verified=ExecutionFidelity(raw_evidence.execution_fidelity),
                justification=raw_evidence.fidelity_justification,
                platform_mismatch=(
                    original_plat != Platform.ANY and original_plat != exec_plat
                ),
                original_platform=original_plat,
                execution_platform=exec_plat,
            )

            # Determine execution host from evidence signals
            host = self._infer_host(raw_evidence)

            return TechniqueEvidence(
                technique_id=step.technique_id,
                technique_name=step.technique_name,
                status=raw_evidence.status,
                execution_mode=ExecutionMode(raw_evidence.execution_mode),
                fidelity=fidelity,
                artifacts=raw_evidence.artifacts_created,
                capabilities_consumed=raw_evidence.prerequisites_consumed,
                capabilities_produced=raw_evidence.capabilities_produced,
                stdout=raw_evidence.stdout[:2000],
                stderr=raw_evidence.stderr[:2000],
                start_time=start_time,
                end_time=datetime.now(),
                duration_ms=int((datetime.now() - start_time).total_seconds() * 1000),
                host=host,
                sut_adjustments_applied=sut_adjustments_applied,
                sut_adjustment_errors=sut_adjustment_errors,
            )

        except Exception as e:
            return self._make_skipped_evidence(
                step,
                start_time,
                str(e),
                sut_adjustments_applied=sut_adjustments_applied,
                sut_adjustment_errors=sut_adjustment_errors,
            )

    def _infer_host(self, raw_evidence) -> str:
        """Infer which host executed the technique from evidence signals."""
        if not self._infrastructure_provider:
            return ""

        # Artifacts referencing "target-vm:" or stdout mentioning "target VM"
        # indicate execution routed through lab transport
        vm_indicators = ("target VM", "target-vm:", "inside target VM")
        evidence_text = raw_evidence.stdout + " ".join(raw_evidence.artifacts_created)
        if any(indicator in evidence_text for indicator in vm_indicators):
            try:
                return resolve_target_vm_name(self.sut.campaign_id)
            except (FileNotFoundError, ValueError):
                return "target-vm"

        # real_controlled executors that use _try_run_on_target_vm may have
        # succeeded on VM without explicit markers; check execution mode
        if raw_evidence.execution_mode == "real_controlled":
            try:
                return resolve_target_vm_name(self.sut.campaign_id)
            except (FileNotFoundError, ValueError):
                return "localhost"

        return "localhost"

    def _make_skipped_evidence(
        self,
        step,
        start_time,
        reason: str,
        sut_adjustments_applied: Optional[list[str]] = None,
        sut_adjustment_errors: Optional[list[str]] = None,
    ) -> TechniqueEvidence:
        """Create evidence for a skipped/failed step."""
        return TechniqueEvidence(
            technique_id=step.technique_id,
            technique_name=step.technique_name,
            status="failed",
            execution_mode=step.expected_mode,
            fidelity=FidelityAssessment(
                declared=step.expected_fidelity,
                verified=step.expected_fidelity,
                justification=f"Execution failed: {reason}",
            ),
            stderr=reason,
            start_time=start_time,
            end_time=datetime.now(),
            sut_adjustments_applied=sut_adjustments_applied or [],
            sut_adjustment_errors=sut_adjustment_errors or [],
        )

    def _save_evidence(self, evidence: CampaignEvidence):
        """Save CampaignEvidence as JSON."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        evidence_dir = self.output_dir / f"{evidence.campaign_id}_{timestamp}"
        evidence_dir.mkdir(exist_ok=True)

        def sanitize_text(value: str) -> str:
            project_root = str(PROJECT_ROOT)
            home_dir = str(HOME_DIR)
            sanitized = value.replace(project_root + os.sep, "")
            sanitized = sanitized.replace(project_root, ".")
            sanitized = sanitized.replace(home_dir + os.sep, "~/")
            sanitized = sanitized.replace(home_dir, "~")
            return sanitized

        def sanitize_payload(value: Any) -> Any:
            if isinstance(value, str):
                return sanitize_text(value)
            if isinstance(value, list):
                return [sanitize_payload(item) for item in value]
            if isinstance(value, dict):
                return {
                    key: sanitize_payload(item)
                    for key, item in value.items()
                }
            return value

        # Summary (full Pydantic model serialized)
        summary_path = evidence_dir / "summary.json"
        with open(summary_path, "w", encoding="utf-8") as f:
            json.dump(
                sanitize_payload(evidence.model_dump(mode="json")),
                f,
                indent=2,
                ensure_ascii=False,
            )

        # Compact manifest for quick inspection
        manifest = {
            "campaign_id": evidence.campaign_id,
            "sut_profile_id": evidence.sut_profile_id,
            "timestamp": timestamp,
            "total_techniques": evidence.total_techniques,
            "successful": evidence.successful,
            "failed": evidence.failed,
            "skipped": evidence.skipped,
            "fidelity_distribution": evidence.fidelity_distribution,
            "evidence_directory": sanitize_text(str(evidence_dir)),
        }
        with open(evidence_dir / "manifest.json", "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2, ensure_ascii=False)

        # Per-technique detail files
        per_tech_dir = evidence_dir / "per_technique"
        per_tech_dir.mkdir(exist_ok=True)
        for te in evidence.technique_results:
            tech_file = per_tech_dir / f"{te.technique_id}.json"
            with open(tech_file, "w", encoding="utf-8") as f:
                json.dump(
                    sanitize_payload(te.model_dump(mode="json")),
                    f,
                    indent=2,
                    ensure_ascii=False,
                )

        print(f"\n[EVIDENCE] Saved to: {evidence_dir}")
        self.evidence_dir = evidence_dir

    def _print_summary(self, evidence: CampaignEvidence):
        """Print human-readable summary."""
        print(f"\n{'=' * 70}")
        print(f"  EXECUTION COMPLETE: {evidence.campaign_id}")
        print(f"{'=' * 70}")
        print(f"  Total:      {evidence.total_techniques}")
        print(f"  Successful: {evidence.successful}")
        print(f"  Failed:     {evidence.failed}")
        print(f"  Rubric:     {evidence.fidelity_distribution}")
        print()

        for te in evidence.technique_results:
            icon = "OK  " if te.status == "success" else "FAIL"
            print(
                f"  [{icon}] {te.technique_id:12s} "
                f"{te.fidelity.verified.value:10s} "
                f"{te.technique_name}"
            )

        print(f"{'=' * 70}\n")


def main():
    parser = argparse.ArgumentParser(
        description="AutoSUT unified campaign runner (formal model)",
    )
    parser.add_argument(
        "--campaign",
        help="Campaign ID (e.g., 0.c0011). Omit to list available.",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Execute ALL available campaigns sequentially",
    )
    parser.add_argument(
        "--output",
        default="release/evidence",
        help="Output evidence directory",
    )

    args = parser.parse_args()

    # List mode
    if not args.campaign and not args.all:
        print("Available campaigns:")
        for cid in list_campaigns():
            print(f"  - {cid}")
        return 0

    # Determine which campaigns to run
    campaign_ids = list_campaigns() if args.all else [args.campaign]

    exit_code = 0
    for cid in campaign_ids:
        try:
            runner = UnifiedCampaignRunner(campaign_id=cid, output_dir=args.output)
            evidence = runner.run()
            if evidence.failed > 0:
                exit_code = 1
        except FileNotFoundError as e:
            print(f"\n[ERROR] {e}")
            exit_code = 1
        except Exception as e:
            print(f"\n[ERROR] Campaign {cid} failed: {e}")
            traceback.print_exc()
            exit_code = 1

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
