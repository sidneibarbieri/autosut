"""Top-level orchestrator: walks one campaign tuple end-to-end."""

from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from . import attacker as attacker_mod
from . import catalog
from . import executor as executor_mod
from . import injector as injector_mod
from . import multi_host_executor as multi_host_mod
from .environment import DockerEnvironment  # noqa: F401 — legacy alias
from .environment_base import select_backend
from .host_fleet import HostFleet
from .models import RunResult, SUTProfile


PROJECT_ROOT = Path(__file__).resolve().parents[2]
EVIDENCE_ROOT = PROJECT_ROOT / "release" / "evidence"


def _docker_ip(container_name: str) -> str:
    proc = subprocess.run(
        ["docker", "inspect", "-f",
         "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
         container_name],
        capture_output=True, text=True, check=False,
    )
    return proc.stdout.strip()


def _provenance() -> dict:
    proc = subprocess.run(["git", "rev-parse", "HEAD"],
                          cwd=PROJECT_ROOT, capture_output=True, text=True)
    base = {
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "git_commit": proc.stdout.strip() if proc.returncode == 0 else "(no git)",
        "host_os": subprocess.run(["uname", "-sm"], capture_output=True, text=True).stdout.strip(),
    }
    # Snapshot live Caldera state into provenance. caldera_summary() returns
    # a dict with reachable=False if the C2 is down — we never swallow real
    # errors here; only network unreachability is encoded in the snapshot.
    from . import caldera_client
    base["caldera"] = caldera_client.caldera_summary()
    return base


class CampaignOrchestrator:
    def run_campaign(self, campaign_id: str,
                     fidelity_preference: str = "real_then_surrogate",
                     sut_override: SUTProfile | None = None,
                     run_label: str = "") -> RunResult:
        attacker_profile, resolved_sut, cve_set = catalog.resolve(
            campaign_id, fidelity_preference=fidelity_preference,
        )
        sut_profile = sut_override if sut_override is not None else resolved_sut
        run_id = (f"{campaign_id}{run_label}"
                  f"_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}")
        run_dir = EVIDENCE_ROOT / run_id
        run_dir.mkdir(parents=True, exist_ok=True)
        (run_dir / "provenance.json").write_text(
            json.dumps(_provenance(), indent=2), encoding="utf-8",
        )

        outcomes = []
        cve_fidelity = []
        provenance_cve_set = cve_set
        teardown_clean = False

        # Multi-host campaigns take a separate execution path: bring up a
        # private network with one container per declared host, dispatch
        # techniques to the host the JSON names. The single-host path
        # below is preserved unchanged for backwards compatibility.
        if sut_profile.is_multi_host:
            outcomes: list = []
            with HostFleet.bring_up(sut_profile, run_dir) as fleet:
                outcomes = multi_host_mod.execute_multi_host(
                    campaign_id, fleet, run_dir,
                )
                teardown_clean = True  # fleet.__exit__ handles teardown
            result = RunResult(
                campaign_id=campaign_id,
                run_id=run_id,
                attacker=attacker_profile,
                sut=sut_profile,
                cves_injected=cve_fidelity,
                techniques=outcomes,
                teardown_clean=teardown_clean,
                manifest_path=str(run_dir / "manifest.json"),
                summary_path=str(run_dir / "summary.json"),
                campaign_state_path=str(run_dir / "campaign_state.json"),
            )
            self._write_manifest(result, run_dir, cve_set)
            return result

        backend = select_backend(sut_profile)
        with backend.bring_up(sut_profile, run_dir) as target_env:
            # Apply declarative SUT composition for single-host campaigns
            # before any techniques run. Multi-host campaigns apply
            # composition inside HostFleet.bring_up; single-host now has
            # parity here.
            if sut_profile.composition is not None:
                from . import sut_composer
                sut_composer.apply_composition(
                    target_env, "target", sut_profile.composition, run_dir,
                )
            target_ip = _docker_ip(target_env.container_name)
            attacker_env = attacker_mod.bring_up_attacker(
                attacker_profile, run_dir, shared_network=None,
            )
            try:
                if cve_set:
                    cve_fidelity = injector_mod.inject(target_env, cve_set)
                    if (fidelity_preference == "real_then_surrogate"
                            and not all(rec.success for rec in cve_fidelity)):
                        # Real-cve attempt failed: record it, clean any
                        # stale state, retry once with the surrogate path.
                        cve_fidelity_first_attempt = cve_fidelity
                        target_env.run_shell(
                            "ray stop --force 2>&1 | head -3 || true",
                            log_name="sut/ray_stop_after_failure.log",
                        )
                        _, _, cve_set_surrogate = catalog.resolve(
                            campaign_id, fidelity_preference="surrogate",
                        )
                        provenance_cve_set = cve_set_surrogate
                        cve_fidelity = (cve_fidelity_first_attempt
                                        + injector_mod.inject(target_env, cve_set_surrogate))
                    proceed = any(rec.success for rec in cve_fidelity)
                    realization = (next(rec for rec in cve_fidelity if rec.success).realization
                                    if proceed else None)
                else:
                    # Campaign has no CVE evidence; the technique executor
                    # runs against the generic SUT.
                    proceed = True
                    from .models import Realization as _R
                    realization = _R.generic_primitive

                if proceed and realization is not None:
                    outcomes = executor_mod.execute(
                        campaign_id, target_env, attacker_env, target_ip, run_dir,
                        realization,
                    )
            finally:
                teardown_clean = attacker_mod.teardown_attacker(attacker_env)

        # target_env teardown happens via __exit__ above.
        result = RunResult(
            campaign_id=campaign_id,
            run_id=run_id,
            attacker=attacker_profile,
            sut=sut_profile,
            cves_injected=cve_fidelity,
            techniques=outcomes,
            teardown_clean=teardown_clean,
            manifest_path=str(run_dir / "manifest.json"),
            summary_path=str(run_dir / "summary.json"),
            campaign_state_path=str(run_dir / "campaign_state.json"),
        )
        self._write_manifest(result, run_dir, provenance_cve_set)
        return result

    def _write_manifest(self, result: RunResult, run_dir: Path,
                        cve_set: list | None = None) -> None:
        from .campaign_state import build_ledger

        ledger = build_ledger(result)
        (run_dir / "campaign_state.json").write_text(
            ledger.model_dump_json(indent=2), encoding="utf-8",
        )
        manifest_dict = result.model_dump(mode="json")
        # Persist paths relative to the run directory.  The returned RunResult
        # keeps absolute paths for in-process callers, but released evidence
        # must remain valid after a ZIP is moved to another machine.
        manifest_dict["manifest_path"] = "manifest.json"
        manifest_dict["summary_path"] = "summary.json"
        manifest_dict["campaign_state_path"] = "campaign_state.json"
        (run_dir / "manifest.json").write_text(
            json.dumps(manifest_dict, indent=2, default=str), encoding="utf-8",
        )

        # Per-run environment provenance: roll the materialised SUT's
        # per-element tags up into a corpus/AutoSUT/analyst summary. The
        # declared CVE-injection set is threaded in so the vulnerability
        # dimension is populated. Named environment_provenance.json to avoid
        # colliding with the run-reproducibility provenance.json above (git +
        # Caldera state). Counted, never computed — see provenance.py.
        from . import provenance
        env_prov = provenance.summarize_profile(
            result.sut, campaign_id=result.campaign_id, cves=cve_set,
        )
        (run_dir / "environment_provenance.json").write_text(
            json.dumps(env_prov.model_dump(), indent=2), encoding="utf-8",
        )
        summary = {
            "campaign_id": result.campaign_id,
            "timestamp": result.timestamp.isoformat(timespec="seconds"),
            "total_techniques": result.total_techniques,
            "successful": result.successful,
            "evidence_backed_successful": result.evidence_backed_successful,
            "adapted_successful": result.adapted_successful,
            "marker_only_successful": result.marker_only_successful,
            "fidelity_distribution": result.fidelity_distribution,
            "evidence_directory": str(run_dir.relative_to(PROJECT_ROOT)),
        }
        (run_dir / "summary.json").write_text(
            json.dumps(summary, indent=2), encoding="utf-8",
        )

        # Fidelity rubric — adopted from the frozen STICKS methodology so each
        # AutoSUT run carries the same 5-question audit surface. Errors here
        # are real bugs (model drift, missing fields) and must surface.
        from . import fidelity_rubric
        rubrics = fidelity_rubric.score_manifest(result.techniques)
        rubric_report = {
            "campaign_id": result.campaign_id,
            "run_id": result.run_id,
            "summary": fidelity_rubric.summarize(rubrics),
            "techniques": [
                {
                    "technique_id": rubric.technique_id,
                    "computed_fidelity": rubric.computed_fidelity.value,
                    "declared_fidelity": rubric.declared_fidelity.value,
                    "consistent": rubric.consistent,
                    "yes_count": rubric.yes_count,
                    "answers": [
                        {
                            "question_id": answer.question_id,
                            "answer": answer.answer,
                            "justification": answer.justification,
                        }
                        for answer in rubric.answers
                    ],
                }
                for rubric in rubrics
            ],
        }
        (run_dir / "fidelity_report.json").write_text(
            json.dumps(rubric_report, indent=2), encoding="utf-8",
        )


def build_default() -> CampaignOrchestrator:
    return CampaignOrchestrator()
