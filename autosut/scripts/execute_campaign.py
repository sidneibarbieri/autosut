#!/usr/bin/env python3
"""Generate and screen campaign procedure proposals on a fresh SUT.

Given a campaign id and a model configuration, this command resolves the declared SUT, starts a
fresh Docker host, materializes the SUT, and asks the model for one procedure proposal per
technique. It statically checks each proposal against the host's declared resources and then tears
the host down. It does not execute model-produced commands or report technique success.

The model is reached through an injected provider config. Reviewers use their own key only for this
optional planning experiment; the released measurement and claim-validation paths need no key.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from orchestrator import catalog  # noqa: E402
from orchestrator.environment import DockerEnvironment  # noqa: E402
from orchestrator.models import SUTComposition, SUTProfile  # noqa: E402
from orchestrator.sut_composer import apply_composition  # noqa: E402
from planning.campaign_execution import (  # noqa: E402
    CampaignExecutionReport,
    TechniqueBrief,
    execute_campaign,
)
from planning.model_provider import ProviderConfig, build_completion, recording_completion  # noqa: E402

RULE = "-" * 78


def load_technique_briefs(campaign_id: str) -> list[TechniqueBrief]:
    """Read the campaign's technique list into (id, summary) briefs the engine consumes."""
    document = json.loads((PROJECT_ROOT / "campaigns" / f"{campaign_id}.json").read_text(encoding="utf-8"))
    briefs: list[TechniqueBrief] = []
    for technique in document.get("techniques", []):
        technique_id = technique.get("technique_id") or technique.get("id")
        summary = technique.get("procedure") or technique.get("description") or technique.get("name") or technique_id
        briefs.append(TechniqueBrief(technique_id=technique_id, summary=f"{technique.get('name', '')}: {summary}"))
    return briefs


def single_host_composition(sut: SUTProfile) -> SUTComposition:
    """The composition the executor materializes: the single host, or the first target host."""
    if sut.composition is not None:
        return sut.composition
    for host in sut.hosts or []:
        if host.composition is not None:
            return host.composition
    raise ValueError(f"campaign SUT {sut.sut_id} declares no composition to materialize")


def print_report(report: CampaignExecutionReport) -> None:
    print(RULE)
    print(f"CAMPAIGN {report.campaign_id}   host: {report.host_id}   techniques: {len(report.runs)}")
    print(RULE)
    for run in report.runs:
        status = "RESOURCE-COMPATIBLE" if run.resource_compatible else "INCOMPATIBLE"
        print(f"  {run.technique_id:<12} {status:<19} {run.abstained_reason}")
        print(f"               proposal-sha256: {run.proposal_sha256}")
    print(RULE)
    print(f"  proposed {len(report.runs)}   resource-compatible "
          f"{sum(run.resource_compatible for run in report.runs)}   "
          f"contract-admitted {report.admitted_count}   executed {report.executed_count}")
    print(RULE)


def write_report(report: CampaignExecutionReport) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_dir = PROJECT_ROOT / "release" / "runs" / "planning" / f"{report.campaign_id}-{stamp}"
    out_dir.mkdir(parents=True, exist_ok=True)
    report_path = out_dir / "execution_report.json"
    report_path.write_text(json.dumps(report.model_dump(), indent=2), encoding="utf-8")
    return report_path


def run(campaign_id: str, config_path: Path, record_path: Path | None = None) -> CampaignExecutionReport:
    _, sut, _ = catalog.resolve(campaign_id)
    composition = single_host_composition(sut)
    briefs = load_technique_briefs(campaign_id)
    complete = build_completion(ProviderConfig.from_file(config_path))
    if record_path is not None:
        record_path.parent.mkdir(parents=True, exist_ok=True)
        complete = recording_completion(complete, record_path)

    readiness = DockerEnvironment.check()
    if not readiness.ready:
        raise RuntimeError(f"docker backend not ready: {', '.join(readiness.gaps)}")

    run_dir = PROJECT_ROOT / "release" / "runs" / "planning" / f"{campaign_id}-live"
    with DockerEnvironment.bring_up(sut, run_dir) as host:
        apply_composition(host, sut.sut_id, composition, run_dir)
        return execute_campaign(host, campaign_id, composition, briefs, complete)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("campaign_id", help="a catalog campaign id, e.g. 0.costaricto")
    parser.add_argument("--config", required=True, help="model provider config, e.g. config.openai.example.json")
    parser.add_argument("--record", help="write the planning transcript here for offline inspection")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    report = run(args.campaign_id, Path(args.config), Path(args.record) if args.record else None)
    print_report(report)
    print(f"wrote {write_report(report)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
