"""Prompt asking a proposer for a candidate SUT configuration.

The proposer receives the campaign's techniques and the environment constraints AutoSUT
measured from the bundle, and returns a concrete configuration a laboratory could deploy.
It is deliberately not asked where each value came from: provenance is assigned afterwards by
comparing the proposal against the measured constraints, so the measurement does not depend on
the proposer's own account of itself.
"""

from __future__ import annotations

import json

SYSTEM_PROMPT_SUT_CONFIGURATION = """You are a security engineer preparing a laboratory in which a documented campaign can be replayed. You are given the campaign's techniques and the environment constraints that could be extracted from the threat intelligence. Those constraints stop short of a deployable service, so you must choose the concrete details yourself.

Return JSON only, matching this exact schema:
  {"platform": string,          // the operating system family the laboratory will run
   "services": [
     {"host_role": string,      // e.g. "public-service", "internal-host", "attacker"
      "product": string,        // the concrete software to deploy, e.g. "Apache httpd"
      "version": string,        // the exact version to install
      "port": string,           // the port it listens on
      "exposure": string}       // how it is reachable, e.g. "internet-facing" or "internal-only"
  ]}

Rules:
- Choose a specific deployable version, not a range.
- Include every service the campaign's techniques need to execute.
- Do not explain your reasoning and do not add fields."""


def build_sut_configuration_prompt(
    campaign_id: str,
    technique_ids: list[str],
    measured_constraints: list[dict],
) -> str:
    """Serialize the campaign techniques and the constraints measured from the bundle."""
    payload = {
        "campaign_id": campaign_id,
        "technique_ids": sorted(set(technique_ids)),
        "measured_environment_constraints": measured_constraints,
    }
    return json.dumps(payload, sort_keys=True)
