"""Synthesize a materializable SUT composition for a campaign plan, and verify it deterministically.

STICKS compiles a STIX bundle into a procedural plan; this module turns that plan into the concrete
environment the plan needs. An untrusted proposer reads the plan's on-host techniques and returns a
:class:`SUTComposition` - the credentials, staged files, and services a host must offer for those
techniques to run - and a deterministic verifier admits it only when every element is materializable:
the platform is one a laboratory can build, each credential is a kind the composer can apply, each
staged file has an absolute path and an octal mode, and each service names a recipe the artifact can
install. This is the environment half of "propose then dispose": the proposer interprets the plan,
the verifier decides what a host can actually stand up.

The proposer is injected as a ``complete`` callable, so the module carries no provider dependency and
verifies in tests without a live model. A composition the verifier cannot admit is returned with its
issues so the caller abstains rather than trying to stand up an environment that cannot be built.
"""

from __future__ import annotations

import json
from typing import Callable

from pydantic import BaseModel, ConfigDict, Field

from orchestrator.models import SUTComposition
from orchestrator.composition_contract import composition_input_issues

CompletionFn = Callable[[str, str], str]

# Credential kinds the composer actually applies to a host; others land as declarative breadcrumbs.
APPLICABLE_CREDENTIAL_KINDS = frozenset({"password", "ssh_key"})

SYSTEM_PROMPT = """You design the lab host a set of attack techniques needs in order to run.
You receive the host platform and the techniques that execute on the host. Return one JSON object
describing what the host must provide:
{
  "credentials": [{"kind": "password"|"ssh_key", "user": string, "secret": string, "purpose": string}],
  "artifacts":   [{"path": absolute string, "content_text": string, "owner": string, "mode": octal string, "purpose": string}],
  "applications":[{"name": string, "version": string, "recipe": string, "purpose": string}],
  "exposures":   [{"port": int, "service": string, "purpose": string}]
}
Stage a decoy file for every technique that reads or collects local data. Declare a credential for
every technique that authenticates. Use only application recipes from the provided list. Keep every
path absolute and every mode a three- or four-digit octal. Provide only what the techniques need.
"""


class CompositionVerdict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    materializable: bool
    issues: list[str] = Field(default_factory=list)


class MalformedCompositionError(ValueError):
    """The model reply could not be parsed into a SUT composition."""


def verify_composition(
    composition: SUTComposition,
    *,
    platform: str,
    materializable_platforms: set[str],
    known_recipes: set[str],
) -> CompositionVerdict:
    """Admit a composition only when every element is one a laboratory can stand up."""
    issues: list[str] = []
    if platform not in materializable_platforms:
        issues.append(f"platform {platform} is not materializable here")
    for credential in composition.credentials:
        if credential.kind not in APPLICABLE_CREDENTIAL_KINDS:
            issues.append(f"credential kind {credential.kind!r} cannot be applied to the host")
    issues.extend(composition_input_issues(composition))
    for application in composition.applications:
        if application.recipe not in known_recipes:
            issues.append(f"application recipe {application.recipe!r} has no installer")
    return CompositionVerdict(materializable=not issues, issues=sorted(set(issues)))


def build_user_prompt(platform: str, technique_briefs: list[dict], known_recipes: set[str]) -> str:
    payload = {
        "platform": platform,
        "on_host_techniques": technique_briefs,
        "available_recipes": sorted(known_recipes),
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def _parse_composition(raw: str) -> SUTComposition:
    start = raw.find("{")
    end = raw.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise MalformedCompositionError("response contains no JSON object")
    try:
        payload = json.loads(raw[start : end + 1])
    except json.JSONDecodeError as error:
        raise MalformedCompositionError(f"reply is not valid JSON: {error}") from error
    return SUTComposition.model_validate(payload)


def _feedback(verdict: CompositionVerdict) -> str:
    return "\nPrevious attempt was not materializable: " + json.dumps(verdict.issues)


def synthesize_composition(
    platform: str,
    technique_briefs: list[dict],
    complete: CompletionFn,
    *,
    materializable_platforms: set[str],
    known_recipes: set[str],
    max_attempts: int = 3,
) -> tuple[SUTComposition, CompositionVerdict]:
    """Propose a composition for the plan and verify it, retrying until materializable or attempts end.

    The final composition is returned with its verdict even when not materializable, so the caller
    abstains rather than trying to build a host it cannot. A malformed reply raises.
    """
    feedback = ""
    composition = None
    verdict = None
    for _ in range(max_attempts):
        raw = complete(SYSTEM_PROMPT, build_user_prompt(platform, technique_briefs, known_recipes) + feedback)
        composition = _parse_composition(raw)
        verdict = verify_composition(
            composition, platform=platform,
            materializable_platforms=materializable_platforms, known_recipes=known_recipes,
        )
        if verdict.materializable:
            return composition, verdict
        feedback = _feedback(verdict)
    return composition, verdict
