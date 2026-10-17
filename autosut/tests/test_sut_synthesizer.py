from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from orchestrator.models import SUTComposition  # noqa: E402
from planning.sut_synthesizer import (  # noqa: E402
    MalformedCompositionError,
    synthesize_composition,
    verify_composition,
)

RECIPES = {"openssh_weak_password", "apache_default_site"}
MATERIALIZABLE = {"Linux"}


def _reply(comp: dict) -> str:
    return json.dumps(comp)


def _linux_comp() -> dict:
    return {
        "credentials": [{"kind": "password", "user": "labuser", "secret": "s", "purpose": "ssh"}],
        "artifacts": [{"path": "/home/labuser/secret.txt", "content_text": "x", "owner": "labuser", "mode": "0644", "purpose": "decoy"}],
        "applications": [{"name": "openssh", "version": "default", "recipe": "openssh_weak_password", "purpose": "ssh"}],
        "exposures": [{"port": 22, "service": "ssh", "purpose": "ssh"}],
    }


def test_verifier_admits_a_materializable_linux_composition():
    verdict = verify_composition(
        SUTComposition.model_validate(_linux_comp()),
        platform="Linux", materializable_platforms=MATERIALIZABLE, known_recipes=RECIPES,
    )
    assert verdict.materializable and not verdict.issues


def test_verifier_rejects_unknown_recipe_and_relative_path_and_bad_mode():
    comp = _linux_comp()
    comp["applications"][0]["recipe"] = "install_windows_iis"
    comp["artifacts"][0]["path"] = "relative/secret.txt"
    comp["artifacts"][0]["mode"] = "rwx"
    verdict = verify_composition(
        SUTComposition.model_validate(comp),
        platform="Linux", materializable_platforms=MATERIALIZABLE, known_recipes=RECIPES,
    )
    assert not verdict.materializable
    assert any("installer" in issue for issue in verdict.issues)
    assert any("absolute" in issue for issue in verdict.issues)
    assert any("octal" in issue for issue in verdict.issues)


def test_verifier_rejects_shell_metacharacters_and_multiline_password():
    comp = _linux_comp()
    comp["credentials"][0]["user"] = "lab;touch /tmp/injected"
    comp["credentials"][0]["secret"] = "first\nother:second"
    verdict = verify_composition(
        SUTComposition.model_validate(comp),
        platform="Linux", materializable_platforms=MATERIALIZABLE, known_recipes=RECIPES,
    )
    assert not verdict.materializable
    assert any("POSIX account" in issue for issue in verdict.issues)
    assert any("multiline" in issue for issue in verdict.issues)


def test_verifier_abstains_on_a_non_materializable_platform():
    verdict = verify_composition(
        SUTComposition.model_validate(_linux_comp()),
        platform="Windows", materializable_platforms=MATERIALIZABLE, known_recipes=RECIPES,
    )
    assert not verdict.materializable
    assert any("not materializable" in issue for issue in verdict.issues)


def test_synthesis_retries_until_materializable():
    bad = _linux_comp(); bad["applications"][0]["recipe"] = "nope"
    replies = iter([_reply(bad), _reply(_linux_comp())])
    calls = {"n": 0}
    def complete(system, user):
        calls["n"] += 1
        return next(replies)
    comp, verdict = synthesize_composition(
        "Linux", [{"technique_id": "T1005", "name": "collect"}], complete,
        materializable_platforms=MATERIALIZABLE, known_recipes=RECIPES,
    )
    assert verdict.materializable
    assert calls["n"] == 2


def test_synthesis_returns_non_materializable_verdict_when_it_cannot_bind():
    bad = _linux_comp(); bad["applications"][0]["recipe"] = "nope"
    comp, verdict = synthesize_composition(
        "Linux", [{"technique_id": "T1005", "name": "collect"}], lambda s, u: _reply(bad),
        materializable_platforms=MATERIALIZABLE, known_recipes=RECIPES, max_attempts=2,
    )
    assert not verdict.materializable


def test_malformed_reply_raises():
    with pytest.raises(MalformedCompositionError):
        synthesize_composition("Linux", [], lambda s, u: "no json",
                               materializable_platforms=MATERIALIZABLE, known_recipes=RECIPES)
