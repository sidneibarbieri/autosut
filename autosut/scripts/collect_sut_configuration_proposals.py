#!/usr/bin/env python3
"""Legacy exploratory collector for candidate SUT configurations.

Each campaign's measured environment constraints are given to several proposers, which return
a concrete deployable configuration. The raw proposals are written for inspection; provenance
and requirement satisfaction are assigned by a separate deterministic build.

This historical collector is not the canonical Step-2 semantic-enrichment
protocol. It retains an Ollama-specific surface only to reproduce its separate
exploratory corpus; it is not wired to ``config.example.json``, cannot qualify
a campaign claim, and must not be used as the default provider path.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
for import_root in (PROJECT_ROOT, SRC_ROOT):
    if str(import_root) not in sys.path:
        sys.path.insert(0, str(import_root))

from planning.sut_configuration_prompt import (  # noqa: E402
    SYSTEM_PROMPT_SUT_CONFIGURATION,
    build_sut_configuration_prompt,
)

PLANS_DIR = PROJECT_ROOT / "release" / "plans"
DEFAULT_OUTPUT_DIR = (
    PROJECT_ROOT / "release" / "experiments" / "sut_configuration" / "proposals"
)
CAMPAIGNS = ("C0010", "C0026", "C0045")
SAMPLES_PER_MODEL = 3
MODELS = ("gpt-oss:20b", "qwen2.5-coder:14b")
OLLAMA_CHAT_URL = "http://localhost:11434/v1/chat/completions"
TEMPERATURE = 0.7


def _constraints(campaign_id: str) -> tuple[list[dict], list[str]]:
    """Measured environment constraints and technique identifiers for one campaign."""
    payload = json.loads(
        (PLANS_DIR / f"{campaign_id}.sut-constraints.json").read_text(encoding="utf-8")
    )
    requirements = payload["requirements"]
    constraints = [
        {
            "kind": requirement["kind"],
            "acceptable_values": requirement["acceptable_values"],
            "source": requirement["source"],
        }
        for requirement in requirements
    ]
    techniques = [
        technique
        for requirement in requirements
        for technique in requirement["technique_ids"]
    ]
    return constraints, techniques


def _request(model: str, system_prompt: str, user_prompt: str) -> str:
    """Single chat completion against the local endpoint; transport failures propagate."""
    import urllib.request

    body = json.dumps(
        {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": TEMPERATURE,
            "response_format": {"type": "json_object"},
        }
    ).encode()
    request = urllib.request.Request(
        OLLAMA_CHAT_URL,
        data=body,
        headers={"Content-Type": "application/json", "Authorization": "Bearer local"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=600) as response:
        payload = json.loads(response.read().decode())
    return payload["choices"][0]["message"]["content"]


def _parse(content: str) -> dict:
    """Accept a fenced or bare JSON object; anything else is recorded as unusable."""
    stripped = content.strip()
    if stripped.startswith("```"):
        stripped = "\n".join(stripped.splitlines()[1:-1]).strip()
    parsed = json.loads(stripped)
    if not isinstance(parsed, dict):
        raise ValueError("proposer returned a non-object payload")
    return parsed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="autosut-sut-config-"):
        for campaign_id in CAMPAIGNS:
            constraints, techniques = _constraints(campaign_id)
            user_prompt = build_sut_configuration_prompt(
                campaign_id, techniques, constraints
            )
            for model in MODELS:
                for sample in range(1, SAMPLES_PER_MODEL + 1):
                    content = _request(
                        model, SYSTEM_PROMPT_SUT_CONFIGURATION, user_prompt
                    )
                    parsed = _parse(content)
                    record = {
                        "campaign_id": campaign_id,
                        "model": model,
                        "sample": sample,
                        "temperature": TEMPERATURE,
                        "platform": str(parsed.get("platform", "")),
                        "services": parsed.get("services", []),
                    }
                    out = (
                        args.output_dir
                        / f"{campaign_id}.{model.replace(':', '_')}.{sample}.json"
                    )
                    out.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
                    print(
                        f"[sut-config] {campaign_id} {model} sample {sample}: "
                        f"platform={record['platform'] or '-'} "
                        f"services={len(record['services'])}"
                    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
