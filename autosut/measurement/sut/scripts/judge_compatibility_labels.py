#!/usr/bin/env python3
"""Label the blind compatibility sample with independent LLM judges.

Each judge reads only the blind annotation sheet and the codebook; neither the
AutoSUT label nor the rule that fired is in its input. Every request and raw
response is stored, so the labels can be re-scored without calling a model.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import urllib.request
from pathlib import Path

from pydantic import BaseModel, ConfigDict

SCRIPTS_DIR = Path(__file__).resolve().parent
AUDIT_DIR = SCRIPTS_DIR / "results" / "audit"
CODEBOOK = AUDIT_DIR / "COMPATIBILITY_ANNOTATION_CODEBOOK.md"
SHEET = AUDIT_DIR / "compatibility_annotation_sheet_A.csv"
JUDGMENT_ROOT = AUDIT_DIR / "compatibility_judgments"
LABELS = ("CF", "VMR", "ID")
ITEM_FIELDS = ("technique_external_id", "technique_name", "tactics", "platforms",
               "permissions", "description_excerpt")
OUTPUT_INSTRUCTION = (
    'Reply with one JSON object and nothing else: {"label": "CF" | "VMR" | "ID", '
    '"reason": "<one sentence naming the deciding factor>"}.'
)


class JudgeConfig(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    model: str
    base_url: str | None = None
    base_url_env: str | None = None
    base_url_suffix: str = ""
    api_key_env: str
    token_parameter: str = "max_tokens"
    max_output_tokens: int = 400
    extra_parameters: dict[str, str] = {}

    def endpoint(self) -> str:
        base = self.base_url or os.environ[self.base_url_env or ""]
        return base.rstrip("/") + self.base_url_suffix + "/chat/completions"


class Judgment(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    item_id: str
    judge: str
    model: str
    label: str | None
    reason: str
    raw_content: str


def load_judges(path: Path) -> list[JudgeConfig]:
    return [JudgeConfig.model_validate(entry) for entry in json.loads(path.read_text())["judges"]]


def item_prompt(row: dict) -> str:
    return "\n".join(f"{field}: {row[field]}" for field in ITEM_FIELDS)


def parse_label(content: str) -> tuple[str | None, str]:
    """Return the label and reason, or (None, reason) when the reply has no valid label."""
    match = re.search(r"\{.*\}", content, re.DOTALL)
    if match is None:
        return None, "reply contained no JSON object"
    try:
        reply = json.loads(match.group(0))
    except json.JSONDecodeError:
        return None, "reply JSON did not parse"
    label = str(reply.get("label", "")).strip().upper()
    return (label if label in LABELS else None), str(reply.get("reason", ""))


def complete(judge: JudgeConfig, system_prompt: str, user_prompt: str) -> dict:
    payload = {
        "model": judge.model,
        "temperature": 0,
        judge.token_parameter: judge.max_output_tokens,
        **judge.extra_parameters,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
    }
    request = urllib.request.Request(
        judge.endpoint(),
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {os.environ[judge.api_key_env]}"},
    )
    with urllib.request.urlopen(request, timeout=300) as response:
        return json.loads(response.read())


def judge_item(judge: JudgeConfig, system_prompt: str, row: dict, output_dir: Path) -> Judgment:
    record_path = output_dir / f"{row['item_id']}.json"
    if record_path.exists():
        return Judgment.model_validate(json.loads(record_path.read_text())["judgment"])
    user_prompt = item_prompt(row)
    response = complete(judge, system_prompt, user_prompt)
    content = response["choices"][0]["message"]["content"] or ""
    label, reason = parse_label(content)
    judgment = Judgment(item_id=row["item_id"], judge=judge.name, model=judge.model,
                        label=label, reason=reason, raw_content=content)
    record_path.write_text(json.dumps({
        "request": {"system": system_prompt, "user": user_prompt, "model": judge.model, "temperature": 0,
                    "extra_parameters": judge.extra_parameters},
        "response": response,
        "judgment": judgment.model_dump(),
    }, indent=2) + "\n", encoding="utf-8")
    return judgment


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--judges", type=Path, required=True)
    parser.add_argument("--judge", action="append", default=[], help="Run only these judge names.")
    args = parser.parse_args()

    system_prompt = CODEBOOK.read_text(encoding="utf-8") + "\n\n" + OUTPUT_INSTRUCTION
    with SHEET.open(encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    for judge in load_judges(args.judges):
        if args.judge and judge.name not in args.judge:
            continue
        output_dir = JUDGMENT_ROOT / judge.name
        output_dir.mkdir(parents=True, exist_ok=True)
        labels = [judge_item(judge, system_prompt, row, output_dir).label for row in rows]
        print(f"[judge:{judge.name}] {len(rows)} items, "
              + ", ".join(f"{label}={labels.count(label)}" for label in (*LABELS, None)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
