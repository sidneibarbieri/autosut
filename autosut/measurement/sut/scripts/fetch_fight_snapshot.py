#!/usr/bin/env python3
"""Fetch and normalize the pinned MITRE FiGHT 3.1.0 YAML snapshot.

The FiGHT website consumes ``fight.yaml`` directly.  FiGHT does not currently
publish an official STIX bundle, so this script preserves the upstream YAML as
the authoritative snapshot and emits a small, deterministic JSON derivative
for measurement code.  The raw hash and expected headline counts are pinned so
that an upstream change fails loudly instead of silently changing paper
denominators.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import tempfile
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple
from urllib.request import Request, urlopen

import yaml


FIGHT_VERSION = "3.1.0"
SOURCE_URL = "https://fight.mitre.org/fight.yaml"
SOURCE_INFO_URL = "https://fight.mitre.org/resources/info/"
SOURCE_TERMS_URL = "https://fight.mitre.org/resources/terms/"
SNAPSHOT_RETRIEVED_AT = "2026-07-18T13:04:28Z"
SOURCE_LAST_MODIFIED = "2025-11-14T17:50:50Z"
EXPECTED_RAW_SHA256 = "59a9addbd75d8680091797d66d5b237d9d026512990c61a6f51692ca94d2a7a8"
EXPECTED_COUNTS = {
    "techniques": 183,
    "with_platforms": 140,
    "with_architecture_segments": 163,
    "with_software": 25,
    "with_cves": 5,
    "fight_namespace_ids": 183,
}
MAX_RAW_BYTES = 10 * 1024 * 1024
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
FIGHT_TECHNIQUE_ID_RE = re.compile(r"^FGT\d{4}(?:\.\d{3})?$")

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_OUTPUT_DIR = SCRIPT_DIR / "data"
RAW_FILENAME = "fight-3.1.0.yaml"
NORMALIZED_FILENAME = "fight-3.1.0.normalized.json"
METADATA_FILENAME = "fight-3.1.0.metadata.json"


class SnapshotError(RuntimeError):
    """Raised when the upstream snapshot violates the pinned contract."""


def sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _text(value: Any, field: str, *, allow_empty: bool = True) -> str:
    if not isinstance(value, str):
        raise SnapshotError(f"{field} must be a string, got {type(value).__name__}")
    normalized = value.replace("\r\n", "\n").replace("\r", "\n").strip()
    if not allow_empty and not normalized:
        raise SnapshotError(f"{field} must not be empty")
    return normalized


def _split_csv(value: Any, field: str) -> List[str]:
    if value is None:
        return []
    raw = _text(value, field)
    return list(dict.fromkeys(part.strip() for part in raw.split(",") if part.strip()))


def _string_list(value: Any, field: str) -> List[str]:
    if not isinstance(value, list):
        raise SnapshotError(f"{field} must be a list")
    return [_text(item, f"{field}[]") for item in value]


def _object_list(value: Any, field: str) -> List[Mapping[str, Any]]:
    if not isinstance(value, list):
        raise SnapshotError(f"{field} must be a list")
    result: List[Mapping[str, Any]] = []
    for index, item in enumerate(value):
        if not isinstance(item, Mapping):
            raise SnapshotError(f"{field}[{index}] must be an object")
        result.append(item)
    return result


def _normalize_software(value: Any, field: str) -> List[Dict[str, str]]:
    software: List[Dict[str, str]] = []
    seen: set = set()
    for index, item in enumerate(_object_list(value, field)):
        entry = {
            "id": _text(item.get("fgsid", ""), f"{field}[{index}].fgsid"),
            "name": _text(
                item.get("name", ""), f"{field}[{index}].name", allow_empty=False
            ),
            "description": _text(
                item.get("description", ""), f"{field}[{index}].description"
            ),
        }
        key = (entry["id"], entry["name"], entry["description"])
        if key not in seen:
            seen.add(key)
            software.append(entry)
    return software


def _normalize_procedures(value: Any, field: str) -> List[Dict[str, str]]:
    procedures: List[Dict[str, str]] = []
    for index, item in enumerate(_object_list(value, field)):
        procedures.append(
            {
                "name": _text(item.get("name", ""), f"{field}[{index}].name"),
                "description": _text(
                    item.get("description", ""), f"{field}[{index}].description"
                ),
            }
        )
    return procedures


def _extract_cves(values: Iterable[Any]) -> List[str]:
    serialized = json.dumps(list(values), ensure_ascii=False)
    return sorted({match.upper() for match in CVE_RE.findall(serialized)})


def _normalize_technique(item: Mapping[str, Any], index: int) -> Dict[str, Any]:
    prefix = f"techniques[{index}]"
    if item.get("object-type") != "technique":
        raise SnapshotError(f"{prefix}.object-type must equal 'technique'")

    technique: Dict[str, Any] = {
        "id": _text(item.get("id"), f"{prefix}.id", allow_empty=False),
        "name": _text(item.get("name"), f"{prefix}.name", allow_empty=False),
        "status": _text(item.get("status"), f"{prefix}.status", allow_empty=False),
        "platforms": _split_csv(item.get("platforms"), f"{prefix}.platforms"),
        "architecture_segments": _split_csv(
            item.get("architecture-segment"), f"{prefix}.architecture-segment"
        ),
        "software": _normalize_software(item.get("software"), f"{prefix}.software"),
        "description": _text(item.get("description"), f"{prefix}.description"),
        "references": _string_list(item.get("references"), f"{prefix}.references"),
        "procedure_examples": _normalize_procedures(
            item.get("procedureexamples"), f"{prefix}.procedureexamples"
        ),
    }
    technique["cves"] = _extract_cves(
        (
            technique["description"],
            technique["references"],
            technique["procedure_examples"],
            technique["software"],
        )
    )
    return technique


def build_normalized(raw_payload: bytes) -> Dict[str, Any]:
    try:
        document = yaml.safe_load(raw_payload)
    except yaml.YAMLError as exc:
        raise SnapshotError(f"invalid FiGHT YAML: {exc}") from exc

    if not isinstance(document, Mapping):
        raise SnapshotError("FiGHT root must be an object")
    if document.get("id") != "FiGHT":
        raise SnapshotError("FiGHT root id is missing or unexpected")
    if document.get("name") != "FiGHT Threat Matrix":
        raise SnapshotError("FiGHT root name is missing or unexpected")

    raw_techniques = _object_list(document.get("techniques"), "techniques")
    techniques = [_normalize_technique(item, index) for index, item in enumerate(raw_techniques)]
    techniques.sort(key=lambda item: item["id"])

    ids = [item["id"] for item in techniques]
    if len(ids) != len(set(ids)):
        raise SnapshotError("FiGHT technique identifiers are not unique")

    counts = {
        "techniques": len(techniques),
        "with_platforms": sum(bool(item["platforms"]) for item in techniques),
        "with_architecture_segments": sum(
            bool(item["architecture_segments"]) for item in techniques
        ),
        "with_software": sum(bool(item["software"]) for item in techniques),
        "with_cves": sum(bool(item["cves"]) for item in techniques),
        "fight_namespace_ids": sum(
            bool(FIGHT_TECHNIQUE_ID_RE.fullmatch(item["id"])) for item in techniques
        ),
    }
    if counts != EXPECTED_COUNTS:
        raise SnapshotError(
            f"FiGHT {FIGHT_VERSION} count contract changed: {counts!r} != {EXPECTED_COUNTS!r}"
        )

    raw_object_counts = {
        key.replace(" ", "_"): len(value)
        for key, value in document.items()
        if isinstance(value, list)
    }
    return {
        "schema_version": "autosut.fight-normalized.v1",
        "source": {
            "name": "MITRE FiGHT",
            "version": FIGHT_VERSION,
            "url": SOURCE_URL,
            "information_url": SOURCE_INFO_URL,
            "terms_url": SOURCE_TERMS_URL,
            "format": "YAML",
            "raw_sha256": sha256(raw_payload),
            "retrieved_at": SNAPSHOT_RETRIEVED_AT,
            "last_modified": SOURCE_LAST_MODIFIED,
            "license": (
                "MITRE grants a non-exclusive, royalty-free license for research, "
                "development, and commercial use; copies must reproduce its "
                "copyright designation and license."
            ),
            "marking": (
                "MITRE FiGHT is a trademark of The MITRE Corporation; approved for "
                "public release, distribution unlimited, case 22-2192."
            ),
        },
        "raw_object_counts": dict(sorted(raw_object_counts.items())),
        "counts": counts,
        "techniques": techniques,
    }


def serialize_json(value: Mapping[str, Any]) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def _download() -> bytes:
    request = Request(
        SOURCE_URL,
        headers={"User-Agent": "AutoSUT-FiGHT-snapshot/1.0 (+research artifact)"},
    )
    with urlopen(request, timeout=60) as response:
        if response.geturl() != SOURCE_URL:
            raise SnapshotError(f"unexpected redirect target: {response.geturl()}")
        payload = response.read(MAX_RAW_BYTES + 1)
    if len(payload) > MAX_RAW_BYTES:
        raise SnapshotError(f"FiGHT YAML exceeds {MAX_RAW_BYTES} bytes")
    return payload


def _atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=str(path.parent), delete=False) as handle:
        temporary = Path(handle.name)
        handle.write(payload)
    temporary.replace(path)


def write_snapshot(raw_payload: bytes, output_dir: Path) -> Tuple[Path, Path, Path]:
    raw_digest = sha256(raw_payload)
    if raw_digest != EXPECTED_RAW_SHA256:
        raise SnapshotError(
            "FiGHT upstream bytes do not match the pinned 3.1.0 snapshot: "
            f"{raw_digest} != {EXPECTED_RAW_SHA256}"
        )

    normalized = build_normalized(raw_payload)
    normalized_payload = serialize_json(normalized)
    metadata = {
        "schema_version": "autosut.snapshot-metadata.v1",
        "dataset": "MITRE FiGHT",
        "version": FIGHT_VERSION,
        "source_url": SOURCE_URL,
        "source_information_url": SOURCE_INFO_URL,
        "source_terms_url": SOURCE_TERMS_URL,
        "retrieved_at": SNAPSHOT_RETRIEVED_AT,
        "source_last_modified": SOURCE_LAST_MODIFIED,
        "license": (
            "MITRE grants a non-exclusive, royalty-free license for research, "
            "development, and commercial use; copies must reproduce its copyright "
            "designation and license."
        ),
        "marking": (
            "MITRE FiGHT is a trademark of The MITRE Corporation; approved for "
            "public release, distribution unlimited, case 22-2192."
        ),
        "authoritative_file": RAW_FILENAME,
        "authoritative_format": "YAML",
        "authoritative_sha256": raw_digest,
        "derived_file": NORMALIZED_FILENAME,
        "derived_sha256": sha256(normalized_payload),
        "counts": normalized["counts"],
        "refresh_policy": (
            "Pinned paper snapshot; update version, hash, denominators, and claims together."
        ),
    }

    raw_path = output_dir / RAW_FILENAME
    normalized_path = output_dir / NORMALIZED_FILENAME
    metadata_path = output_dir / METADATA_FILENAME
    _atomic_write(raw_path, raw_payload)
    _atomic_write(normalized_path, normalized_payload)
    _atomic_write(metadata_path, serialize_json(metadata))
    return raw_path, normalized_path, metadata_path


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--from-raw",
        type=Path,
        help="Regenerate from an existing pinned YAML file instead of using the network.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help=f"Snapshot directory (default: {DEFAULT_OUTPUT_DIR}).",
    )
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    raw_payload = args.from_raw.read_bytes() if args.from_raw else _download()
    paths = write_snapshot(raw_payload, args.output_dir)
    for path in paths:
        print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
