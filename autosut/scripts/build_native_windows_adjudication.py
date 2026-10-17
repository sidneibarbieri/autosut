#!/usr/bin/env python3
"""Build and assess a hash-bound human native-Windows adjudication packet.

This script never infers semantic requirements from keywords or procedure text.
It only validates a supplied frozen STICKS corpus, prepares a review packet, or
accounts for human annotations under a separately persisted protocol.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.cti.native_windows_adjudication import (  # noqa: E402
    AssessmentStatus,
    CandidateSelectionMode,
    CorpusSourceMode,
    assess_adjudication,
    build_annotation_template,
    build_candidate_set,
    load_annotation_set,
    load_candidate_set,
    load_protocol,
    new_protocol,
    write_json,
)


def _source_mode(value: str) -> CorpusSourceMode:
    try:
        return CorpusSourceMode(value)
    except ValueError as exc:
        choices = ", ".join(item.value for item in CorpusSourceMode)
        raise argparse.ArgumentTypeError(f"source mode must be one of: {choices}") from exc


def _selection_mode(value: str) -> CandidateSelectionMode:
    try:
        return CandidateSelectionMode(value)
    except ValueError as exc:
        choices = ", ".join(item.value for item in CandidateSelectionMode)
        raise argparse.ArgumentTypeError(f"selection mode must be one of: {choices}") from exc


def _required_annotation_count(value: str) -> int:
    parsed = int(value)
    if parsed not in {1, 2}:
        raise argparse.ArgumentTypeError("annotation count must be 1 or 2")
    return parsed


def _add_prepare_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--protocol", type=Path, required=True)
    parser.add_argument("--plans-root", type=Path, required=True)
    parser.add_argument("--attack-bundle", type=Path, required=True)
    parser.add_argument("--source-identifier", required=True)
    parser.add_argument("--source-mode", type=_source_mode, required=True)
    parser.add_argument("--candidate-output", type=Path, required=True)
    parser.add_argument("--template-output", type=Path, required=True)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    protocol_template = subparsers.add_parser(
        "protocol-template",
        help="write a versioned protocol that must be pinned before preparation",
    )
    protocol_template.add_argument("--protocol-id", required=True)
    protocol_template.add_argument(
        "--candidate-selection",
        type=_selection_mode,
        default=CandidateSelectionMode.WINDOWS_PLATFORM_LABEL_TRIAGE,
    )
    protocol_template.add_argument(
        "--required-independent-annotation-count",
        type=_required_annotation_count,
        default=2,
    )
    protocol_template.add_argument("--output", type=Path, required=True)

    prepare = subparsers.add_parser(
        "prepare",
        help="validate an explicit corpus input and write a candidate packet and annotation form",
    )
    _add_prepare_arguments(prepare)

    assess = subparsers.add_parser(
        "assess",
        help="validate one or two completed identity-free annotation sets and account for agreement",
    )
    assess.add_argument("--protocol", type=Path, required=True)
    assess.add_argument("--candidate-set", type=Path, required=True)
    assess.add_argument("--annotation", type=Path, action="append", default=[])
    assess.add_argument("--output", type=Path, required=True)
    assess.add_argument(
        "--require-release-qualified",
        action="store_true",
        help="exit nonzero unless the release-scope decision is qualified",
    )
    return parser


def _run_protocol_template(args: argparse.Namespace) -> int:
    protocol = new_protocol(
        protocol_id=args.protocol_id,
        candidate_selection=args.candidate_selection,
        required_independent_annotation_count=args.required_independent_annotation_count,
    )
    write_json(args.output, protocol)
    print(f"[native-windows-adjudication] protocol={args.output}")
    print(f"[native-windows-adjudication] protocol_sha256={protocol.content_sha256}")
    return 0


def _run_prepare(args: argparse.Namespace) -> int:
    protocol = load_protocol(args.protocol)
    candidate_set = build_candidate_set(
        corpus_root=args.plans_root,
        attack_bundle_path=args.attack_bundle,
        source_identifier=args.source_identifier,
        source_mode=args.source_mode,
        protocol=protocol,
        project_root=PROJECT_ROOT,
    )
    template = build_annotation_template(candidate_set=candidate_set, protocol=protocol)
    write_json(args.candidate_output, candidate_set)
    write_json(args.template_output, template)
    print(
        "[native-windows-adjudication] "
        f"compiled={candidate_set.compiled_campaign_count} "
        f"selected={candidate_set.selected_candidate_count} "
        f"not_compiled={candidate_set.not_compiled_campaign_count}"
    )
    print(f"[native-windows-adjudication] candidates={args.candidate_output}")
    print(f"[native-windows-adjudication] annotation_template={args.template_output}")
    print(
        "[native-windows-adjudication] "
        f"release_dependency_status={candidate_set.corpus.release_dependency_status}"
    )
    return 0


def _run_assess(args: argparse.Namespace) -> int:
    protocol = load_protocol(args.protocol)
    candidate_set = load_candidate_set(args.candidate_set)
    annotation_sets = [load_annotation_set(path) for path in args.annotation]
    assessment = assess_adjudication(
        candidate_set=candidate_set,
        protocol=protocol,
        annotation_sets=annotation_sets,
    )
    write_json(args.output, assessment)
    print(
        "[native-windows-adjudication] "
        f"adjudication_status={assessment.adjudication_status.value} "
        f"release_scope_decision_status={assessment.release_scope_decision_status.value}"
    )
    print(f"[native-windows-adjudication] assessment={args.output}")
    if args.require_release_qualified and (
        assessment.release_scope_decision_status is not AssessmentStatus.QUALIFIED
    ):
        return 2
    return 0


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()
    if args.command == "protocol-template":
        return _run_protocol_template(args)
    if args.command == "prepare":
        return _run_prepare(args)
    if args.command == "assess":
        return _run_assess(args)
    raise RuntimeError(f"unhandled command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
