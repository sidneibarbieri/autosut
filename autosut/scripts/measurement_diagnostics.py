"""Recognize the exact reviewer-local measurement log layout."""

from pathlib import Path
import re

LOG_NAMES = frozenset({
    "measurement_pipeline_release.log", "measurement_render_release.log",
    "measurement_traceability_release.log", "measurement_validation_release.log",
    "measurement_cve_resolution_release.log", "measurement_infra_automation_release.log",
    "measurement_corpus_state_release.log", "measurement_provenance_release.log",
    "measurement_rule_surface_release.log", "measurement_sync_release.log",
    "measurement_bib_policy_check.log", "measurement_paper_release.log",
    "measurement_latex_reference_warnings.log", "measurement_todo_hits.log",
    "measurement_paper_hygiene.log",
})


def is_measurement_log_path(path: Path) -> bool:
    """Accept a declared log name in a direct, generated per-invocation directory."""
    return (
        len(path.parts) == 4
        and path.parts[:2] == ("results", "reviewer_runtime")
        and re.fullmatch(r"measurement-[A-Za-z0-9]{6}", path.parts[2]) is not None
        and path.name in LOG_NAMES
    )
