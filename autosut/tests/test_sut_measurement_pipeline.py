from __future__ import annotations

import importlib.util
import random
import sys
from collections import Counter, defaultdict
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = (
    PROJECT_ROOT
    / "measurement"
    / "sut"
    / "scripts"
    / "sut_measurement_pipeline.py"
)


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "sut_measurement_pipeline", SCRIPT_PATH
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_campaign_precision_reference_uses_linked_software() -> None:
    pipeline = _load_module()
    campaign_id = "campaign--versioned"
    software_id = "malware--versioned"
    campaign = {"id": campaign_id, "name": "Versioned campaign"}
    software = {
        "id": software_id,
        "name": "Example Tool v2.4",
        "x_mitre_platforms": ["Windows"],
    }
    rel_fwd = defaultdict(
        list,
        {campaign_id: [("uses", software_id, {"type": "relationship"})]},
    )
    rel_rev = defaultdict(list)
    by_id = {campaign_id: campaign, software_id: software}

    software_results = pipeline.analyze_software_references(
        campaigns=[campaign],
        intrusion_sets=[],
        software_objects=[software],
        rel_fwd=rel_fwd,
        rel_rev=rel_rev,
        by_id=by_id,
        excluded_campaign_ids=set(),
    )

    platform_row = software_results["campaign_platform_details"][0]
    assert platform_row["software_ids"] == [software_id]
    assert platform_row["has_version_reference"] is True
    assert platform_row["has_precision_reference"] is True

    completeness = pipeline.analyze_campaign_profile_completeness(
        software_results,
        {"campaign_cve_details": []},
    )
    assert completeness["tier_t1_count"] == 1
    assert completeness["tier_t2_count"] == 1
    assert completeness["tier_t3_count"] == 0


def test_threshold_confusion_recomputes_neighbors_inside_conditioned_set() -> None:
    pipeline = _load_module()
    profiles = {
        "one": {"x"},
        "two-near-one": {"x", "y"},
        "two-far": {"u", "v"},
    }

    all_profiles = pipeline.compute_threshold_confusion_from_profiles(
        profiles, min_feature_count=1, delta=0.5
    )
    conditioned = pipeline.compute_threshold_confusion_from_profiles(
        profiles, min_feature_count=2, delta=0.5
    )

    assert all_profiles["confused_count"] == 2
    assert conditioned["sample_size"] == 2
    assert conditioned["confused_count"] == 0


def test_cardinality_randomizer_preserves_every_profile_size() -> None:
    pipeline = _load_module()
    profiles = {
        "empty": set(),
        "one": {"a"},
        "three": {"a", "b", "c"},
    }
    randomized = pipeline.randomize_profiles_preserving_cardinality(
        profiles,
        feature_universe={"a", "b", "c", "d", "e"},
        rng=random.Random(7),
    )

    assert {key: len(value) for key, value in randomized.items()} == {
        key: len(value) for key, value in profiles.items()
    }


def test_threshold_collapse_null_is_direct_deterministic_and_plus_one_corrected() -> None:
    pipeline = _load_module()
    profiles = {
        "singleton-a": {"popular"},
        "singleton-b": {"popular"},
        "larger-a": {"x", "y"},
        "larger-b": {"u", "v"},
    }
    kwargs = dict(
        observed_profiles=profiles,
        feature_universe={"popular", "x", "y", "u", "v", "w"},
        delta=0.1,
        n_iter=50,
        seed=11,
    )

    first = pipeline.analyze_threshold_collapse_null_model(**kwargs)
    second = pipeline.analyze_threshold_collapse_null_model(**kwargs)

    assert first["distribution_rows"] == second["distribution_rows"]
    assert first["observed_k1_confused_count"] == 2
    assert first["observed_k2_confused_count"] == 0
    assert first["observed_collapse_pp"] == 50.0
    expected = round((first["collapse_extreme_iterations"] + 1) / 51, 3)
    assert first["collapse_p_value"] == expected
    assert first["collapse_p_value_mc_se"] >= 0.0


def test_degree_preserving_swaps_keep_both_bipartite_degree_sequences() -> None:
    pipeline = _load_module()
    profiles = {
        "p1": {"a", "b"},
        "p2": {"b", "c"},
        "p3": {"c", "d"},
        "p4": {"a", "d"},
    }
    mutable = {key: set(value) for key, value in profiles.items()}
    edges = [
        (profile_id, feature_id)
        for profile_id in sorted(mutable)
        for feature_id in sorted(mutable[profile_id])
    ]
    before_rows = {key: len(value) for key, value in mutable.items()}
    before_columns = Counter(
        feature for feature_set in mutable.values() for feature in feature_set
    )

    accepted = pipeline._attempt_degree_preserving_edge_swaps(
        mutable, edges, random.Random(19), attempts=500
    )

    assert accepted > 0
    assert {key: len(value) for key, value in mutable.items()} == before_rows
    assert Counter(
        feature for feature_set in mutable.values() for feature in feature_set
    ) == before_columns


def test_leave_one_out_identifies_the_two_singleton_collision_rows() -> None:
    pipeline = _load_module()
    profiles = {
        "singleton-a": {"popular"},
        "singleton-b": {"popular"},
        "larger-a": {"x", "y"},
        "larger-b": {"u", "v"},
    }

    result = pipeline.analyze_threshold_collapse_leave_one_out(
        profiles, delta=0.1
    )

    assert result["influential_profile_count"] == 2
    assert result["influential_profile_ids"] == [
        "singleton-a",
        "singleton-b",
    ]
    assert result["influential_shared_feature_ids"] == ["popular"]
    assert result["minimum_leave_one_out_collapse_pp"] == 0.0


def test_source_native_retirement_flags_cover_attack_and_capec() -> None:
    pipeline = _load_module()

    assert pipeline.is_deprecated_or_revoked({"x_mitre_deprecated": True})
    assert pipeline.is_deprecated_or_revoked({"revoked": True})
    assert pipeline.is_deprecated_or_revoked({"x_capec_status": "Deprecated"})
    assert pipeline.is_deprecated_or_revoked({"x_capec_status": " obsolete "})
    assert not pipeline.is_deprecated_or_revoked({"x_capec_status": "Stable"})


def test_active_relationship_count_requires_two_active_endpoints() -> None:
    pipeline = _load_module()
    relationships = [
        {"source_ref": "a", "target_ref": "b"},
        {"source_ref": "a", "target_ref": "retired"},
        {"source_ref": "missing", "target_ref": "b"},
    ]

    assert pipeline.count_relationships_with_active_endpoints(
        relationships, {"a": {}, "b": {}}
    ) == 1


def test_convergence_rate_excludes_single_signal_rows(tmp_path: Path) -> None:
    pipeline = _load_module()
    pipeline.AUDIT_DIR = tmp_path
    facts = [
        {"campaign_id": "agree", "campaign_name": "Agree"},
        {"campaign_id": "conflict", "campaign_name": "Conflict"},
        {"campaign_id": "single", "campaign_name": "Single"},
    ]
    environments = [
        {
            "campaign_id": "agree",
            "technique_platforms": "Windows;Linux",
            "software_platforms": "Linux",
            "tactic_implied": "",
            "description_mined": "",
        },
        {
            "campaign_id": "conflict",
            "technique_platforms": "Windows",
            "software_platforms": "Linux",
            "tactic_implied": "",
            "description_mined": "",
        },
        {
            "campaign_id": "single",
            "technique_platforms": "Windows",
            "software_platforms": "",
            "tactic_implied": "",
            "description_mined": "",
        },
    ]

    result = pipeline.analyze_evidence_convergence(facts, environments)

    assert result["total_campaigns"] == 3
    assert result["assessable_campaign_count"] == 2
    assert result["assessable_convergence_count"] == 1
    assert result["assessable_divergence_count"] == 1
    assert result["assessable_convergence_rate_pct"] == 50.0
