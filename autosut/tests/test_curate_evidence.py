from scripts.curate_evidence import RunClassification, _designate_goldens


def _candidate(run_id: str) -> RunClassification:
    return RunClassification(
        run_id=run_id,
        campaign_id="0.shadowray",
        path=f"release/evidence/{run_id}",
        techniques_total=10,
        techniques_success=10,
        has_manifest=True,
        has_summary=True,
        has_rubric=True,
        has_composition=True,
        has_teardown=True,
        classification="golden_candidate",
        reason="test fixture",
    )


def test_designate_goldens_uses_timestamp_suffix_not_label() -> None:
    candidates = [
        _candidate("0.shadowray_verifysurr_20260728_124217"),
        _candidate("0.shadowray_20260731_223638"),
    ]

    assert _designate_goldens(candidates)["0.shadowray"] == (
        "0.shadowray_20260731_223638"
    )
