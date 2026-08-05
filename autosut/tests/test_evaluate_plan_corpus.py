from scripts.evaluate_plan_corpus import evaluate_corpus


def test_empty_plan_directory_is_reported_without_execution_claim(tmp_path) -> None:
    report = evaluate_corpus(
        tmp_path / "plans",
        materializable_platforms={"Linux"},
        constraints_dir=tmp_path / "constraints",
    )
    assert report["plan_count"] == 0
    assert report["evaluation_claim"] == (
        "platform_constraint_and_blueprint_skeleton_coverage_"
        "not_replay_ready_sut_or_campaign_execution"
    )
