from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = PROJECT_ROOT / "scripts" / "run_all_lab_campaigns.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("run_all_lab_campaigns", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_campaign_subset_writes_canonical_tsv_and_json(monkeypatch, tmp_path: Path) -> None:
    module = _load_module()

    monkeypatch.setattr(module, "_list_lab_campaigns", lambda: ["0.c0011", "0.c0015"])

    class StubRunLabModule:
        @staticmethod
        def main(argv):
            if argv == ["--campaign", "0.c0015", "--provider", "qemu"]:
                raise RuntimeError("expected failure")
            return 0

    monkeypatch.setattr(module, "_load_run_lab_module", lambda: StubRunLabModule())

    output_path = tmp_path / "full_lab_batch_test.tsv"
    exit_code = module.main(
        [
            "--campaign",
            "0.c0011",
            "--campaign",
            "0.c0015",
            "--provider",
            "qemu",
            "--output",
            str(output_path),
        ]
    )

    assert exit_code == 1
    assert output_path.read_text(encoding="utf-8").splitlines() == [
        "campaign\tstatus\tnotes",
        "0.c0011\tPASS\t",
        "0.c0015\tFAIL\tRuntimeError: expected failure",
    ]
    assert output_path.with_suffix(".json").exists()


def test_unknown_campaign_exits_with_error(monkeypatch) -> None:
    module = _load_module()
    monkeypatch.setattr(module, "_list_lab_campaigns", lambda: ["0.c0011"])

    try:
        module.main(["--campaign", "0.unknown"])
    except SystemExit as error:
        assert "Unknown lab campaign(s): 0.unknown" in str(error)
    else:
        raise AssertionError("SystemExit expected for unknown campaign")


def test_reuse_lab_passes_keep_lab_and_destroys_once(monkeypatch, tmp_path: Path) -> None:
    module = _load_module()
    monkeypatch.setattr(module, "_list_lab_campaigns", lambda: ["0.c0011", "0.c0015"])
    monkeypatch.setattr(
        module,
        "_validate_reuse_compatibility",
        lambda campaigns: ("caldera", "attacker", "target-linux-1"),
    )

    calls: list[list[str]] = []
    destroy_calls: list[str] = []

    class StubRunLabModule:
        @staticmethod
        def main(argv):
            calls.append(list(argv))
            return 0

    monkeypatch.setattr(module, "_load_run_lab_module", lambda: StubRunLabModule())
    monkeypatch.setattr(module, "_destroy_reused_lab", lambda campaign_id: destroy_calls.append(campaign_id))

    output_path = tmp_path / "full_lab_batch_reuse.tsv"
    exit_code = module.main(
        [
            "--campaign",
            "0.c0011",
            "--campaign",
            "0.c0015",
            "--provider",
            "qemu",
            "--reuse-lab",
            "--output",
            str(output_path),
        ]
    )

    assert exit_code == 0
    assert calls == [
        ["--campaign", "0.c0011", "--provider", "qemu", "--keep-lab"],
        ["--campaign", "0.c0015", "--provider", "qemu", "--keep-lab"],
    ]
    assert destroy_calls == ["0.c0011"]


def test_reuse_lab_rejects_incompatible_topologies(monkeypatch) -> None:
    module = _load_module()
    monkeypatch.setattr(module, "_list_lab_campaigns", lambda: ["0.c0011", "0.shadowray"])

    def fake_validate(campaigns):
        raise SystemExit("Incompatible lab topologies for --reuse-lab")

    monkeypatch.setattr(module, "_validate_reuse_compatibility", fake_validate)

    try:
        module.main(["--campaign", "0.c0011", "--campaign", "0.shadowray", "--reuse-lab"])
    except SystemExit as error:
        assert "Incompatible lab topologies for --reuse-lab" in str(error)
    else:
        raise AssertionError("SystemExit expected for incompatible reuse request")


def test_reuse_lab_still_cleans_up_after_failure(monkeypatch, tmp_path: Path) -> None:
    module = _load_module()
    monkeypatch.setattr(module, "_list_lab_campaigns", lambda: ["0.c0011", "0.c0015"])
    monkeypatch.setattr(
        module,
        "_validate_reuse_compatibility",
        lambda campaigns: ("caldera", "attacker", "target-linux-1"),
    )

    calls: list[list[str]] = []
    destroy_calls: list[str] = []

    class StubRunLabModule:
        @staticmethod
        def main(argv):
            calls.append(list(argv))
            if argv[1] == "0.c0015":
                raise RuntimeError("expected failure")
            return 0

    monkeypatch.setattr(module, "_load_run_lab_module", lambda: StubRunLabModule())
    monkeypatch.setattr(module, "_destroy_reused_lab", lambda campaign_id: destroy_calls.append(campaign_id))

    output_path = tmp_path / "full_lab_batch_reuse_failure.tsv"
    exit_code = module.main(
        [
            "--campaign",
            "0.c0011",
            "--campaign",
            "0.c0015",
            "--provider",
            "qemu",
            "--reuse-lab",
            "--output",
            str(output_path),
        ]
    )

    assert exit_code == 1
    assert calls == [
        ["--campaign", "0.c0011", "--provider", "qemu", "--keep-lab"],
        ["--campaign", "0.c0015", "--provider", "qemu", "--keep-lab"],
    ]
    assert destroy_calls == ["0.c0011"]
    assert output_path.read_text(encoding="utf-8").splitlines() == [
        "campaign\tstatus\tnotes",
        "0.c0011\tPASS\t",
        "0.c0015\tFAIL\tRuntimeError: expected failure",
    ]


def test_assume_lab_running_requires_reuse_lab(monkeypatch) -> None:
    module = _load_module()
    monkeypatch.setattr(module, "_list_lab_campaigns", lambda: ["0.c0011"])

    try:
        module.main(["--campaign", "0.c0011", "--assume-lab-running"])
    except SystemExit as error:
        assert "--assume-lab-running requires --reuse-lab" in str(error)
    else:
        raise AssertionError("SystemExit expected when reuse mode is absent")


def test_assume_lab_running_only_applies_to_first_campaign(monkeypatch, tmp_path: Path) -> None:
    module = _load_module()
    monkeypatch.setattr(module, "_list_lab_campaigns", lambda: ["0.c0011", "0.c0015"])
    monkeypatch.setattr(
        module,
        "_validate_reuse_compatibility",
        lambda campaigns: ("caldera", "attacker", "target-linux-1"),
    )

    calls: list[list[str]] = []
    destroy_calls: list[str] = []

    class StubRunLabModule:
        @staticmethod
        def main(argv):
            calls.append(list(argv))
            return 0

    monkeypatch.setattr(module, "_load_run_lab_module", lambda: StubRunLabModule())
    monkeypatch.setattr(module, "_destroy_reused_lab", lambda campaign_id: destroy_calls.append(campaign_id))

    output_path = tmp_path / "full_lab_batch_warm.tsv"
    exit_code = module.main(
        [
            "--campaign",
            "0.c0011",
            "--campaign",
            "0.c0015",
            "--provider",
            "qemu",
            "--reuse-lab",
            "--assume-lab-running",
            "--output",
            str(output_path),
        ]
    )

    assert exit_code == 0
    assert calls == [
        ["--campaign", "0.c0011", "--provider", "qemu", "--keep-lab", "--assume-lab-running"],
        ["--campaign", "0.c0015", "--provider", "qemu", "--keep-lab"],
    ]
    assert destroy_calls == ["0.c0011"]
