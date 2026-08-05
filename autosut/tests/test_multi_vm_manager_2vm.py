from pathlib import Path

import multi_vm_manager_2vm as manager


def test_overall_status_ready() -> None:
    rows = [
        {"process_up": True, "ssh_up": True},
        {"process_up": True, "ssh_up": True},
    ]
    assert manager._overall_status(rows) == "ready"


def test_overall_status_degraded() -> None:
    rows = [
        {"process_up": True, "ssh_up": True},
        {"process_up": True, "ssh_up": False},
    ]
    assert manager._overall_status(rows) == "degraded"


def test_overall_status_stopped() -> None:
    rows = [
        {"process_up": False, "ssh_up": False},
        {"process_up": False, "ssh_up": False},
    ]
    assert manager._overall_status(rows) == "stopped"


def test_read_pid_handles_missing_and_value(tmp_path: Path) -> None:
    missing = tmp_path / "missing.pid"
    assert manager._read_pid(missing) is None

    pid_file = tmp_path / "vm.pid"
    pid_file.write_text("12345")
    assert manager._read_pid(pid_file) == 12345
