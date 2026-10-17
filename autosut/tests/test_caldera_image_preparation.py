"""Pinned Caldera image preparation is explicit and measurable."""

from __future__ import annotations

import subprocess

from infrastructure.caldera_instance import CALDERA_IMAGE, CalderaInstance


def test_prepare_image_uses_an_existing_digest(monkeypatch) -> None:
    commands: list[list[str]] = []

    def fake_run(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    timestamps = iter((10.0, 10.25))
    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr("infrastructure.caldera_instance.time.monotonic", lambda: next(timestamps))

    cache_hit, seconds = CalderaInstance.prepare_image()

    assert cache_hit is True
    assert seconds == 0.25
    assert commands == [["docker", "image", "inspect", CALDERA_IMAGE]]


def test_prepare_image_pulls_a_missing_digest(monkeypatch) -> None:
    commands: list[list[str]] = []

    def fake_run(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        returncode = 1 if command[1:3] == ["image", "inspect"] else 0
        return subprocess.CompletedProcess(command, returncode, "", "")

    timestamps = iter((20.0, 23.5))
    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr("infrastructure.caldera_instance.time.monotonic", lambda: next(timestamps))

    cache_hit, seconds = CalderaInstance.prepare_image()

    assert cache_hit is False
    assert seconds == 3.5
    assert commands == [
        ["docker", "image", "inspect", CALDERA_IMAGE],
        ["docker", "pull", "--platform", "linux/amd64", CALDERA_IMAGE],
    ]
