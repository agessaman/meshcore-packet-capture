"""Tests for installer.system.install_launchd_service rendering (no root needed)."""
from __future__ import annotations

from pathlib import Path

import pytest

from installer import system as sysmod


def _stub_side_effects(monkeypatch: pytest.MonkeyPatch) -> list:
    """Neutralize privileged side effects; return the captured run_cmd calls list."""
    calls: list[list[str]] = []
    monkeypatch.setattr(sysmod.shutil, "chown", lambda *a, **k: None)
    monkeypatch.setattr(sysmod.os, "chmod", lambda *a, **k: None)
    monkeypatch.setattr(sysmod, "run_cmd", lambda cmd, **k: calls.append(cmd) or None)
    return calls


def test_launchd_copies_template_when_present(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    install_dir = tmp_path / "opt"
    install_dir.mkdir()
    (install_dir / "com.meshcore.meshcore_packet_capture.plist").write_text("<plist/>")

    copied: list[tuple[str, str]] = []
    monkeypatch.setattr(sysmod.shutil, "copy2", lambda src, dst: copied.append((src, dst)))
    calls = _stub_side_effects(monkeypatch)

    ok = sysmod.install_launchd_service(str(install_dir), str(tmp_path / "etc"), auto=True)
    assert ok is True
    assert copied[0][1] == "/Library/LaunchDaemons/com.meshcore.meshcore_packet_capture.plist"
    assert ["launchctl", "load", copied[0][1]] in calls


def test_launchd_generates_plist_when_no_template(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    install_dir = tmp_path / "opt"
    install_dir.mkdir()
    dest = tmp_path / "out.plist"

    real_path = sysmod.Path

    def _fake_path(value):
        if str(value).startswith("/Library/LaunchDaemons/"):
            return dest
        return real_path(value)

    monkeypatch.setattr(sysmod, "Path", _fake_path)
    _stub_side_effects(monkeypatch)

    ok = sysmod.install_launchd_service(str(install_dir), str(tmp_path / "etc"), auto=True)
    assert ok is True
    content = dest.read_text()
    assert "com.meshcore.meshcore_packet_capture" in content
    assert "-m" in content and "meshcore_packet_capture" in content
    assert f"{install_dir}/venv/bin/python3" in content
