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


class _FakeProc:
    def __init__(self, returncode=0, stdout=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = ""


def test_restart_launchd_ble_kickstarts_user_agent(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    home = tmp_path / "home"
    (home / "Library" / "LaunchAgents").mkdir(parents=True)
    plist = home / "Library" / "LaunchAgents" / "com.meshcore.meshcore_packet_capture.plist"
    plist.write_text("<plist/>")

    monkeypatch.setattr(sysmod, "_user_connection_is_ble", lambda cfg: True)
    monkeypatch.setattr(sysmod, "_console_user", lambda: "alice")
    monkeypatch.setattr(
        sysmod.pwd, "getpwnam",
        lambda u: type("PW", (), {"pw_dir": str(home), "pw_uid": 501})(),
    )
    monkeypatch.setattr(sysmod, "check_service_health", lambda *a, **k: None)

    calls: list[list[str]] = []
    monkeypatch.setattr(sysmod, "run_cmd", lambda cmd, **k: calls.append(cmd) or _FakeProc(0))

    sysmod.restart_launchd_service(str(tmp_path / "etc"))

    assert ["launchctl", "kickstart", "-k", "gui/501/com.meshcore.meshcore_packet_capture"] in calls


def test_restart_launchd_daemon_stop_start(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    import time as _time
    monkeypatch.setattr(sysmod, "_user_connection_is_ble", lambda cfg: False)
    monkeypatch.setattr(sysmod, "check_service_health", lambda *a, **k: None)
    monkeypatch.setattr(_time, "sleep", lambda *a: None)

    calls: list[list[str]] = []

    def _run(cmd, **k):
        calls.append(cmd)
        if cmd[:2] == ["launchctl", "list"]:
            return _FakeProc(0, "com.meshcore.meshcore_packet_capture\t-\t0")
        return _FakeProc(0)

    monkeypatch.setattr(sysmod, "run_cmd", _run)

    sysmod.restart_launchd_service(str(tmp_path / "etc"))

    assert ["launchctl", "stop", "com.meshcore.meshcore_packet_capture"] in calls
    assert ["launchctl", "start", "com.meshcore.meshcore_packet_capture"] in calls


def test_launchd_present_true_for_user_agent(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    home = tmp_path / "home"
    (home / "Library" / "LaunchAgents").mkdir(parents=True)
    (home / "Library" / "LaunchAgents" / "com.meshcore.meshcore_packet_capture.plist").write_text("<plist/>")

    monkeypatch.setattr(sysmod, "_user_connection_is_ble", lambda cfg: True)
    monkeypatch.setattr(sysmod, "_console_user", lambda: "alice")
    monkeypatch.setattr(
        sysmod.pwd, "getpwnam",
        lambda u: type("PW", (), {"pw_dir": str(home), "pw_uid": 501})(),
    )
    # launchctl should not even be consulted once the agent plist is found.
    monkeypatch.setattr(sysmod, "run_cmd", lambda *a, **k: pytest.fail("should not run launchctl"))

    assert sysmod.launchd_service_present(str(tmp_path / "etc")) is True


def test_launchd_present_true_for_loaded_daemon(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.setattr(sysmod, "_user_connection_is_ble", lambda cfg: False)
    monkeypatch.setattr(
        sysmod, "run_cmd",
        lambda *a, **k: _FakeProc(0, "com.meshcore.meshcore_packet_capture\t-\t0"),
    )
    assert sysmod.launchd_service_present(str(tmp_path / "etc")) is True


def test_launchd_present_false_when_nothing_installed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.setattr(sysmod, "_user_connection_is_ble", lambda cfg: False)
    monkeypatch.setattr(sysmod, "run_cmd", lambda *a, **k: _FakeProc(0, "other.service\t-\t0"))
    assert sysmod.launchd_service_present(str(tmp_path / "etc")) is False


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
