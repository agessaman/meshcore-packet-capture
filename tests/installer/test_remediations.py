"""Tests for installer UX/robustness remediations.

Covers: non-interactive prompt fallback, reading existing custom-broker values
on reconfigure, shared owner/email across token presets, and macOS BLE
LaunchAgent placement.
"""
from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

from installer import config as cfg
from installer import system as sysmod
from installer import ui


def _seed_user_toml(config_dir: Path) -> Path:
    config_d = config_dir / "config.d"
    config_d.mkdir(parents=True)
    dest = cfg.user_config_path(config_dir)
    cfg.write_user_toml_base(
        str(dest), "SEA", "agessaman/x", "main",
        {"type": "serial", "serial_device": "/dev/ttyUSB0"},
    )
    return dest


# --- Non-interactive prompt guard ------------------------------------------

def test_prompts_fall_back_to_default_without_tty(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(ui, "_interactive_input_stream", lambda: None)
    monkeypatch.setattr(ui, "_NONINTERACTIVE_WARNED", False, raising=False)
    assert ui.prompt_input("Server", "mqtt.example.com") == "mqtt.example.com"
    assert ui.prompt_yes_no("Proceed?", "y") is True
    assert ui.prompt_yes_no("Proceed?", "n") is False


# --- Reading existing custom-broker values ---------------------------------

def test_custom_broker_fields_reads_existing(tmp_path: Path):
    config_dir = tmp_path / "etc"
    dest = _seed_user_toml(config_dir)
    cfg.append_custom_broker_toml(
        str(dest), "custom-1", "mqtt.example.com", "8883", "websockets",
        "true", "false", "password", username="u", password="p",
    )
    assert cfg._user_custom_broker_names(config_dir) == ["custom-1"]
    fields = cfg._custom_broker_fields(config_dir, "custom-1")
    assert fields["server"] == "mqtt.example.com"
    assert fields["port"] == "8883"
    assert fields["transport"] == "websockets"
    assert fields["use_tls"] == "true"
    assert fields["tls_verify"] == "false"
    assert fields["auth_method"] == "password"
    assert fields["username"] == "u"


def test_edit_custom_broker_replaces_not_duplicates(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    config_dir = tmp_path / "etc"
    dest = _seed_user_toml(config_dir)
    cfg.append_custom_broker_toml(
        str(dest), "custom-1", "old.example.com", "1883", "tcp",
        "false", "true", "none",
    )

    # Simulate accepting the new server, keeping defaults for everything else.
    inputs = iter(["new.example.com", "1883", "3"])  # server, port, auth choice (none)
    monkeypatch.setattr(cfg, "prompt_input", lambda *a, **k: next(inputs))
    monkeypatch.setattr(cfg, "prompt_yes_no", lambda *a, **k: False)

    cfg.configure_custom_broker(0, str(config_dir), existing_name="custom-1")

    data = tomllib.loads(dest.read_text())
    brokers = [b for b in data["broker"] if b.get("name") == "custom-1"]
    assert len(brokers) == 1  # replaced, not duplicated
    assert brokers[0]["server"] == "new.example.com"


def test_existing_owner_email_reused_as_default(tmp_path: Path):
    config_dir = tmp_path / "etc"
    dest = _seed_user_toml(config_dir)
    cfg.append_custom_broker_toml(
        str(dest), "custom-1", "mqtt.example.com", "443", "websockets",
        "true", "true", "token", audience="aud", owner="B" * 64, email="me@example.com",
    )
    owner, email = cfg._existing_owner_email(config_dir)
    assert owner == "B" * 64
    assert email == "me@example.com"


# --- macOS BLE LaunchAgent placement ---------------------------------------

def test_launchd_uses_agent_for_ble(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    install_dir = tmp_path / "opt"
    install_dir.mkdir()
    config_dir = tmp_path / "etc"
    config_d = config_dir / "config.d"
    config_d.mkdir(parents=True)
    (config_d / "99-user.toml").write_text('[capture]\nconnection_type = "ble"\n')

    home = tmp_path / "home"
    home.mkdir()

    class _Pw:
        pw_dir = str(home)
        pw_uid = 501

    monkeypatch.setenv("SUDO_USER", "alice")
    monkeypatch.setattr(sysmod.pwd, "getpwnam", lambda name: _Pw())
    monkeypatch.setattr(sysmod.shutil, "chown", lambda *a, **k: None)
    monkeypatch.setattr(sysmod.os, "chmod", lambda *a, **k: None)
    calls: list[list[str]] = []
    monkeypatch.setattr(sysmod, "run_cmd", lambda cmd, **k: calls.append(cmd) or None)

    ok = sysmod.install_launchd_service(str(install_dir), str(config_dir), auto=True)
    assert ok is True

    plist = home / "Library" / "LaunchAgents" / "com.meshcore.meshcore_packet_capture.plist"
    assert plist.exists()
    # Logs point at the user's home, not /var/log.
    assert str(home / "Library" / "Logs") in plist.read_text()
    # Loaded into the user's GUI domain.
    assert any(c[:3] == ["launchctl", "bootstrap", "gui/501"] for c in calls)


def test_launchd_uses_daemon_for_serial(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    install_dir = tmp_path / "opt"
    install_dir.mkdir()
    config_dir = tmp_path / "etc"
    (config_dir / "config.d").mkdir(parents=True)
    (config_dir / "config.d" / "99-user.toml").write_text('[capture]\nconnection_type = "serial"\n')

    dest = tmp_path / "out.plist"
    real_path = sysmod.Path
    monkeypatch.setattr(
        sysmod, "Path",
        lambda v: dest if str(v).startswith("/Library/LaunchDaemons/") else real_path(v),
    )
    monkeypatch.setattr(sysmod.shutil, "chown", lambda *a, **k: None)
    monkeypatch.setattr(sysmod.os, "chmod", lambda *a, **k: None)
    calls: list[list[str]] = []
    monkeypatch.setattr(sysmod, "run_cmd", lambda cmd, **k: calls.append(cmd) or None)

    ok = sysmod.install_launchd_service(str(install_dir), str(config_dir), auto=True)
    assert ok is True
    assert any(c[:3] == ["launchctl", "bootstrap", "system"] for c in calls)
