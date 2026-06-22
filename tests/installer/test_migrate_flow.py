"""Tests for the legacy-install detection / migration sentinel helpers."""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

import installer.migrate_cmd as mc


def test_detect_old_installation_found(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    old = tmp_path / ".meshcore-packet-capture"
    old.mkdir()
    (old / "packet_capture.py").write_text("# legacy launcher\n")
    monkeypatch.setattr(mc, "_real_user_home", lambda: tmp_path)
    assert mc.detect_old_installation() == str(old)


def test_detect_old_installation_absent(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.setattr(mc, "_real_user_home", lambda: tmp_path)
    assert mc.detect_old_installation() is None


def test_detect_requires_launcher_marker(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    # Directory exists but has no packet_capture.py -> not a legacy install.
    (tmp_path / ".meshcore-packet-capture").mkdir()
    monkeypatch.setattr(mc, "_real_user_home", lambda: tmp_path)
    assert mc.detect_old_installation() is None


def test_parse_env_file_strips_quotes_and_inline_comments(tmp_path: Path) -> None:
    env_file = tmp_path / ".env.local"
    env_file.write_text(
        'PACKETCAPTURE_IATA="SEA"  # home airport\n'
        "PACKETCAPTURE_LOG_LEVEL='DEBUG'\n"
        "PACKETCAPTURE_MQTT1_PASSWORD=abc#123\n"
    )

    assert mc.parse_env_file(str(env_file)) == {
        "PACKETCAPTURE_IATA": "SEA",
        "PACKETCAPTURE_LOG_LEVEL": "DEBUG",
        "PACKETCAPTURE_MQTT1_PASSWORD": "abc#123",
    }


def test_migration_sentinel_roundtrip(tmp_path: Path):
    old = tmp_path / "old"
    old.mkdir()
    assert mc.is_already_migrated(str(old)) is False
    mc.mark_migrated(str(old), "/opt/meshcore-packet-capture")
    assert mc.is_already_migrated(str(old)) is True
    assert "/opt/meshcore-packet-capture" in (old / mc._MIGRATED_SENTINEL).read_text()


def test_run_migrate_writes_config_before_service_cleanup(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    old = tmp_path / ".meshcore-packet-capture"
    old.mkdir()
    (old / "packet_capture.py").write_text("# legacy launcher\n")
    (old / ".env.local").write_text(
        "PACKETCAPTURE_IATA=SEA\n"
        "PACKETCAPTURE_MQTT1_ENABLED=true\n"
        "PACKETCAPTURE_MQTT1_SERVER=mqtt.example.com\n"
    )
    config_dir = tmp_path / "etc"
    ctx = SimpleNamespace(
        install_dir="/opt/meshcore-packet-capture",
        config_dir=str(config_dir),
        repo_dir="",
        local_install="",
        repo="agessaman/meshcore-packet-capture",
        branch="main",
    )
    events: list[str] = []

    monkeypatch.setattr(mc, "detect_old_installation", lambda: str(old))
    monkeypatch.setattr(mc, "prompt_yes_no", lambda *_a, **_k: True)
    monkeypatch.setattr(mc, "_stop_old_services", lambda _old: events.append("stop"))
    monkeypatch.setattr(mc, "_cleanup_old_service_units", lambda: events.append("cleanup"))

    assert mc.run_migrate(ctx) is True

    migrated = config_dir / "config.d" / "99-user.toml"
    assert migrated.exists()
    assert "[[broker]]" in migrated.read_text()
    assert events == ["stop", "cleanup"]
    assert mc.is_already_migrated(str(old)) is True


def test_run_migrate_without_user_config_leaves_legacy_service_alone(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    old = tmp_path / ".meshcore-packet-capture"
    old.mkdir()
    (old / "packet_capture.py").write_text("# legacy launcher\n")
    config_dir = tmp_path / "etc"
    ctx = SimpleNamespace(
        install_dir="/opt/meshcore-packet-capture",
        config_dir=str(config_dir),
        repo_dir="",
        local_install="",
        repo="agessaman/meshcore-packet-capture",
        branch="main",
    )
    events: list[str] = []

    monkeypatch.setattr(mc, "detect_old_installation", lambda: str(old))
    monkeypatch.setattr(mc, "prompt_yes_no", lambda *_a, **_k: True)
    monkeypatch.setattr(mc, "_stop_old_services", lambda _old: events.append("stop"))
    monkeypatch.setattr(mc, "_cleanup_old_service_units", lambda: events.append("cleanup"))

    assert mc.run_migrate(ctx) is False

    assert not (config_dir / "config.d" / "99-user.toml").exists()
    assert events == []
    assert mc.is_already_migrated(str(old)) is False


def test_run_migrate_backs_up_existing_user_toml(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    old = tmp_path / ".meshcore-packet-capture"
    old.mkdir()
    (old / "packet_capture.py").write_text("# legacy launcher\n")
    (old / ".env.local").write_text("PACKETCAPTURE_IATA=SEA\n")
    config_dir = tmp_path / "etc"
    config_d = config_dir / "config.d"
    config_d.mkdir(parents=True)
    user_toml = config_d / "99-user.toml"
    user_toml.write_text("[general]\niata = \"OLD\"\n")
    ctx = SimpleNamespace(
        install_dir="/opt/meshcore-packet-capture",
        config_dir=str(config_dir),
        repo_dir="",
        local_install="",
        repo="agessaman/meshcore-packet-capture",
        branch="main",
    )

    monkeypatch.setattr(mc, "detect_old_installation", lambda: str(old))
    monkeypatch.setattr(mc, "prompt_yes_no", lambda *_a, **_k: True)
    monkeypatch.setattr(mc, "_stop_old_services", lambda _old: None)
    monkeypatch.setattr(mc, "_cleanup_old_service_units", lambda: None)

    assert mc.run_migrate(ctx) is True

    assert (config_d / "99-user.toml.backup").read_text() == "[general]\niata = \"OLD\"\n"
    assert 'iata = "SEA"' in user_toml.read_text()


def test_macos_cleanup_includes_main_branch_launchagent(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    home = tmp_path / "home"
    launch_agents = home / "Library" / "LaunchAgents"
    launch_agents.mkdir(parents=True)
    old_plist = launch_agents / "com.meshcore.packet-capture.plist"
    old_plist.write_text("<plist/>")

    monkeypatch.setattr(mc.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(mc, "_real_user_home", lambda: home)
    monkeypatch.setattr(mc, "run_cmd", lambda *_a, **_k: None)

    mc._cleanup_old_service_units()

    assert not old_plist.exists()
