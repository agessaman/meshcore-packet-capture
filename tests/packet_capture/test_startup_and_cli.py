"""Startup, env loading, and CLI behavior tests for packet capture."""
from __future__ import annotations

import logging
import os
import signal
import sys
from pathlib import Path

import pytest

import meshcore_packet_capture.packet_capture as pc


@pytest.mark.asyncio
async def test_main_prints_unit_before_environment_or_capture(monkeypatch, capsys):
    def unexpected(*args, **kwargs):
        pytest.fail('unit generation started capture or loaded configuration')

    monkeypatch.setattr(pc, 'init_environment', unexpected)
    monkeypatch.setattr(pc, 'PacketCapture', unexpected)
    monkeypatch.setattr(sys, 'argv', ['packet_capture.py', '--print-systemd-unit', '--user'])
    await pc.main()
    result = capsys.readouterr()
    assert result.out.startswith('[Unit]\n')
    assert result.err == ''


def test_load_env_files_uses_explicit_dir_and_local_override(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    env_dir = tmp_path / "envdir"
    env_dir.mkdir(parents=True, exist_ok=True)
    (env_dir / ".env").write_text("PACKETCAPTURE_ORIGIN=FROM_ENV\nPACKETCAPTURE_FOO=1\n")
    (env_dir / ".env.local").write_text("PACKETCAPTURE_ORIGIN=FROM_LOCAL\n")

    monkeypatch.delenv("PACKETCAPTURE_ORIGIN", raising=False)
    monkeypatch.delenv("PACKETCAPTURE_FOO", raising=False)
    monkeypatch.setenv("MESHCORE_PACKETCAPTURE_ENV_DIR", str(env_dir))

    loaded = pc.load_env_files()
    assert loaded["PACKETCAPTURE_ORIGIN"] == "FROM_LOCAL"
    assert os.environ["PACKETCAPTURE_ORIGIN"] == "FROM_LOCAL"
    assert os.environ["PACKETCAPTURE_FOO"] == "1"


def test_load_env_files_does_not_override_existing_env(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    env_dir = tmp_path / "envdir"
    env_dir.mkdir(parents=True, exist_ok=True)
    (env_dir / ".env").write_text("PACKETCAPTURE_ORIGIN=FROM_FILE\n")

    monkeypatch.setenv("MESHCORE_PACKETCAPTURE_ENV_DIR", str(env_dir))
    monkeypatch.setenv("PACKETCAPTURE_ORIGIN", "FROM_PROCESS")

    pc.load_env_files()
    assert os.environ["PACKETCAPTURE_ORIGIN"] == "FROM_PROCESS"


def test_init_environment_keeps_existing_env_over_toml(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg = tmp_path / "cfg.toml"
    cfg.write_text('[general]\niata = "FILE"\n')
    monkeypatch.delenv("MESHCORE_PACKETCAPTURE_ENV_DIR", raising=False)
    monkeypatch.setenv("PACKETCAPTURE_IATA", "PROCESS")

    pc.init_environment([str(cfg)])
    assert os.environ["PACKETCAPTURE_IATA"] == "PROCESS"


@pytest.mark.parametrize("user_config", [False, True])
@pytest.mark.parametrize("explicit_configs", [False, True])
@pytest.mark.asyncio
async def test_main_parses_repeatable_config_and_no_mqtt(
    monkeypatch: pytest.MonkeyPatch, user_config: bool, explicit_configs: bool,
) -> None:
    init_calls: list[tuple[list[str] | None, bool]] = []
    created: list[object] = []

    class _DummyCapture:
        def __init__(self, output_file=None, verbose=False, debug=False, enable_mqtt=True, shutdown_event=None):
            self.output_file = output_file
            self.verbose = verbose
            self.debug = debug
            self.enable_mqtt = enable_mqtt
            self.shutdown_event = shutdown_event
            self.should_exit = False
            self.logger = logging.getLogger("dummy")
            created.append(self)

        async def start(self) -> None:
            return

        async def stop(self) -> None:
            return

    monkeypatch.setattr(pc, "init_environment", lambda cfg=None, **kw: init_calls.append((cfg, kw["user_config"])))
    monkeypatch.setattr(pc, "PacketCapture", _DummyCapture)
    monkeypatch.setattr(signal, "signal", lambda *_a, **_k: None)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "packet_capture.py",
            *(["--config", "a.toml", "--config", "b.toml"] if explicit_configs else []),
            "--no-mqtt",
            "--verbose",
            *(["--user-config"] if user_config else []),
        ],
    )

    await pc.main()

    assert init_calls == [(["a.toml", "b.toml"] if explicit_configs else None, user_config)]
    assert len(created) == 1
    assert created[0].enable_mqtt is False
    assert created[0].verbose is True


@pytest.mark.parametrize("process_value", [None, "PROCESS"])
def test_selected_tree_keeps_env_precedence_and_legacy_env_directory(tmp_path, monkeypatch, process_value):
    legacy = tmp_path / "legacy"
    legacy.mkdir()
    (legacy / ".env").write_text("PACKETCAPTURE_IATA=ENV\nPACKETCAPTURE_CONNECTION_TYPE=tcp\n")
    (legacy / ".env.local").write_text(
        "PACKETCAPTURE_IATA=LOCAL\nPACKETCAPTURE_TCP_HOST=legacy.example\n"
        "PACKETCAPTURE_CONFIG_DIR=/invalid/legacy/path\n"
    )
    selected = tmp_path / "selected"
    selected.mkdir()
    (selected / "config.toml").write_text('[general]\niata="TOML"\n')
    monkeypatch.setenv("MESHCORE_PACKETCAPTURE_ENV_DIR", str(legacy))
    monkeypatch.setenv("PACKETCAPTURE_CONFIG_DIR", str(selected))
    monkeypatch.setattr(pc, "_environment_initialized", False)
    if process_value:
        monkeypatch.setenv("PACKETCAPTURE_IATA", process_value)
    pc.init_environment(user_config=True)
    assert os.environ["PACKETCAPTURE_IATA"] == (process_value or "TOML")
    assert os.environ["PACKETCAPTURE_CONNECTION_TYPE"] == "tcp"
    assert os.environ["PACKETCAPTURE_TCP_HOST"] == "legacy.example"


def test_directory_selector_can_come_from_env_local(tmp_path, monkeypatch):
    selected = tmp_path / "selected"
    selected.mkdir()
    (selected / "config.toml").write_text('[general]\niata="SELECTED"\n')
    legacy = tmp_path / "legacy"
    legacy.mkdir()
    (legacy / ".env.local").write_text(f"PACKETCAPTURE_CONFIG_DIR={selected}\n")
    monkeypatch.setenv("MESHCORE_PACKETCAPTURE_ENV_DIR", str(legacy))
    monkeypatch.setattr(pc, "_environment_initialized", False)
    pc.init_environment()
    assert os.environ["PACKETCAPTURE_IATA"] == "SELECTED"
