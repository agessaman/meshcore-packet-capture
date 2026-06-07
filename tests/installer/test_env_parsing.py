"""Tests for legacy .env parsing: installer.migrate_cmd.parse_env_file and the
runtime loader in meshcore_packet_capture.packet_capture.load_env_files."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from installer.migrate_cmd import parse_env_file


def test_parse_basic_keyvalue(tmp_path: Path):
    f = tmp_path / ".env"
    f.write_text("KEY=value\nOTHER=123\n")
    assert parse_env_file(str(f)) == {"KEY": "value", "OTHER": "123"}


def test_parse_skips_comments_and_blanks(tmp_path: Path):
    f = tmp_path / ".env"
    f.write_text("# comment\n\n  \nKEY=value\n")
    assert parse_env_file(str(f)) == {"KEY": "value"}


def test_parse_value_with_equals(tmp_path: Path):
    f = tmp_path / ".env"
    f.write_text("URL=https://example.com/?a=1&b=2\n")
    assert parse_env_file(str(f))["URL"] == "https://example.com/?a=1&b=2"


def test_parse_trims_whitespace(tmp_path: Path):
    f = tmp_path / ".env"
    f.write_text("  KEY  =  value  \n")
    assert parse_env_file(str(f)) == {"KEY": "value"}


def test_parse_missing_or_empty_path():
    assert parse_env_file("") == {}
    assert parse_env_file("/nonexistent/path/.env") == {}


# --- runtime loader --------------------------------------------------------

def _load_env_files():
    from meshcore_packet_capture.packet_capture import load_env_files

    return load_env_files


def test_load_env_files_local_overrides_base(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    (tmp_path / ".env").write_text("PACKETCAPTURE_IATA=AAA\nPACKETCAPTURE_LOG_LEVEL=INFO\n")
    (tmp_path / ".env.local").write_text("PACKETCAPTURE_IATA=BBB\n")
    monkeypatch.setenv("MESHCORE_PACKETCAPTURE_ENV_DIR", str(tmp_path))
    monkeypatch.delenv("PACKETCAPTURE_IATA", raising=False)
    monkeypatch.delenv("PACKETCAPTURE_LOG_LEVEL", raising=False)

    _load_env_files()()
    assert os.environ["PACKETCAPTURE_IATA"] == "BBB"  # .env.local wins over .env
    assert os.environ["PACKETCAPTURE_LOG_LEVEL"] == "INFO"


def test_load_env_files_does_not_override_process_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    (tmp_path / ".env").write_text("PACKETCAPTURE_IATA=FROMFILE\n")
    monkeypatch.setenv("MESHCORE_PACKETCAPTURE_ENV_DIR", str(tmp_path))
    monkeypatch.setenv("PACKETCAPTURE_IATA", "FROMENV")

    _load_env_files()()
    assert os.environ["PACKETCAPTURE_IATA"] == "FROMENV"


def test_load_env_files_handles_quotes_and_inline_comments(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    (tmp_path / ".env").write_text('PACKETCAPTURE_ORIGIN="My Node"  # trailing comment\n')
    monkeypatch.setenv("MESHCORE_PACKETCAPTURE_ENV_DIR", str(tmp_path))
    monkeypatch.delenv("PACKETCAPTURE_ORIGIN", raising=False)

    _load_env_files()()
    assert os.environ["PACKETCAPTURE_ORIGIN"] == "My Node"
