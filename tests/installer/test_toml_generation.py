"""Tests for installer.config TOML writers and the round-trippable serializer."""
from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

from installer.config import (
    _load_user_toml,
    _toml_dumps,
    _write_user_toml,
    append_custom_broker_toml,
    append_disabled_broker_toml,
    append_letsmesh_broker_toml,
    append_remote_serial_toml,
    write_user_toml_base,
)


def _parse(path: Path) -> dict:
    with open(path, "rb") as f:
        return tomllib.load(f)


def test_write_user_toml_base(tmp_path: Path):
    dest = tmp_path / "99-user.toml"
    write_user_toml_base(str(dest), "SEA", "/dev/ttyUSB0", "agessaman/x", "main")
    data = _parse(dest)
    assert data["general"]["iata"] == "SEA"
    assert data["serial"]["ports"] == ["/dev/ttyUSB0"]
    assert data["update"]["repo"] == "agessaman/x"
    assert data["update"]["branch"] == "main"


def test_base_plus_disabled_broker(tmp_path: Path):
    dest = tmp_path / "99-user.toml"
    write_user_toml_base(str(dest), "SEA", "/dev/ttyUSB0", "agessaman/x", "main")
    append_disabled_broker_toml(str(dest), "letsmesh-eu")
    data = _parse(dest)
    assert data["broker"][0] == {"name": "letsmesh-eu", "enabled": False}


def test_base_plus_letsmesh_broker(tmp_path: Path):
    dest = tmp_path / "99-user.toml"
    write_user_toml_base(str(dest), "SEA", "/dev/ttyUSB0", "agessaman/x", "main")
    append_letsmesh_broker_toml(
        str(dest), "letsmesh-us", "mqtt-us-v1.letsmesh.net",
        "mqtt-us-v1.letsmesh.net", "A" * 64, "u@example.com",
    )
    broker = _parse(dest)["broker"][0]
    assert broker["name"] == "letsmesh-us"
    assert broker["transport"] == "websockets"
    assert broker["tls"]["enabled"] is True
    assert broker["auth"]["method"] == "token"
    assert broker["auth"]["owner"] == "A" * 64


def test_custom_broker_password_and_remote_serial(tmp_path: Path):
    dest = tmp_path / "99-user.toml"
    write_user_toml_base(str(dest), "SEA", "/dev/ttyUSB0", "agessaman/x", "main")
    append_custom_broker_toml(
        str(dest), "mybroker", "mqtt.example.com", "1883", "tcp",
        "true", "false", "password", username="u", password="p",
    )
    append_remote_serial_toml(str(dest), "KEY1,KEY2")
    data = _parse(dest)
    broker = data["broker"][0]
    assert broker["port"] == 1883
    assert broker["tls"]["verify"] is False
    assert broker["auth"] == {"method": "password", "username": "u", "password": "p"}
    assert data["remote_serial"]["enabled"] is True
    assert data["remote_serial"]["allowed_companions"] == ["KEY1", "KEY2"]


# --- _toml_dumps round-trip -----------------------------------------------

def test_toml_dumps_roundtrips_nested_and_arrays():
    doc = {
        "general": {"iata": "SEA", "log_level": "DEBUG"},
        "serial": {"ports": ["/dev/ttyUSB0", "/dev/ttyACM0"], "baud_rate": 115200},
        "remote_serial": {"enabled": True, "allowed_companions": []},
        "broker": [
            {
                "name": "letsmesh-us",
                "enabled": True,
                "port": 443,
                "tls": {"enabled": True, "verify": True},
                "auth": {"method": "token", "audience": "aud"},
            },
            {"name": "custom", "enabled": False},
        ],
    }
    assert tomllib.loads(_toml_dumps(doc)) == doc


def test_load_write_user_toml_roundtrip(tmp_path: Path):
    dest = tmp_path / "user.toml"
    doc = {"general": {"iata": "PDX"}, "broker": [{"name": "b1", "enabled": True}]}
    _write_user_toml(dest, doc)
    assert _load_user_toml(dest) == doc


def test_load_user_toml_missing_returns_empty(tmp_path: Path):
    assert _load_user_toml(tmp_path / "absent.toml") == {}


def test_toml_dumps_quotes_dotted_keys():
    # A broker name with a dot must be quoted to survive round-trip.
    doc = {"broker": [{"name": "meshat.se", "enabled": True}]}
    assert tomllib.loads(_toml_dumps(doc)) == doc
