"""Tests for installer.config TOML writers and the round-trippable serializer."""
from __future__ import annotations

import tomllib
from pathlib import Path

from installer.config import (
    _load_user_toml,
    _toml_dumps,
    _write_user_toml,
    append_custom_broker_toml,
    append_disabled_broker_toml,
    append_letsmesh_broker_toml,
    set_user_toml_iata,
    write_user_toml_base,
)


def _parse(path: Path) -> dict:
    with open(path, "rb") as f:
        return tomllib.load(f)


def test_set_iata_updates_existing_in_place(tmp_path: Path):
    p = tmp_path / "99-user.toml"
    p.write_text('[general]\niata = "XXX"\nlog_level = "INFO"\n')
    set_user_toml_iata(str(p), "SEA")
    data = _parse(p)
    assert data["general"]["iata"] == "SEA"
    assert data["general"]["log_level"] == "INFO"  # untouched


def test_set_iata_injects_without_duplicate_general(tmp_path: Path):
    # Downloaded config already has [general] (without iata) — must not create a
    # second [general] table, which tomllib would reject.
    p = tmp_path / "99-user.toml"
    p.write_text('[general]\nlog_level = "DEBUG"\n\n[capture]\nconnection_type = "ble"\n')
    set_user_toml_iata(str(p), "LAX")
    data = _parse(p)  # parses cleanly == no duplicate table
    assert data["general"]["iata"] == "LAX"
    assert data["general"]["log_level"] == "DEBUG"
    assert data["capture"]["connection_type"] == "ble"


def test_set_iata_on_config_without_general(tmp_path: Path):
    p = tmp_path / "99-user.toml"
    p.write_text('[capture]\nconnection_type = "tcp"\n')
    set_user_toml_iata(str(p), "NYC")
    data = _parse(p)
    assert data["general"]["iata"] == "NYC"
    assert data["capture"]["connection_type"] == "tcp"


def test_write_user_toml_base(tmp_path: Path):
    dest = tmp_path / "99-user.toml"
    write_user_toml_base(str(dest), "SEA", "agessaman/x", "main", {"type": "serial", "serial_device": "/dev/ttyUSB0"})
    data = _parse(dest)
    assert data["general"]["iata"] == "SEA"
    assert data["capture"]["connection_type"] == "serial"
    assert data["serial"]["ports"] == ["/dev/ttyUSB0"]
    assert data["update"]["repo"] == "agessaman/x"
    assert data["update"]["branch"] == "main"


def test_base_plus_disabled_broker(tmp_path: Path):
    dest = tmp_path / "99-user.toml"
    write_user_toml_base(str(dest), "SEA", "agessaman/x", "main", {"type": "serial", "serial_device": "/dev/ttyUSB0"})
    append_disabled_broker_toml(str(dest), "letsmesh-eu")
    data = _parse(dest)
    assert data["broker"][0] == {"name": "letsmesh-eu", "enabled": False}


def test_base_plus_letsmesh_broker(tmp_path: Path):
    dest = tmp_path / "99-user.toml"
    write_user_toml_base(str(dest), "SEA", "agessaman/x", "main", {"type": "serial", "serial_device": "/dev/ttyUSB0"})
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


def test_custom_broker_password(tmp_path: Path):
    dest = tmp_path / "99-user.toml"
    write_user_toml_base(str(dest), "SEA", "agessaman/x", "main", {"type": "serial", "serial_device": "/dev/ttyUSB0"})
    append_custom_broker_toml(
        str(dest), "mybroker", "mqtt.example.com", "1883", "tcp",
        "true", "false", "password", username="u", password="p",
    )
    data = _parse(dest)
    broker = data["broker"][0]
    assert broker["port"] == 1883
    assert broker["tls"]["verify"] is False
    assert broker["auth"] == {"method": "password", "username": "u", "password": "p"}


# --- _toml_dumps round-trip -----------------------------------------------

def test_toml_dumps_roundtrips_nested_and_arrays():
    doc = {
        "general": {"iata": "SEA", "log_level": "DEBUG"},
        "serial": {"ports": ["/dev/ttyUSB0", "/dev/ttyACM0"], "baud_rate": 115200},
        # exercise a nested table with a bool and an empty array
        "misc": {"flag": True, "items": []},
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
