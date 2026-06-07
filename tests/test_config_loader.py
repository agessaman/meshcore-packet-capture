"""Tests for config_loader TOML merge and env flattening."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

import meshcore_packet_capture.config_loader as cl


def test_deep_merge_nested():
    base = {"a": 1, "nested": {"x": 1, "y": 2}}
    over = {"nested": {"y": 99, "z": 3}}
    assert cl.deep_merge(base, over) == {"a": 1, "nested": {"x": 1, "y": 99, "z": 3}}


def test_merge_broker_lists_by_name():
    base = [{"name": "a", "port": 1883, "nested": {"k": 1}}]
    over = [{"name": "a", "port": 8883, "nested": {"k": 2}}]
    merged = cl.merge_broker_lists(base, over)
    assert len(merged) == 1
    assert merged[0]["port"] == 8883
    assert merged[0]["nested"]["k"] == 2


def test_load_explicit_paths_order(tmp_path: Path):
    first = tmp_path / "a.toml"
    second = tmp_path / "b.toml"
    first.write_text('[general]\niata = "AAA"\n')
    second.write_text('[general]\niata = "BBB"\n')
    cfg = cl.load_config([str(first), str(second)])
    assert cfg["general"]["iata"] == "BBB"


def test_flatten_brokers_to_mqtt_slots():
    cfg = {
        "broker": [
            {"name": "one", "enabled": True, "server": "mqtt.example", "port": 1883, "transport": "tcp"},
            {
                "name": "two",
                "enabled": True,
                "server": "wss.example",
                "port": 443,
                "transport": "websockets",
                "tls": {"enabled": True, "verify": True},
                "auth": {"method": "token", "audience": "aud"},
            },
        ]
    }
    env = cl.flatten_config_to_env_dict(cfg)
    assert env["PACKETCAPTURE_MQTT1_SERVER"] == "mqtt.example"
    assert env["PACKETCAPTURE_MQTT2_USE_TLS"] == "true"
    assert env["PACKETCAPTURE_MQTT2_USE_AUTH_TOKEN"] == "true"
    assert env["PACKETCAPTURE_MQTT2_TOKEN_AUDIENCE"] == "aud"


def test_flatten_broker_topic_token():
    cfg = {
        "broker": [
            {
                "name": "meshrank",
                "enabled": True,
                "server": "meshrank.net",
                "port": 8883,
                "auth": {"method": "none", "topic_token": "abc123"},
                "topics": {"packets": "meshrank/uplink/{TOKEN}/{PUBLIC_KEY}/packets"},
            }
        ]
    }
    env = cl.flatten_config_to_env_dict(cfg)
    assert env["PACKETCAPTURE_MQTT1_TOPIC_TOKEN"] == "abc123"
    assert env["PACKETCAPTURE_MQTT1_TOPIC_PACKETS"] == "meshrank/uplink/{TOKEN}/{PUBLIC_KEY}/packets"


def test_apply_config_respects_existing_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.delenv("PACKETCAPTURE_IATA", raising=False)
    base = tmp_path / "base.toml"
    base.write_text('[general]\niata = "FROMFILE"\n')
    cl.apply_config_to_environ([str(base)])
    assert os.environ.get("PACKETCAPTURE_IATA") == "FROMFILE"
    monkeypatch.setenv("PACKETCAPTURE_IATA", "FROMENV")
    cl.apply_config_to_environ([str(base)])
    assert os.environ.get("PACKETCAPTURE_IATA") == "FROMENV"


def test_toml_overrides_env_sourced_key(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    """With ``protected`` given, TOML overwrites a key that only came from .env
    but never overwrites a key from the real process env."""
    base = tmp_path / "base.toml"
    base.write_text('[general]\niata = "FROMTOML"\n')

    # Snapshot real process env, then simulate a .env-sourced key.
    monkeypatch.delenv("PACKETCAPTURE_IATA", raising=False)
    preexisting = set(os.environ)
    monkeypatch.setenv("PACKETCAPTURE_IATA", "FROMDOTENV")
    cl.apply_config_to_environ([str(base)], protected=preexisting)
    assert os.environ.get("PACKETCAPTURE_IATA") == "FROMTOML"

    # A real process env var (present in the snapshot) is protected from TOML.
    monkeypatch.setenv("PACKETCAPTURE_IATA", "FROMENV")
    protected_with_env = set(os.environ)
    cl.apply_config_to_environ([str(base)], protected=protected_with_env)
    assert os.environ.get("PACKETCAPTURE_IATA") == "FROMENV"


def test_topics_keys_uppercased():
    cfg = {"topics": {"status": "s", "raw": "r"}}
    env = cl.flatten_config_to_env_dict(cfg)
    assert env["PACKETCAPTURE_TOPIC_STATUS"] == "s"
    assert env["PACKETCAPTURE_TOPIC_RAW"] == "r"


def test_capture_extended_keys_mapped():
    cfg = {
        "capture": {
            "connection_retry_delay_max": 30,
            "connection_retry_backoff_multiplier": 1.5,
            "drain_messages": False,
            "tcp_keepalive": True,
            "tcp_keepalive_idle": 60,
            "binary_interface_enabled": True,
            "binary_interface_host": "0.0.0.0",
            "binary_interface_port": 5001,
            "owner_public_key": "ABC",
            "owner_email": "u@example.com",
        }
    }
    env = cl.flatten_config_to_env_dict(cfg)
    assert env["PACKETCAPTURE_CONNECTION_RETRY_DELAY_MAX"] == "30"
    assert env["PACKETCAPTURE_CONNECTION_RETRY_BACKOFF_MULTIPLIER"] == "1.5"
    assert env["PACKETCAPTURE_DRAIN_MESSAGES"] == "false"
    assert env["PACKETCAPTURE_TCP_KEEPALIVE_ENABLED"] == "true"
    assert env["PACKETCAPTURE_TCP_KEEPALIVE_IDLE"] == "60"
    assert env["PACKETCAPTURE_BINARY_INTERFACE_ENABLED"] == "true"
    assert env["PACKETCAPTURE_BINARY_INTERFACE_HOST"] == "0.0.0.0"
    assert env["PACKETCAPTURE_BINARY_INTERFACE_PORT"] == "5001"
    assert env["PACKETCAPTURE_OWNER_PUBLIC_KEY"] == "ABC"
    assert env["PACKETCAPTURE_OWNER_EMAIL"] == "u@example.com"
