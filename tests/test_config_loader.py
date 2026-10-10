"""Tests for config_loader TOML merge and env flattening."""
from __future__ import annotations

import os
from pathlib import Path

import pytest
import tomllib

import meshcore_packet_capture.config_loader as cl


def _write_tree(root: Path, value: str) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "config.toml").write_text(f'[general]\niata = "{value}"\n')
    return root


@pytest.fixture
def config_trees(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    system = _write_tree(tmp_path / "system", "SYSTEM")
    xdg = tmp_path / "xdg"
    _write_tree(xdg / "meshcore-packet-capture", "USER")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(xdg))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    return system, xdg


def _load_system(root: Path, **kwargs):
    return cl.load_config(base_path=str(root / "config.toml"), config_d=str(root / "config.d"), **kwargs)


def test_user_discovery_is_opt_in(config_trees):
    system, _ = config_trees
    assert _load_system(system)["general"]["iata"] == "SYSTEM"
    assert _load_system(system, user_config=True)["general"]["iata"] == "USER"


def test_system_overrides_and_user_fallback_preserve_defaults(config_trees, monkeypatch):
    system, xdg = config_trees
    config_d = system / "config.d"
    config_d.mkdir()
    (config_d / "99-later.toml").write_text('[general]\niata="SYSTEM-LATER"\n')
    (config_d / "10-earlier.toml").write_text('[general]\niata="SYSTEM-EARLIER"\n')
    assert _load_system(system)["general"]["iata"] == "SYSTEM-LATER"
    monkeypatch.setenv("XDG_CONFIG_HOME", str(xdg / "missing"))
    assert _load_system(system, user_config=True)["general"]["iata"] == "SYSTEM-LATER"


def test_user_config_d_works_without_either_base_file(config_trees):
    system, xdg = config_trees
    (system / "config.toml").unlink()
    user = xdg / "meshcore-packet-capture"
    (user / "config.toml").unlink()
    (user / "config.d").mkdir()
    (user / "config.d" / "99-user.toml").write_text('[general]\niata="USER-ONLY"\n')
    assert _load_system(system, user_config=True) == {"general": {"iata": "USER-ONLY"}}


def test_directory_selection_is_resolved_on_each_load(config_trees, tmp_path, monkeypatch):
    system, _ = config_trees
    for value in ("FIRST", "SECOND"):
        selected = _write_tree(tmp_path / value, value)
        monkeypatch.setenv("PACKETCAPTURE_CONFIG_DIR", str(selected))
        assert _load_system(system)["general"]["iata"] == value
    monkeypatch.delenv("PACKETCAPTURE_CONFIG_DIR")
    assert _load_system(system)["general"]["iata"] == "SYSTEM"


@pytest.mark.parametrize("xdg_value", [None, "", "relative/path"])
def test_user_discovery_home_fallback(config_trees, monkeypatch, xdg_value):
    system, _ = config_trees
    home_tree = Path.home() / ".config" / "meshcore-packet-capture"
    _write_tree(home_tree, "HOME")
    if xdg_value is None:
        monkeypatch.delenv("XDG_CONFIG_HOME")
    else:
        monkeypatch.setenv("XDG_CONFIG_HOME", xdg_value)
    assert _load_system(system, user_config=True)["general"]["iata"] == "HOME"


def test_user_tree_overlays_system_brokers_by_name(config_trees):
    system, xdg = config_trees
    (system / "config.toml").write_text(
        '[[broker]]\nname="shared"\nserver="system.example"\nport=1883\n'
        '[[broker]]\nname="system-only"\nserver="retained.example"\n'
    )
    user = xdg / "meshcore-packet-capture"
    (user / "config.toml").write_text('[[broker]]\nname="shared"\nport=8883\n')
    (user / "config.d").mkdir()
    (user / "config.d" / "10-user.toml").write_text('[[broker]]\nname="user-only"\nserver="user.example"\n')
    cfg = _load_system(system, user_config=True)
    assert cfg["broker"] == [
        {"name": "shared", "server": "system.example", "port": 8883},
        {"name": "system-only", "server": "retained.example"},
        {"name": "user-only", "server": "user.example"},
    ]


@pytest.mark.parametrize("user_config", [False, True])
def test_directory_override_selects_only_its_tree(config_trees, tmp_path, monkeypatch, user_config):
    system, _ = config_trees
    selected = _write_tree(tmp_path / "selected", "SELECTED")
    checkout = _write_tree(tmp_path / "checkout", "CHECKOUT")
    (system / "config.toml").write_text('[general]\niata="SYSTEM"\n[[broker]]\nname="system-only"\n')
    monkeypatch.setenv("MESHCORE_PACKETCAPTURE_ENV_DIR", str(checkout))
    monkeypatch.setenv("PACKETCAPTURE_CONFIG_DIR", str(selected))
    assert _load_system(system, user_config=user_config) == {"general": {"iata": "SELECTED"}}


@pytest.mark.parametrize("value", ["", "   "])
def test_empty_directory_override_keeps_default_discovery(config_trees, monkeypatch, value):
    system, _ = config_trees
    monkeypatch.setenv("PACKETCAPTURE_CONFIG_DIR", value)
    assert _load_system(system)["general"]["iata"] == "SYSTEM"


@pytest.mark.parametrize("path_kind", ["relative", "tilde", "spaces"])
def test_directory_override_path_handling(config_trees, tmp_path, monkeypatch, path_kind):
    system, _ = config_trees
    monkeypatch.chdir(tmp_path)
    if path_kind == "relative":
        selected = _write_tree(tmp_path / "selected", "SELECTED")
        value = "selected"
    elif path_kind == "tilde":
        selected = _write_tree(Path.home() / "selected", "SELECTED")
        value = "~/selected"
    else:
        selected = _write_tree(tmp_path / " directory with spaces ", "SELECTED")
        value = str(selected)
    monkeypatch.setenv("PACKETCAPTURE_CONFIG_DIR", value)
    assert _load_system(system)["general"]["iata"] == "SELECTED"


def test_empty_selected_tree_does_not_fall_back(config_trees, tmp_path, monkeypatch):
    system, _ = config_trees
    selected = tmp_path / "empty"
    selected.mkdir()
    monkeypatch.setenv("PACKETCAPTURE_CONFIG_DIR", str(selected))
    assert _load_system(system, user_config=True) == {}


@pytest.mark.parametrize("kind", ["missing", "file"])
def test_invalid_selected_directory_fails(config_trees, tmp_path, monkeypatch, kind):
    system, _ = config_trees
    selected = tmp_path / kind
    if kind == "file":
        selected.write_text("not a directory")
    monkeypatch.setenv("PACKETCAPTURE_CONFIG_DIR", str(selected))
    with pytest.raises(NotADirectoryError, match="PACKETCAPTURE_CONFIG_DIR"):
        _load_system(system, user_config=True)


def test_explicit_files_bypass_directory_and_user_discovery(config_trees, monkeypatch):
    system, _ = config_trees
    monkeypatch.setenv("PACKETCAPTURE_CONFIG_DIR", "/does/not/exist")
    cfg = cl.load_config([str(system / "config.toml")], user_config=True)
    assert cfg == {"general": {"iata": "SYSTEM"}}


def test_directory_discovery_add_change_remove_and_sort(config_trees, tmp_path, monkeypatch):
    system, _ = config_trees
    selected = _write_tree(tmp_path / "selected", "BASE")
    config_d = selected / "config.d"
    config_d.mkdir()
    monkeypatch.setenv("PACKETCAPTURE_CONFIG_DIR", str(selected))
    assert _load_system(system)["general"]["iata"] == "BASE"
    later = config_d / "99-later.toml"
    earlier = config_d / "10-earlier.toml"
    later.write_text('[general]\niata="LATER"\n')
    earlier.write_text('[general]\niata="EARLIER"\n')
    (config_d / "ignored.toml.bak").write_text("invalid TOML")
    (config_d / "nested").mkdir()
    (config_d / "nested" / "100-nested.toml").write_text("invalid TOML")
    assert _load_system(system)["general"]["iata"] == "LATER"
    later.write_text('[general]\niata="CHANGED"\n')
    assert _load_system(system)["general"]["iata"] == "CHANGED"
    later.unlink()
    assert _load_system(system)["general"]["iata"] == "EARLIER"


@pytest.mark.parametrize("location", ["selected", "user", "checkout"])
def test_malformed_config_reports_filename(config_trees, tmp_path, monkeypatch, caplog, location):
    system, xdg = config_trees
    if location == "user":
        root = xdg / "meshcore-packet-capture"
    else:
        root = _write_tree(tmp_path / location, "BASE")
        variable = "PACKETCAPTURE_CONFIG_DIR" if location == "selected" else "MESHCORE_PACKETCAPTURE_ENV_DIR"
        monkeypatch.setenv(variable, str(root))
    (root / "config.d").mkdir()
    bad = root / "config.d" / "99-bad.toml"
    bad.write_text("invalid TOML")
    with pytest.raises(tomllib.TOMLDecodeError):
        _load_system(system, user_config=True)
    assert str(bad) in caplog.text


def test_checkout_discovery_precedes_xdg_and_preserves_no_config_fallback(config_trees, tmp_path, monkeypatch):
    system, _ = config_trees
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    monkeypatch.setenv("MESHCORE_PACKETCAPTURE_ENV_DIR", str(checkout))
    assert _load_system(system, user_config=True)["general"]["iata"] == "USER"
    _write_tree(checkout, "CHECKOUT")
    assert _load_system(system, user_config=True) == {"general": {"iata": "CHECKOUT"}}
    assert _load_system(system)["general"]["iata"] == "SYSTEM"


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
                "websocket_path": "/mqtt",
                "tls": {"enabled": True, "verify": True},
                "auth": {"method": "token", "audience": "aud"},
            },
        ]
    }
    env = cl.flatten_config_to_env_dict(cfg)
    assert env["PACKETCAPTURE_MQTT1_SERVER"] == "mqtt.example"
    assert env["PACKETCAPTURE_MQTT1_NAME"] == "one"
    assert env["PACKETCAPTURE_MQTT2_NAME"] == "two"
    assert env["PACKETCAPTURE_MQTT2_WEBSOCKET_PATH"] == "/mqtt"
    assert env["PACKETCAPTURE_MQTT2_USE_TLS"] == "true"
    assert env["PACKETCAPTURE_MQTT2_USE_AUTH_TOKEN"] == "true"
    assert env["PACKETCAPTURE_MQTT2_TOKEN_AUDIENCE"] == "aud"


def test_flatten_supports_more_than_six_brokers():
    cfg = {
        "broker": [
            {"name": f"b{i}", "enabled": True, "server": f"mqtt{i}.example", "port": 1883}
            for i in range(1, 9)  # 8 enabled brokers
        ]
    }
    env = cl.flatten_config_to_env_dict(cfg)
    # No fixed 6-broker cap: slots 7 and 8 must be emitted too.
    assert env["PACKETCAPTURE_MQTT7_SERVER"] == "mqtt7.example"
    assert env["PACKETCAPTURE_MQTT8_SERVER"] == "mqtt8.example"


def test_flatten_broker_token_ttl():
    cfg = {
        "broker": [
            {
                "name": "waev",
                "enabled": True,
                "server": "mqtt.waev.app",
                "port": 443,
                "auth": {"method": "token", "audience": "mqtt.waev.app", "token_ttl": 3600},
            },
            # token broker without token_ttl -> no TOKEN_TTL emitted (uses default later)
            {
                "name": "letsmesh-us",
                "enabled": True,
                "server": "mqtt-us-v1.letsmesh.net",
                "auth": {"method": "token", "audience": "mqtt-us-v1.letsmesh.net"},
            },
        ]
    }
    env = cl.flatten_config_to_env_dict(cfg)
    assert env["PACKETCAPTURE_MQTT1_TOKEN_TTL"] == "3600"
    assert "PACKETCAPTURE_MQTT2_TOKEN_TTL" not in env


def test_flatten_broker_token_owner_email():
    cfg = {
        "broker": [
            {
                "name": "waev",
                "enabled": True,
                "server": "mqtt.waev.app",
                "auth": {
                    "method": "token",
                    "audience": "mqtt.waev.app",
                    "owner": "A" * 64,
                    "email": "User@Example.COM",
                },
            }
        ]
    }
    env = cl.flatten_config_to_env_dict(cfg)
    assert env["PACKETCAPTURE_MQTT1_TOKEN_OWNER"] == "A" * 64
    assert env["PACKETCAPTURE_MQTT1_TOKEN_EMAIL"] == "User@Example.COM"


def test_flatten_token_ttl_ignored_for_non_token_auth():
    cfg = {
        "broker": [
            {
                "name": "pw",
                "enabled": True,
                "server": "mqtt.example.com",
                # token_ttl is meaningless for password auth and must not be emitted
                "auth": {"method": "password", "username": "u", "password": "p", "token_ttl": 60},
            }
        ]
    }
    env = cl.flatten_config_to_env_dict(cfg)
    assert "PACKETCAPTURE_MQTT1_TOKEN_TTL" not in env


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
            "ble_pin": "012345",
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
    assert env["PACKETCAPTURE_BLE_PIN"] == "012345"
    assert env["PACKETCAPTURE_DRAIN_MESSAGES"] == "false"
    assert env["PACKETCAPTURE_TCP_KEEPALIVE_ENABLED"] == "true"
    assert env["PACKETCAPTURE_TCP_KEEPALIVE_IDLE"] == "60"
    assert env["PACKETCAPTURE_BINARY_INTERFACE_ENABLED"] == "true"
    assert env["PACKETCAPTURE_BINARY_INTERFACE_HOST"] == "0.0.0.0"
    assert env["PACKETCAPTURE_BINARY_INTERFACE_PORT"] == "5001"
    assert env["PACKETCAPTURE_OWNER_PUBLIC_KEY"] == "ABC"
    assert env["PACKETCAPTURE_OWNER_EMAIL"] == "u@example.com"


def test_flatten_neighbors_capture_settings():
    cfg = {
        "capture": {
            "neighbors_interval_hours": 48,
            "neighbors_discover_window": 90.0,
            "neighbors_command_timeout": 25.0,
            "neighbors_scope_timeout": 0.0,
            "neighbors_scope_min_timeout": 8.0,
            "neighbors_scope_gap": 2.5,
            "neighbors_cycle_timeout": 900,
            "neighbors_max": 16,
            "neighbors_self_scopes": "DEN,APRS",
        }
    }
    env = cl.flatten_config_to_env_dict(cfg)
    assert env["PACKETCAPTURE_NEIGHBORS_INTERVAL_HOURS"] == "48"
    assert env["PACKETCAPTURE_NEIGHBORS_DISCOVER_WINDOW"] == "90.0"
    assert env["PACKETCAPTURE_NEIGHBORS_COMMAND_TIMEOUT"] == "25.0"
    assert env["PACKETCAPTURE_NEIGHBORS_SCOPE_TIMEOUT"] == "0.0"
    assert env["PACKETCAPTURE_NEIGHBORS_SCOPE_MIN_TIMEOUT"] == "8.0"
    assert env["PACKETCAPTURE_NEIGHBORS_SCOPE_GAP"] == "2.5"
    assert env["PACKETCAPTURE_NEIGHBORS_CYCLE_TIMEOUT"] == "900"
    assert env["PACKETCAPTURE_NEIGHBORS_MAX"] == "16"
    assert env["PACKETCAPTURE_NEIGHBORS_SELF_SCOPES"] == "DEN,APRS"


def test_flatten_per_broker_neighbors_flag_and_topic():
    cfg = {
        "broker": [
            {
                "name": "analyzer",
                "enabled": True,
                "server": "mqtt.example",
                "neighbors": True,
                "topics": {"neighbors": "custom/{IATA}/{PUBLIC_KEY}/neighbors"},
            },
            {"name": "plain", "enabled": True, "server": "other.example"},
        ]
    }
    env = cl.flatten_config_to_env_dict(cfg)
    assert env["PACKETCAPTURE_MQTT1_NEIGHBORS"] == "true"
    assert env["PACKETCAPTURE_MQTT1_TOPIC_NEIGHBORS"] == "custom/{IATA}/{PUBLIC_KEY}/neighbors"
    # Unset means off: no key emitted, so the runtime default (off) applies.
    assert "PACKETCAPTURE_MQTT2_NEIGHBORS" not in env


def test_flatten_per_broker_neighbors_explicit_false():
    cfg = {"broker": [{"name": "a", "enabled": True, "neighbors": False}]}
    env = cl.flatten_config_to_env_dict(cfg)
    assert env["PACKETCAPTURE_MQTT1_NEIGHBORS"] == "false"
