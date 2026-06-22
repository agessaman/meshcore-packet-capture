"""Tests for the legacy .env -> TOML migration conversion (installer.migrate_cmd)."""
from __future__ import annotations

import tomllib

from installer.migrate_cmd import env_to_toml, normalize_env_keys


def _roundtrip(env: dict[str, str]) -> dict:
    """Convert env -> TOML string -> parsed dict, asserting it is valid TOML."""
    return tomllib.loads(env_to_toml(env))


# --- normalize_env_keys ----------------------------------------------------

def test_normalize_maps_mctomqtt_prefix():
    out = normalize_env_keys({"MCTOMQTT_IATA": "SEA", "OTHER": "x"})
    assert out == {"PACKETCAPTURE_IATA": "SEA", "OTHER": "x"}


def test_normalize_leaves_packetcapture_keys_untouched():
    out = normalize_env_keys({"PACKETCAPTURE_IATA": "SEA"})
    assert out == {"PACKETCAPTURE_IATA": "SEA"}


# --- general ---------------------------------------------------------------

def test_general_omits_defaults():
    # XXX iata and INFO log level are defaults and should be dropped.
    data = _roundtrip({"PACKETCAPTURE_IATA": "XXX", "PACKETCAPTURE_LOG_LEVEL": "INFO"})
    assert "general" not in data


def test_general_includes_customizations():
    data = _roundtrip(
        {
            "PACKETCAPTURE_IATA": "SEA",
            "PACKETCAPTURE_LOG_LEVEL": "DEBUG",
            "PACKETCAPTURE_SYNC_TIME": "false",
        }
    )
    assert data["general"]["iata"] == "SEA"
    assert data["general"]["log_level"] == "DEBUG"
    assert data["general"]["sync_time"] is False


# --- serial ----------------------------------------------------------------

def test_serial_ports_split_and_defaults_skipped():
    data = _roundtrip(
        {
            "PACKETCAPTURE_SERIAL_PORTS": "/dev/ttyACM0, /dev/ttyUSB0",
            "PACKETCAPTURE_SERIAL_BAUD_RATE": "115200",  # default -> skipped
            "PACKETCAPTURE_SERIAL_TIMEOUT": "5",
        }
    )
    assert data["serial"]["ports"] == ["/dev/ttyACM0", "/dev/ttyUSB0"]
    assert "baud_rate" not in data["serial"]
    assert data["serial"]["timeout"] == 5


# --- update / topics -------------------------------------------------------

def test_update_section():
    data = _roundtrip(
        {
            "PACKETCAPTURE_UPDATE_REPO": "agessaman/meshcore-packet-capture",
            "PACKETCAPTURE_UPDATE_BRANCH": "main",
        }
    )
    assert data["update"]["repo"] == "agessaman/meshcore-packet-capture"
    assert data["update"]["branch"] == "main"


def test_topics_section():
    data = _roundtrip(
        {
            "PACKETCAPTURE_TOPIC_STATUS": "meshcore/{IATA}/{PUBLIC_KEY}/status",
            "PACKETCAPTURE_TOPIC_PACKETS": "meshcore/{IATA}/{PUBLIC_KEY}/packets",
        }
    )
    assert data["topics"]["status"].endswith("/status")
    assert data["topics"]["packets"].endswith("/packets")


# --- capture ---------------------------------------------------------------

def test_capture_numeric_vs_string():
    data = _roundtrip(
        {
            "PACKETCAPTURE_CONNECTION_TYPE": "tcp",
            "PACKETCAPTURE_TCP_HOST": "host.example",
            "PACKETCAPTURE_TCP_PORT": "5000",
            "PACKETCAPTURE_ADVERT_INTERVAL_HOURS": "11",
        }
    )
    assert data["capture"]["connection_type"] == "tcp"
    assert data["capture"]["tcp_host"] == "host.example"
    assert data["capture"]["tcp_port"] == 5000  # numeric
    assert data["capture"]["advert_interval_hours"] == 11


def test_invalid_numeric_values_are_skipped():
    data = _roundtrip(
        {
            "PACKETCAPTURE_CONNECTION_TYPE": "tcp",
            "PACKETCAPTURE_TCP_HOST": "host.example",
            "PACKETCAPTURE_TCP_PORT": "not-a-port",
            "PACKETCAPTURE_SERIAL_TIMEOUT": "slow",
        }
    )
    assert data["capture"]["connection_type"] == "tcp"
    assert data["capture"]["tcp_host"] == "host.example"
    assert "tcp_port" not in data["capture"]
    assert "serial" not in data


# --- brokers ---------------------------------------------------------------

def test_letsmesh_us_broker_token_auth():
    data = _roundtrip(
        {
            "PACKETCAPTURE_MQTT1_ENABLED": "true",
            "PACKETCAPTURE_MQTT1_SERVER": "mqtt-us-v1.letsmesh.net",
            "PACKETCAPTURE_MQTT1_PORT": "443",
            "PACKETCAPTURE_MQTT1_TRANSPORT": "websockets",
            "PACKETCAPTURE_MQTT1_USE_TLS": "true",
            "PACKETCAPTURE_MQTT1_USE_AUTH_TOKEN": "true",
            "PACKETCAPTURE_MQTT1_TOKEN_AUDIENCE": "mqtt-us-v1.letsmesh.net",
            "PACKETCAPTURE_MQTT1_TOKEN_OWNER": "A" * 64,
            "PACKETCAPTURE_MQTT1_TOKEN_EMAIL": "u@example.com",
        }
    )
    broker = data["broker"][0]
    assert broker["name"] == "letsmesh-us"
    assert broker["server"] == "mqtt-us-v1.letsmesh.net"
    assert broker["transport"] == "websockets"
    assert broker["tls"]["enabled"] is True
    assert broker["auth"]["method"] == "token"
    assert broker["auth"]["audience"] == "mqtt-us-v1.letsmesh.net"
    assert broker["auth"]["owner"] == "A" * 64
    assert broker["auth"]["email"] == "u@example.com"


def test_letsmesh_eu_broker_named():
    data = _roundtrip(
        {
            "PACKETCAPTURE_MQTT1_ENABLED": "true",
            "PACKETCAPTURE_MQTT1_SERVER": "mqtt-eu-v1.letsmesh.net",
        }
    )
    assert data["broker"][0]["name"] == "letsmesh-eu"


def test_custom_broker_password_auth():
    data = _roundtrip(
        {
            "PACKETCAPTURE_MQTT2_ENABLED": "true",
            "PACKETCAPTURE_MQTT2_SERVER": "mqtt.example.com",
            "PACKETCAPTURE_MQTT2_PORT": "1883",
            "PACKETCAPTURE_MQTT2_USERNAME": "user",
            "PACKETCAPTURE_MQTT2_PASSWORD": "pass",
        }
    )
    broker = data["broker"][0]
    assert broker["name"] == "custom-2"
    assert "tls" not in broker  # USE_TLS not set
    assert broker["auth"]["method"] == "password"
    assert broker["auth"]["username"] == "user"
    assert broker["auth"]["password"] == "pass"


def test_broker_no_auth_method_none():
    data = _roundtrip(
        {
            "PACKETCAPTURE_MQTT1_ENABLED": "true",
            "PACKETCAPTURE_MQTT1_SERVER": "mqtt.example.com",
        }
    )
    assert data["broker"][0]["auth"]["method"] == "none"


def test_disabled_or_serverless_broker_skipped():
    assert "broker" not in _roundtrip(
        {"PACKETCAPTURE_MQTT1_ENABLED": "false", "PACKETCAPTURE_MQTT1_SERVER": "x"}
    )
    assert "broker" not in _roundtrip({"PACKETCAPTURE_MQTT1_ENABLED": "true"})


def test_two_brokers_in_order():
    data = _roundtrip(
        {
            "PACKETCAPTURE_MQTT1_ENABLED": "true",
            "PACKETCAPTURE_MQTT1_SERVER": "mqtt-us-v1.letsmesh.net",
            "PACKETCAPTURE_MQTT2_ENABLED": "true",
            "PACKETCAPTURE_MQTT2_SERVER": "mqtt.example.com",
        }
    )
    names = [b["name"] for b in data["broker"]]
    assert names == ["letsmesh-us", "custom-2"]


def test_six_brokers_all_migrated():
    # Legacy .env supported up to 6 broker slots; none should be dropped.
    env = {}
    for n in range(1, 7):
        env[f"PACKETCAPTURE_MQTT{n}_ENABLED"] = "true"
        env[f"PACKETCAPTURE_MQTT{n}_SERVER"] = f"mqtt{n}.example.com"
    data = _roundtrip(env)
    names = [b["name"] for b in data["broker"]]
    assert names == [f"custom-{n}" for n in range(1, 7)]


def test_empty_env_produces_empty_valid_toml():
    assert _roundtrip({}) == {}
