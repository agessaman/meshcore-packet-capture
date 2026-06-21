"""TOML configuration loading for MeshCore Packet Capture.

Mirrors meshcoretomqtt merge semantics (deep merge, [[broker]] by name).
Default paths: /etc/meshcore-packet-capture/config.toml + config.d/*.toml.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

import tomllib

logger = logging.getLogger(__name__)

DEFAULT_CONFIG_FILE = "/etc/meshcore-packet-capture/config.toml"
DEFAULT_CONFIG_D = "/etc/meshcore-packet-capture/config.d"
ENV_PREFIX = "PACKETCAPTURE_"


def deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Deep merge two dicts. override values take precedence."""
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def merge_broker_lists(
    base_brokers: list[dict[str, Any]], override_brokers: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Merge broker lists by name. Override brokers replace base brokers with the same name."""
    if not override_brokers:
        return base_brokers
    if not base_brokers:
        return override_brokers

    result = list(base_brokers)
    base_names = {b.get("name", ""): i for i, b in enumerate(result)}

    for broker in override_brokers:
        name = broker.get("name", "")
        if name and name in base_names:
            result[base_names[name]] = deep_merge(result[base_names[name]], broker)
        else:
            result.append(broker)

    return result


def _apply_override(config: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Merge an override dict into config, handling broker lists specially."""
    override_brokers = override.pop("broker", None)
    config_brokers = config.get("broker", [])
    config = deep_merge(config, override)
    if override_brokers is not None:
        config["broker"] = merge_broker_lists(config_brokers, override_brokers)
    return config


def _load_toml(path: str | Path) -> dict[str, Any]:
    with open(path, "rb") as f:
        return tomllib.load(f)


def _load_config_dir(config: dict[str, Any], config_d: Path) -> dict[str, Any]:
    if not config_d.is_dir():
        return config
    for override_file in sorted(config_d.glob("*.toml")):
        logger.info("Loading config override: %s", override_file)
        override = _load_toml(override_file)
        config = _apply_override(config, override)
    return config


def load_config(
    config_paths: list[str] | None = None,
    *,
    base_path: str = DEFAULT_CONFIG_FILE,
    config_d: str = DEFAULT_CONFIG_D,
) -> dict[str, Any]:
    """Load and merge TOML. If config_paths is set, load only those files in order."""
    if config_paths:
        config: dict[str, Any] = {}
        for path in config_paths:
            if not os.path.exists(path):
                logger.error("Config file not found: %s", path)
                continue
            logger.info("Loading config: %s", path)
            override = _load_toml(path)
            config = _apply_override(config, override)
        return config

    config = {}
    if os.path.exists(base_path):
        config = _load_toml(base_path)
        logger.info("Loaded base config from %s", base_path)
    else:
        logger.warning("Base config not found at %s, using defaults", base_path)

    config = _load_config_dir(config, Path(config_d))
    return config


def _bool_str(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v).lower() if v else "false"


def _broker_to_env_slot(broker: dict[str, Any], slot: int) -> dict[str, str]:
    """Map one [[broker]] table to PACKETCAPTURE_MQTT{n}_* keys (suffix only, no prefix)."""
    prefix = f"MQTT{slot}_"
    out: dict[str, str] = {}
    out[prefix + "ENABLED"] = _bool_str(broker.get("enabled", False))
    if "name" in broker:
        out[prefix + "NAME"] = str(broker["name"])
    if "server" in broker:
        out[prefix + "SERVER"] = str(broker["server"])
    if "port" in broker:
        out[prefix + "PORT"] = str(int(broker["port"]))
    if "transport" in broker:
        out[prefix + "TRANSPORT"] = str(broker["transport"])
    if "keepalive" in broker:
        out[prefix + "KEEPALIVE"] = str(int(broker["keepalive"]))
    if "qos" in broker:
        out[prefix + "QOS"] = str(int(broker["qos"]))
    if "retain" in broker:
        out[prefix + "RETAIN"] = _bool_str(broker["retain"])
    if "client_id_prefix" in broker:
        out[prefix + "CLIENT_ID_PREFIX"] = str(broker["client_id_prefix"])
    if "iata" in broker:
        out[prefix + "IATA"] = str(broker["iata"])

    tls = broker.get("tls") or {}
    if tls:
        out[prefix + "USE_TLS"] = _bool_str(tls.get("enabled", False))
        if "verify" in tls:
            out[prefix + "TLS_VERIFY"] = _bool_str(tls["verify"])

    auth = broker.get("auth") or {}
    method = str(auth.get("method", "none")).lower()
    if "topic_token" in auth:
        out[prefix + "TOPIC_TOKEN"] = str(auth["topic_token"])
    if method == "token":
        out[prefix + "USE_AUTH_TOKEN"] = "true"
        if "audience" in auth:
            out[prefix + "TOKEN_AUDIENCE"] = str(auth["audience"])
        if "token_ttl" in auth:
            out[prefix + "TOKEN_TTL"] = str(int(auth["token_ttl"]))
        if "owner" in auth:
            out[prefix + "TOKEN_OWNER"] = str(auth["owner"])
        if "email" in auth:
            out[prefix + "TOKEN_EMAIL"] = str(auth["email"])
    elif method == "password":
        out[prefix + "USE_AUTH_TOKEN"] = "false"
        if "username" in auth:
            out[prefix + "USERNAME"] = str(auth["username"])
        if "password" in auth:
            out[prefix + "PASSWORD"] = str(auth["password"])
    else:
        out[prefix + "USE_AUTH_TOKEN"] = "false"

    topics = broker.get("topics") or {}
    for tkey, tval in topics.items():
        u = tkey.upper()
        out[f"{prefix}TOPIC_{u}"] = str(tval)

    return out


def flatten_config_to_env_dict(config: dict[str, Any]) -> dict[str, str]:
    """Turn merged TOML into PACKETCAPTURE_* environment keys."""
    env: dict[str, str] = {}

    general = config.get("general") or {}
    if "iata" in general:
        env["PACKETCAPTURE_IATA"] = str(general["iata"])
    if "log_level" in general:
        env["PACKETCAPTURE_LOG_LEVEL"] = str(general["log_level"])

    topics = config.get("topics") or {}
    for tkey, tval in topics.items():
        env["PACKETCAPTURE_TOPIC_" + str(tkey).upper()] = str(tval)

    serial = config.get("serial") or {}
    if "ports" in serial:
        ports = serial["ports"]
        if isinstance(ports, list):
            env["PACKETCAPTURE_SERIAL_PORTS"] = ",".join(str(p) for p in ports)
        else:
            env["PACKETCAPTURE_SERIAL_PORTS"] = str(ports)
    if "baud_rate" in serial:
        env["PACKETCAPTURE_SERIAL_BAUD_RATE"] = str(int(serial["baud_rate"]))
    if "timeout" in serial:
        env["PACKETCAPTURE_SERIAL_TIMEOUT"] = str(int(serial["timeout"]))

    update = config.get("update") or {}
    if "repo" in update:
        env["PACKETCAPTURE_UPDATE_REPO"] = str(update["repo"])
    if "branch" in update:
        env["PACKETCAPTURE_UPDATE_BRANCH"] = str(update["branch"])

    capture = config.get("capture") or {}
    _CAPTURE_MAP = {
        "connection_type": "CONNECTION_TYPE",
        "timeout": "TIMEOUT",
        "tcp_host": "TCP_HOST",
        "tcp_port": "TCP_PORT",
        "ble_address": "BLE_ADDRESS",
        "ble_device": "BLE_DEVICE",
        "ble_device_name": "BLE_DEVICE_NAME",
        "ble_name": "BLE_NAME",
        "origin": "ORIGIN",
        "origin_id": "ORIGIN_ID",
        "private_key": "PRIVATE_KEY",
        "private_key_file": "PRIVATE_KEY_FILE",
        "advert_interval_hours": "ADVERT_INTERVAL_HOURS",
        "data_dir": "DATA_DIR",
        "max_connection_retries": "MAX_CONNECTION_RETRIES",
        "connection_retry_delay": "CONNECTION_RETRY_DELAY",
        "connection_retry_delay_max": "CONNECTION_RETRY_DELAY_MAX",
        "connection_retry_backoff_multiplier": "CONNECTION_RETRY_BACKOFF_MULTIPLIER",
        "connection_retry_jitter": "CONNECTION_RETRY_JITTER",
        "health_check_interval": "HEALTH_CHECK_INTERVAL",
        "health_check_grace_period": "HEALTH_CHECK_GRACE_PERIOD",
        "device_command_retry_limit": "DEVICE_COMMAND_RETRY_LIMIT",
        "ble_command_retry_limit": "BLE_COMMAND_RETRY_LIMIT",
        "tcp_command_retry_limit": "TCP_COMMAND_RETRY_LIMIT",
        "health_check_retry_limit": "HEALTH_CHECK_RETRY_LIMIT",
        "stats_retry_limit": "STATS_RETRY_LIMIT",
        "device_info_retry_limit": "DEVICE_INFO_RETRY_LIMIT",
        "stats_in_status_enabled": "STATS_IN_STATUS_ENABLED",
        "stats_refresh_interval": "STATS_REFRESH_INTERVAL",
        "max_service_failures": "MAX_SERVICE_FAILURES",
        "service_failure_window": "SERVICE_FAILURE_WINDOW",
        "critical_failure_threshold": "CRITICAL_FAILURE_THRESHOLD",
        "max_consecutive_failures": "MAX_CONSECUTIVE_FAILURES",
        "mqtt_health_check_interval": "MQTT_HEALTH_CHECK_INTERVAL",
        "mqtt_grace_period": "MQTT_GRACE_PERIOD",
        "raw_duplicate_window": "RAW_DUPLICATE_WINDOW",
        "drain_messages": "DRAIN_MESSAGES",
        "max_mqtt_retries": "MAX_MQTT_RETRIES",
        "mqtt_retry_delay": "MQTT_RETRY_DELAY",
        "jwt_renewal_interval": "JWT_RENEWAL_INTERVAL",
        "jwt_renewal_threshold": "JWT_RENEWAL_THRESHOLD",
        "rf_data_timeout": "RF_DATA_TIMEOUT",
        "upload_packet_types": "UPLOAD_PACKET_TYPES",
        "tcp_keepalive_enabled": "TCP_KEEPALIVE_ENABLED",
        # Alias for legacy PACKETCAPTURE_TCP_KEEPALIVE naming.
        "tcp_keepalive": "TCP_KEEPALIVE_ENABLED",
        "tcp_keepalive_idle": "TCP_KEEPALIVE_IDLE",
        "tcp_keepalive_interval": "TCP_KEEPALIVE_INTERVAL",
        "tcp_keepalive_count": "TCP_KEEPALIVE_COUNT",
        "tcp_sdk_auto_reconnect_enabled": "TCP_SDK_AUTO_RECONNECT_ENABLED",
        "tcp_sdk_max_reconnect_attempts": "TCP_SDK_MAX_RECONNECT_ATTEMPTS",
        "exit_on_reconnect_fail": "EXIT_ON_RECONNECT_FAIL",
        "owner_public_key": "OWNER_PUBLIC_KEY",
        "owner_email": "OWNER_EMAIL",
        "binary_interface_enabled": "BINARY_INTERFACE_ENABLED",
        "binary_interface_host": "BINARY_INTERFACE_HOST",
        "binary_interface_port": "BINARY_INTERFACE_PORT",
        "binary_interface_stats_interval": "BINARY_INTERFACE_STATS_INTERVAL",
        "binary_interface_event_buffer_timeout": "BINARY_INTERFACE_EVENT_BUFFER_TIMEOUT",
    }
    for tkey, ekey in _CAPTURE_MAP.items():
        if tkey in capture:
            val = capture[tkey]
            if isinstance(val, bool):
                env["PACKETCAPTURE_" + ekey] = _bool_str(val)
            elif isinstance(val, float):
                env["PACKETCAPTURE_" + ekey] = str(val)
            elif isinstance(val, int):
                env["PACKETCAPTURE_" + ekey] = str(val)
            else:
                env["PACKETCAPTURE_" + ekey] = str(val)

    brokers = config.get("broker") or []
    slot = 1
    for broker in brokers:
        if not broker.get("enabled", False):
            continue
        for k, v in _broker_to_env_slot(broker, slot).items():
            env["PACKETCAPTURE_" + k] = v
        slot += 1

    return env


def apply_config_to_environ(
    config_paths: list[str] | None = None,
    *,
    base_path: str = DEFAULT_CONFIG_FILE,
    config_d: str = DEFAULT_CONFIG_D,
    protected: set[str] | None = None,
) -> dict[str, Any]:
    """Load TOML and apply it to os.environ as PACKETCAPTURE_* keys.

    Precedence: TOML wins over values that were only sourced from ``.env`` files,
    but never overrides the real process environment. Pass ``protected`` with the
    set of keys present in ``os.environ`` *before* any ``.env`` files were loaded
    (the genuine process env). Those keys are left untouched; every other key is
    overwritten by the TOML value. When ``protected`` is ``None`` the legacy
    behavior is used: only keys absent from ``os.environ`` are set.
    """
    cfg = load_config(config_paths, base_path=base_path, config_d=config_d)
    for key, value in flatten_config_to_env_dict(cfg).items():
        if protected is None:
            if key not in os.environ:
                os.environ[key] = value
        elif key not in protected:
            os.environ[key] = value
    return cfg
