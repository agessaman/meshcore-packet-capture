"""Helpers for direct-message capture topic wiring."""

from __future__ import annotations

from typing import Any, Optional


def resolve_direct_topic(capture: Any, broker_num: int) -> Optional[str]:
    """Resolve the configured direct topic for a broker."""
    return capture.get_topic("direct", broker_num)


def direct_topic_enabled_on_any_broker(capture: Any) -> bool:
    """Return True when direct topic resolves for any enabled broker."""
    for broker_num in capture.iter_configured_mqtt_brokers():
        if not capture.get_env_bool(f"MQTT{broker_num}_ENABLED", False):
            continue
        if resolve_direct_topic(capture, broker_num):
            return True
    return False
