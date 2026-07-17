"""Helpers for channel-message capture topic wiring."""

from __future__ import annotations

from typing import Any, Optional


def resolve_channel_topic(capture: Any, broker_num: int, channel_idx: Any) -> Optional[str]:
    """Resolve the configured channel topic for a broker and channel index."""
    channel_topic = capture.get_topic("channel", broker_num)
    if not channel_topic:
        return None

    try:
        channel_value = int(channel_idx)
    except (TypeError, ValueError):
        channel_value = 0

    if "{CHANNEL}" in channel_topic:
        return channel_topic.replace("{CHANNEL}", str(channel_value))
    return f"{channel_topic.rstrip('/')}/{channel_value}"


def channel_topic_enabled_on_any_broker(capture: Any) -> bool:
    """Return True when channel topic resolves for any enabled broker."""
    for broker_num in capture.iter_configured_mqtt_brokers():
        if not capture.get_env_bool(f"MQTT{broker_num}_ENABLED", False):
            continue
        if capture.get_topic("channel", broker_num):
            return True
    return False
