"""Helpers for channel-message capture topic wiring."""

from __future__ import annotations

from typing import Any, Optional


def broker_wants_channel(capture: Any, broker_num: int) -> bool:
    """Return True when this broker explicitly opted into channel export."""
    try:
        return bool(capture._broker_wants_channel(broker_num))
    except Exception:
        return False


def resolve_channel_topic(capture: Any, broker_num: int, channel_idx: Any) -> Optional[str]:
    """Resolve the channel topic for a broker that has opted in.

    Returns None when the broker did not set ``channel = true``, has no
    channel topic, or when channel_idx is missing, malformed, or outside
    0-255. This prevents misrouting to channel 0 on invalid input and
    prevents a global ``[topics] channel`` template from enabling export.
    """
    if not broker_wants_channel(capture, broker_num):
        return None

    channel_topic = capture.get_topic("channel", broker_num)
    if not channel_topic:
        return None

    if channel_idx is None:
        return None

    if isinstance(channel_idx, str) and channel_idx.strip() == "":
        return None

    try:
        channel_value = int(channel_idx)
    except (TypeError, ValueError):
        return None

    if channel_value < 0 or channel_value > 255:
        return None

    if "{CHANNEL}" in channel_topic:
        return channel_topic.replace("{CHANNEL}", str(channel_value))
    return f"{channel_topic.rstrip('/')}/{channel_value}"


def channel_topic_enabled_on_any_broker(capture: Any) -> bool:
    """Return True when an enabled broker opted in and has a routable topic."""
    for broker_num in capture.iter_configured_mqtt_brokers():
        if not capture.get_env_bool(f"MQTT{broker_num}_ENABLED", False):
            continue
        if not broker_wants_channel(capture, broker_num):
            continue
        if capture.get_topic("channel", broker_num):
            return True
    return False
