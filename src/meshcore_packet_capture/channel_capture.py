"""Helpers for channel-message capture topic wiring."""

from __future__ import annotations

from typing import Any, Optional


def resolve_channel_topic(capture: Any, broker_num: int, channel_idx: Any) -> Optional[str]:
    """Resolve the configured channel topic for a broker and channel index.

    Returns None when the broker has no channel topic or when channel_idx
    is missing, malformed, or out of the valid range (0-255). This prevents
    misrouting to channel 0 on invalid input.
    """
    channel_topic = capture.get_topic("channel", broker_num)
    if not channel_topic:
        return None

    if channel_idx is None:
        return None

    # Reject empty strings explicitly
    if isinstance(channel_idx, str) and channel_idx.strip() == "":
        return None

    try:
        channel_value = int(channel_idx)
    except (TypeError, ValueError):
        return None

    # Validate range: MeshCore channels are expected in 0-255.
    # Reject negative or out-of-range values to avoid ACL bypass to channel 0.
    if channel_value < 0 or channel_value > 255:
        return None

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
