"""Helpers for direct-message capture topic wiring."""

from __future__ import annotations

from typing import Any, Optional


def broker_wants_direct(capture: Any, broker_num: int) -> bool:
    """Return True when this broker explicitly opted into direct export."""
    try:
        return bool(capture._broker_wants_direct(broker_num))
    except Exception:
        return False


def resolve_direct_topic(capture: Any, broker_num: int) -> Optional[str]:
    """Resolve the direct topic only when the broker has opted in.

    A global ``[topics] direct`` template is not an ACL. Without
    ``direct = true`` on this broker, return None even if a topic string
    would otherwise resolve.
    """
    if not broker_wants_direct(capture, broker_num):
        return None
    topic = capture.get_topic("direct", broker_num)
    return topic or None


def direct_topic_enabled_on_any_broker(capture: Any) -> bool:
    """Return True when an enabled broker opted in and has a routable topic."""
    for broker_num in capture.iter_configured_mqtt_brokers():
        if not capture.get_env_bool(f"MQTT{broker_num}_ENABLED", False):
            continue
        if resolve_direct_topic(capture, broker_num):
            return True
    return False
