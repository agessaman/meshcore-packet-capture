"""Helpers for decoded message-event capture and publishing."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Optional

from .channel_capture import resolve_channel_topic
from .direct_capture import resolve_direct_topic


def _coerce_signal_value(value: Any) -> Optional[float]:
    """Convert a signal value to float when possible."""
    try:
        if value is None:
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


def _extract_signal_from_mapping(mapping: dict[str, Any]) -> tuple[Optional[float], Optional[float]]:
    """Extract SNR/RSSI values from a mapping with common key variants."""
    snr = _coerce_signal_value(mapping.get("snr"))
    if snr is None:
        snr = _coerce_signal_value(mapping.get("SNR"))

    rssi = _coerce_signal_value(mapping.get("rssi"))
    if rssi is None:
        rssi = _coerce_signal_value(mapping.get("RSSI"))

    return snr, rssi


def _best_effort_message_signal(payload: dict[str, Any]) -> tuple[Optional[float], Optional[float]]:
    """Best-effort SNR/RSSI for decoded message events."""
    snr, rssi = _extract_signal_from_mapping(payload)

    metadata = payload.get("metadata")
    if isinstance(metadata, dict):
        signal_block = metadata.get("signal")
        if isinstance(signal_block, dict):
            nested_snr, nested_rssi = _extract_signal_from_mapping(signal_block)
            if snr is None:
                snr = nested_snr
            if rssi is None:
                rssi = nested_rssi

    attributes = payload.get("attributes")
    if isinstance(attributes, dict):
        attr_snr, attr_rssi = _extract_signal_from_mapping(attributes)
        if snr is None:
            snr = attr_snr
        if rssi is None:
            rssi = attr_rssi

    return snr, rssi


def _sanitize_for_log(value: Any, max_len: int = 120) -> str:
    """Sanitize a value for safe logging, preventing newline/log injection."""
    if value is None:
        return "-"
    if not isinstance(value, str):
        value = str(value)
    # Replace newline, carriage return, tab to avoid log injection
    value = value.replace("\n", " ").replace("\r", " ").replace("\t", " ")
    # Strip other control chars (<32) except space
    value = "".join(ch for ch in value if ord(ch) >= 32)
    if len(value) > max_len:
        value = value[:max_len] + "..."
    return value


def _should_log_content(capture: Any) -> bool:
    """Return True if full message content logging is explicitly enabled."""
    # Separate option for message content to avoid persistent plaintext in logs by default
    try:
        return bool(capture.get_env_bool("LOG_DECODED_CONTENT", False))
    except Exception:
        return False


def _broker_wants_raw(capture: Any, broker_num: int) -> bool:
    """Per-broker opt-in for raw SDK event_payload export.

    Defaults to global INCLUDE_DECODED_RAW, which itself defaults to False.
    Raw payload is only exported when explicitly enabled per-broker.
    """
    try:
        raw_val = capture.get_env(f"MQTT{broker_num}_INCLUDE_DECODED_RAW", "")
        if raw_val != "":
            return str(raw_val).strip().lower() in ("true", "1", "yes", "on")
        return bool(capture.get_env_bool("INCLUDE_DECODED_RAW", False))
    except Exception:
        return False


async def handle_decoded_message_event(capture: Any, event: Any) -> None:
    """Handle decoded MeshCore message events and publish message content.

    Security properties enforced:
    - Cross-broker isolation: a broker receives a direct/channel message only when
      it explicitly enables that message type (DIRECT or CHANNEL topic). This prevents
      a private direct message configured for broker 1 from leaking to broker 2 via
      its generic decoded topic.
    - Channel validation: invalid or missing channel indices are rejected (no fallback
      to channel 0) to prevent misrouting / ACL bypass.
    - Logging: metadata only by default, sanitized to prevent log injection.
      Full message bodies require LOG_DECODED_CONTENT=true.
    - Payload schema: allowlisted, versioned schema by default. Raw SDK payload
      (event_payload) is only exported when per-broker INCLUDE_DECODED_RAW is enabled.
    """
    try:
        payload = getattr(event, "payload", None)
        if not isinstance(payload, dict):
            if capture.debug:
                capture.logger.debug(f"Skipping message event without dict payload: {payload}")
            return

        event_type_name = str(getattr(event, "type", "UNKNOWN")).split(".")[-1]
        message_type = payload.get("type", "")

        is_channel = message_type == "CHAN" or event_type_name == "CHANNEL_MSG_RECV"
        direction = "channel" if is_channel else "direct"
        snr, rssi = _best_effort_message_signal(payload)

        # Allowlisted, versioned schema by default
        message_data = {
            "schema_version": 1,
            "origin": capture.device_name or capture.get_env("ORIGIN", "MeshCore Device"),
            "origin_id": capture.device_public_key.upper()
            if capture.device_public_key and capture.device_public_key != "Unknown"
            else None,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "type": "DECODED_MESSAGE",
            "event_type": event_type_name,
            "direction": direction,
            "message": payload.get("text", ""),
            "message_type": message_type,
            "from": payload.get("from"),
            "to": payload.get("to"),
            "channel_idx": payload.get("channel_idx"),
            "pubkey_prefix": payload.get("pubkey_prefix"),
            "msg_id": payload.get("msg_id"),
            "snr": snr,
            "rssi": rssi,
        }

        # Drop None/empty-string keys for compactness
        message_data = {
            key: value for key, value in message_data.items() if value not in (None, "")
        }

        # Sanitized metadata logging by default
        from_sanitized = _sanitize_for_log(message_data.get("from", "unknown"))
        channel_sanitized = _sanitize_for_log(message_data.get("channel_idx", "-"), max_len=10)
        msg_id_sanitized = _sanitize_for_log(message_data.get("msg_id", "-"))
        type_sanitized = _sanitize_for_log(event_type_name)

        if _should_log_content(capture):
            content_sanitized = _sanitize_for_log(message_data.get("message", ""), max_len=200)
            capture.logger.info(
                f"Decoded {direction} message from={from_sanitized} "
                f"channel={channel_sanitized} msg_id={msg_id_sanitized} "
                f"type={type_sanitized}: {content_sanitized}"
            )
        else:
            # Metadata only – avoids persistent plaintext copies and injection
            capture.logger.info(
                f"Decoded {direction} message from={from_sanitized} "
                f"channel={channel_sanitized} msg_id={msg_id_sanitized} type={type_sanitized}"
            )

        if not capture.enable_mqtt:
            return

        if not capture.mqtt_clients:
            return

        for mqtt_client_info in capture.mqtt_clients:
            broker_num = mqtt_client_info["broker_num"]
            mqtt_client = mqtt_client_info["client"]

            # Resolve direction-specific topic – this is the explicit opt-in check.
            # Each broker only receives message content when it explicitly enables that type.
            if direction == "channel":
                message_topic = resolve_channel_topic(
                    capture,
                    broker_num,
                    payload.get("channel_idx"),
                )
                # If channel_idx invalid/missing or broker has no channel topic, skip broker
                if message_topic is None:
                    if capture.debug:
                        # Distinguish invalid channel vs missing config
                        has_channel_cfg = capture.get_topic("channel", broker_num) is not None
                        if has_channel_cfg:
                            capture.logger.debug(
                                f"Skipping channel message for broker {broker_num}: "
                                f"invalid channel_idx={payload.get('channel_idx')!r}"
                            )
                        else:
                            capture.logger.debug(
                                f"Skipping channel message for broker {broker_num}: "
                                "channel topic not configured (cross-broker isolation)"
                            )
                    continue
            else:
                message_topic = resolve_direct_topic(capture, broker_num)
                if message_topic is None:
                    if capture.debug:
                        capture.logger.debug(
                            f"Skipping direct message for broker {broker_num}: "
                            "direct topic not configured (cross-broker isolation)"
                        )
                    continue

            # Build per-broker payload with optional raw export
            per_broker_data = dict(message_data)
            if _broker_wants_raw(capture, broker_num):
                per_broker_data["event_payload"] = payload

            payload_json = json.dumps(per_broker_data)

            decoded_topic = capture.get_topic("decoded", broker_num)
            # Publish to decoded topic only for brokers that explicitly enabled this type
            # (prevents private direct messages leaking via generic decoded topic on other brokers)
            if decoded_topic:
                capture.safe_publish(
                    decoded_topic,
                    payload_json,
                    client=mqtt_client,
                    broker_num=broker_num,
                )
            if message_topic:
                capture.safe_publish(
                    message_topic,
                    payload_json,
                    client=mqtt_client,
                    broker_num=broker_num,
                )

    except Exception as e:
        capture.logger.error(f"Error handling decoded message event: {e}")
