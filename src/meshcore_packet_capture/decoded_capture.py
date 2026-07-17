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


async def handle_decoded_message_event(capture: Any, event: Any) -> None:
    """Handle decoded MeshCore message events and publish message content."""
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

        message_data = {
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
            "event_payload": payload,
        }

        message_data = {
            key: value for key, value in message_data.items() if value not in (None, "")
        }

        if capture.verbose:
            capture.logger.info(f"💬 Decoded {direction} message event: {json.dumps(message_data)}")
        else:
            message_preview = message_data.get("message", "")
            capture.logger.info(
                f"💬 Decoded {direction} message"
                f" (from={message_data.get('from', 'unknown')}, "
                f"channel={message_data.get('channel_idx', '-')})"
                f": {message_preview}"
            )

        if capture.enable_mqtt:
            payload_json = json.dumps(message_data)
            if capture.mqtt_clients:
                for mqtt_client_info in capture.mqtt_clients:
                    broker_num = mqtt_client_info["broker_num"]
                    mqtt_client = mqtt_client_info["client"]
                    decoded_topic = capture.get_topic("decoded", broker_num)
                    if direction == "channel":
                        message_topic = resolve_channel_topic(
                            capture,
                            broker_num,
                            message_data.get("channel_idx"),
                        )
                    else:
                        message_topic = resolve_direct_topic(capture, broker_num)

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
