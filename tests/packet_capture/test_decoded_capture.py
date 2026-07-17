"""Decoded-message capture behavior tests."""
from __future__ import annotations

import json
import types

import pytest

from meshcore_packet_capture import packet_capture as pc_mod
from meshcore_packet_capture.packet_capture import PacketCapture


def test_get_topic_decoded_requires_explicit_config(capture: PacketCapture) -> None:
    assert capture.get_topic("decoded", broker_num=1) is None


@pytest.mark.asyncio
async def test_handle_decoded_message_event_publishes_decoded_payload(
    capture: PacketCapture,
) -> None:
    published: list[tuple[str | None, str, object | None, int | None]] = []

    capture.enable_mqtt = True
    capture.mqtt_connected = True
    capture.device_name = "node"
    capture.device_public_key = "abc123"
    client_obj = object()
    capture.mqtt_clients = [{"client": client_obj, "broker_num": 1, "label": "mqtt1"}]

    def _get_topic(topic_type, broker_num=None):
        assert broker_num == 1
        if topic_type == "decoded":
            return "meshcore/private/ABC123/decoded"
        if topic_type == "direct":
            return "meshcore/private/ABC123/direct"
        if topic_type == "channel":
            return "meshcore/private/ABC123/channel/{CHANNEL}"
        raise AssertionError(f"unexpected topic_type: {topic_type}")

    def _publish(topic, payload, **kwargs):
        published.append((topic, payload, kwargs.get("client"), kwargs.get("broker_num")))
        return {"attempted": 1, "succeeded": 1}

    capture.get_topic = _get_topic  # type: ignore[method-assign]
    capture.safe_publish = _publish

    event = types.SimpleNamespace(
        type="CONTACT_MSG_RECV",
        payload={
            "type": "PRIV",
            "text": "hello world",
            "from": "node-a",
            "pubkey_prefix": "a1b2c3",
            "msg_id": "msg-1",
        },
    )

    await capture.handle_decoded_message_event(event)

    assert published
    assert published[0][0] == "meshcore/private/ABC123/decoded"
    assert published[1][0] == "meshcore/private/ABC123/direct"
    assert published[0][2] is client_obj
    assert published[0][3] == 1
    payload_json = json.loads(published[0][1])
    assert payload_json["type"] == "DECODED_MESSAGE"
    assert payload_json["direction"] == "direct"
    assert payload_json["message"] == "hello world"
    assert payload_json["from"] == "node-a"


@pytest.mark.asyncio
async def test_handle_decoded_message_event_includes_payload_signal(
    capture: PacketCapture,
) -> None:
    published: list[tuple[str | None, str]] = []

    capture.enable_mqtt = True
    capture.mqtt_connected = True
    capture.mqtt_clients = [{"client": object(), "broker_num": 1, "label": "mqtt1"}]

    def _get_topic(topic_type, broker_num=None):
        if topic_type == "direct":
            return "meshcore/private/ABC123/direct"
        if topic_type == "channel":
            return "meshcore/private/ABC123/channel/{CHANNEL}"
        return None

    def _publish(topic, payload, **kwargs):
        published.append((topic, payload))
        return {"attempted": 1, "succeeded": 1}

    capture.get_topic = _get_topic  # type: ignore[method-assign]
    capture.safe_publish = _publish

    event = types.SimpleNamespace(
        type="CONTACT_MSG_RECV",
        payload={
            "type": "PRIV",
            "text": "hello world",
            "from": "node-a",
            "pubkey_prefix": "a1b2c3",
            "msg_id": "msg-1",
            "snr": 12.5,
            "rssi": -87,
        },
    )

    await capture.handle_decoded_message_event(event)

    payload_json = json.loads(published[0][1])
    assert payload_json["snr"] == 12.5
    assert payload_json["rssi"] == -87.0


@pytest.mark.asyncio
async def test_handle_decoded_message_event_does_not_use_rf_cache_signal(
    capture: PacketCapture,
) -> None:
    published: list[tuple[str | None, str]] = []

    capture.enable_mqtt = True
    capture.mqtt_connected = True
    capture.mqtt_clients = [{"client": object(), "broker_num": 1, "label": "mqtt1"}]
    capture.rf_data_cache = {
        "old": {"snr": 1.0, "rssi": -100, "timestamp": 1.0},
        "recent": {"snr": 7.25, "rssi": -72, "timestamp": 10.0},
    }

    def _get_topic(topic_type, broker_num=None):
        if topic_type == "direct":
            return "meshcore/private/ABC123/direct"
        if topic_type == "channel":
            return "meshcore/private/ABC123/channel/{CHANNEL}"
        return None

    def _publish(topic, payload, **kwargs):
        published.append((topic, payload))
        return {"attempted": 1, "succeeded": 1}

    capture.get_topic = _get_topic  # type: ignore[method-assign]
    capture.safe_publish = _publish

    event = types.SimpleNamespace(
        type="CONTACT_MSG_RECV",
        payload={
            "type": "PRIV",
            "text": "hello world",
            "from": "node-a",
            "pubkey_prefix": "a1b2c3",
            "msg_id": "msg-1",
        },
    )

    original_time = pc_mod.time.time
    try:
        pc_mod.time.time = lambda: 12.0
        await capture.handle_decoded_message_event(event)
    finally:
        pc_mod.time.time = original_time

    payload_json = json.loads(published[0][1])
    assert "snr" not in payload_json
    assert "rssi" not in payload_json


@pytest.mark.asyncio
async def test_handle_decoded_message_event_reads_metadata_signal(
    capture: PacketCapture,
) -> None:
    published: list[tuple[str | None, str]] = []

    capture.enable_mqtt = True
    capture.mqtt_connected = True
    capture.mqtt_clients = [{"client": object(), "broker_num": 1, "label": "mqtt1"}]

    def _get_topic(topic_type, broker_num=None):
        if topic_type == "direct":
            return "meshcore/private/ABC123/direct"
        if topic_type == "channel":
            return "meshcore/private/ABC123/channel/{CHANNEL}"
        return None

    def _publish(topic, payload, **kwargs):
        published.append((topic, payload))
        return {"attempted": 1, "succeeded": 1}

    capture.get_topic = _get_topic  # type: ignore[method-assign]
    capture.safe_publish = _publish

    event = types.SimpleNamespace(
        type="CONTACT_MSG_RECV",
        payload={
            "type": "PRIV",
            "text": "hello world",
            "from": "node-a",
            "pubkey_prefix": "a1b2c3",
            "msg_id": "msg-1",
            "metadata": {
                "signal": {
                    "SNR": 3.14,
                    "RSSI": -91,
                }
            },
        },
    )

    await capture.handle_decoded_message_event(event)

    payload_json = json.loads(published[0][1])
    assert payload_json["snr"] == 3.14
    assert payload_json["rssi"] == -91.0
