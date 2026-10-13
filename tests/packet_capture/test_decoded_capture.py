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


@pytest.mark.asyncio
async def test_cross_broker_isolation_direct_not_leaked_to_decoded_only_broker(
    capture: PacketCapture,
) -> None:
    """Broker with only decoded topic must not receive direct messages intended for another broker."""
    published: list[tuple[str | None, int | None]] = []

    capture.enable_mqtt = True
    capture.mqtt_connected = True
    capture.mqtt_clients = [
        {"client": object(), "broker_num": 1, "label": "private"},
        {"client": object(), "broker_num": 2, "label": "community"},
    ]

    def _get_topic(topic_type, broker_num=None):
        if broker_num == 1 and topic_type == "direct":
            return "meshcore/private/direct"
        if broker_num == 2 and topic_type == "decoded":
            return "meshcore/community/decoded"
        return None

    def _publish(topic, payload, **kwargs):
        published.append((topic, kwargs.get("broker_num")))
        return {"attempted": 1, "succeeded": 1}

    capture.get_topic = _get_topic  # type: ignore[method-assign]
    capture.safe_publish = _publish

    event = types.SimpleNamespace(
        type="CONTACT_MSG_RECV",
        payload={
            "type": "PRIV",
            "text": "secret private message",
            "from": "node-a",
            "msg_id": "msg-private",
        },
    )

    await capture.handle_decoded_message_event(event)

    # Only broker 1 (direct enabled) should receive; broker 2 (decoded-only) must not leak
    broker_nums = [bnum for _, bnum in published]
    assert 1 in broker_nums
    assert 2 not in broker_nums
    assert len(published) == 1
    assert published[0][0] == "meshcore/private/direct"


@pytest.mark.asyncio
async def test_cross_broker_isolation_channel_not_leaked(
    capture: PacketCapture,
) -> None:
    published: list[tuple[str | None, int | None]] = []

    capture.enable_mqtt = True
    capture.mqtt_connected = True
    capture.mqtt_clients = [
        {"client": object(), "broker_num": 1, "label": "private"},
        {"client": object(), "broker_num": 2, "label": "community"},
    ]

    def _get_topic(topic_type, broker_num=None):
        if broker_num == 1 and topic_type == "channel":
            return "meshcore/private/channel/{CHANNEL}"
        if broker_num == 2 and topic_type == "decoded":
            return "meshcore/community/decoded"
        return None

    def _publish(topic, payload, **kwargs):
        published.append((topic, kwargs.get("broker_num")))
        return {"attempted": 1, "succeeded": 1}

    capture.get_topic = _get_topic  # type: ignore[method-assign]
    capture.safe_publish = _publish

    event = types.SimpleNamespace(
        type="CHANNEL_MSG_RECV",
        payload={
            "type": "CHAN",
            "text": "channel secret",
            "from": "node-a",
            "channel_idx": 2,
            "msg_id": "msg-chan",
        },
    )

    await capture.handle_decoded_message_event(event)

    broker_nums = [bnum for _, bnum in published]
    assert 1 in broker_nums
    assert 2 not in broker_nums


@pytest.mark.asyncio
async def test_invalid_channel_idx_rejected(
    capture: PacketCapture,
) -> None:
    """Malformed or out-of-range channel indices must not route to channel 0."""
    published: list[tuple[str | None, str]] = []

    capture.enable_mqtt = True
    capture.mqtt_connected = True
    capture.mqtt_clients = [{"client": object(), "broker_num": 1, "label": "mqtt1"}]

    def _get_topic(topic_type, broker_num=None):
        if topic_type == "channel":
            return "meshcore/private/channel/{CHANNEL}"
        return None

    def _publish(topic, payload, **kwargs):
        published.append((topic, payload))
        return {"attempted": 1, "succeeded": 1}

    capture.get_topic = _get_topic  # type: ignore[method-assign]
    capture.safe_publish = _publish

    invalid_indices = [None, "", "not-a-number", -1, 999, 256]

    for invalid in invalid_indices:
        published.clear()
        event = types.SimpleNamespace(
            type="CHANNEL_MSG_RECV",
            payload={
                "type": "CHAN",
                "text": "test",
                "from": "node-a",
                "channel_idx": invalid,
                "msg_id": "msg-invalid",
            },
        )
        await capture.handle_decoded_message_event(event)
        assert published == [], f"Should not publish for invalid channel_idx={invalid!r}"


@pytest.mark.asyncio
async def test_valid_channel_idx_accepted(
    capture: PacketCapture,
) -> None:
    published: list[tuple[str | None, str]] = []

    capture.enable_mqtt = True
    capture.mqtt_connected = True
    capture.mqtt_clients = [{"client": object(), "broker_num": 1, "label": "mqtt1"}]

    def _get_topic(topic_type, broker_num=None):
        if topic_type == "channel":
            return "meshcore/private/channel/{CHANNEL}"
        return None

    def _publish(topic, payload, **kwargs):
        published.append((topic, payload))
        return {"attempted": 1, "succeeded": 1}

    capture.get_topic = _get_topic  # type: ignore[method-assign]
    capture.safe_publish = _publish

    for valid in [0, 1, 3, 255, "5"]:
        published.clear()
        event = types.SimpleNamespace(
            type="CHANNEL_MSG_RECV",
            payload={
                "type": "CHAN",
                "text": "test",
                "from": "node-a",
                "channel_idx": valid,
                "msg_id": "msg-valid",
            },
        )
        await capture.handle_decoded_message_event(event)
        assert len(published) == 1
        expected_idx = int(valid) if isinstance(valid, str) else valid
        assert published[0][0] == f"meshcore/private/channel/{expected_idx}"


@pytest.mark.asyncio
async def test_logging_metadata_only_by_default(
    capture: PacketCapture, caplog: pytest.LogCaptureFixture
) -> None:
    """INFO logs should not contain decrypted message bodies by default."""
    import logging

    published: list[tuple[str | None, str]] = []

    capture.enable_mqtt = True
    capture.mqtt_connected = True
    capture.mqtt_clients = [{"client": object(), "broker_num": 1, "label": "mqtt1"}]

    def _get_topic(topic_type, broker_num=None):
        if topic_type == "direct":
            return "meshcore/private/direct"
        return None

    def _publish(topic, payload, **kwargs):
        published.append((topic, payload))
        return {"attempted": 1, "succeeded": 1}

    capture.get_topic = _get_topic  # type: ignore[method-assign]
    capture.safe_publish = _publish
    capture.logger.setLevel(logging.INFO)

    event = types.SimpleNamespace(
        type="CONTACT_MSG_RECV",
        payload={
            "type": "PRIV",
            "text": "super secret message\nwith newline",
            "from": "node-a",
            "msg_id": "msg-secret",
        },
    )

    with caplog.at_level(logging.INFO):
        await capture.handle_decoded_message_event(event)

    log_text = "\n".join(rec.message for rec in caplog.records)
    assert "super secret message" not in log_text, "Message body should not be logged by default"
    assert "node-a" in log_text
    # No newline injection from message
    for rec in caplog.records:
        assert "\n" not in rec.message or "super secret" not in rec.message


@pytest.mark.asyncio
async def test_logging_with_content_option_includes_sanitized_body(
    capture: PacketCapture, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    import logging

    published: list[tuple[str | None, str]] = []
    capture.enable_mqtt = True
    capture.mqtt_connected = True
    capture.mqtt_clients = [{"client": object(), "broker_num": 1, "label": "mqtt1"}]

    def _get_topic(topic_type, broker_num=None):
        if topic_type == "direct":
            return "meshcore/private/direct"
        return None

    def _publish(topic, payload, **kwargs):
        published.append((topic, payload))
        return {"attempted": 1, "succeeded": 1}

    capture.get_topic = _get_topic  # type: ignore[method-assign]
    capture.safe_publish = _publish
    capture.logger.setLevel(logging.INFO)
    monkeypatch.setenv("PACKETCAPTURE_LOG_DECODED_CONTENT", "true")

    event = types.SimpleNamespace(
        type="CONTACT_MSG_RECV",
        payload={
            "type": "PRIV",
            "text": "hello world",
            "from": "node-a",
            "msg_id": "msg-1",
        },
    )

    with caplog.at_level(logging.INFO):
        await capture.handle_decoded_message_event(event)

    log_text = "\n".join(rec.message for rec in caplog.records)
    assert "hello world" in log_text


@pytest.mark.asyncio
async def test_default_payload_excludes_raw_and_has_version(
    capture: PacketCapture,
) -> None:
    """Allowlisted schema by default, versioned, no raw event_payload."""
    published: list[tuple[str | None, str]] = []

    capture.enable_mqtt = True
    capture.mqtt_connected = True
    capture.mqtt_clients = [{"client": object(), "broker_num": 1, "label": "mqtt1"}]

    def _get_topic(topic_type, broker_num=None):
        if topic_type == "direct":
            return "meshcore/private/direct"
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
            "text": "hello",
            "from": "node-a",
            "msg_id": "msg-1",
            "extra_unexpected_field": "should not leak",
        },
    )

    await capture.handle_decoded_message_event(event)

    payload_json = json.loads(published[0][1])
    assert payload_json["schema_version"] == 1
    assert "event_payload" not in payload_json
    assert "extra_unexpected_field" not in payload_json
    assert payload_json["message"] == "hello"
    assert payload_json["type"] == "DECODED_MESSAGE"


@pytest.mark.asyncio
async def test_raw_payload_opt_in_per_broker(
    capture: PacketCapture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Raw payload only exported when per-broker INCLUDE_DECODED_RAW is enabled."""
    published: list[tuple[str | None, str, int | None]] = []

    capture.enable_mqtt = True
    capture.mqtt_connected = True
    capture.mqtt_clients = [
        {"client": object(), "broker_num": 1, "label": "private"},
        {"client": object(), "broker_num": 2, "label": "community"},
    ]

    def _get_topic(topic_type, broker_num=None):
        if topic_type == "direct":
            return f"meshcore/{broker_num}/direct"
        return None

    def _publish(topic, payload, **kwargs):
        published.append((topic, payload, kwargs.get("broker_num")))
        return {"attempted": 1, "succeeded": 1}

    capture.get_topic = _get_topic  # type: ignore[method-assign]
    capture.safe_publish = _publish

    monkeypatch.setenv("PACKETCAPTURE_MQTT2_INCLUDE_DECODED_RAW", "true")

    event = types.SimpleNamespace(
        type="CONTACT_MSG_RECV",
        payload={
            "type": "PRIV",
            "text": "hello",
            "from": "node-a",
            "msg_id": "msg-1",
            "sdk_meta": "raw value",
        },
    )

    await capture.handle_decoded_message_event(event)

    # Broker 1 should NOT have event_payload, broker 2 should
    for _topic, payload_str, broker_num in published:
        data = json.loads(payload_str)
        if broker_num == 1:
            assert "event_payload" not in data
        else:
            assert "event_payload" in data
            assert data["event_payload"]["sdk_meta"] == "raw value"
