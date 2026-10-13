"""Direct-message capture routing and subscription tests."""
from __future__ import annotations

import types

import pytest

from meshcore_packet_capture import packet_capture as pc_mod
from meshcore_packet_capture.packet_capture import PacketCapture


@pytest.mark.asyncio
async def test_handle_decoded_message_event_routes_direct_topic_per_broker(
    capture: PacketCapture,
) -> None:
    published: list[tuple[str | None, str, object | None, int | None]] = []

    capture.enable_mqtt = True
    capture.mqtt_connected = True
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
        return None

    def _publish(topic, payload, **kwargs):
        published.append((topic, payload, kwargs.get("client"), kwargs.get("broker_num")))
        return {"attempted": 1, "succeeded": 1}

    capture.get_topic = _get_topic  # type: ignore[method-assign]
    capture.safe_publish = _publish  # type: ignore[method-assign]

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


@pytest.mark.asyncio
async def test_setup_event_handlers_does_not_subscribe_message_events(
    monkeypatch: pytest.MonkeyPatch, capture: PacketCapture
) -> None:
    subscribed: list[tuple[str, object]] = []

    event_type = types.SimpleNamespace(
        RX_LOG_DATA="RX_LOG_DATA",
        RAW_DATA="RAW_DATA",
        STATUS_RESPONSE="STATUS_RESPONSE",
        CONTACT_MSG_RECV="CONTACT_MSG_RECV",
        CHANNEL_MSG_RECV="CHANNEL_MSG_RECV",
        DISCONNECTED="DISCONNECTED",
    )
    monkeypatch.setattr(pc_mod, "EventType", event_type)

    capture.meshcore = types.SimpleNamespace(
        subscribe=lambda event_name, handler: subscribed.append((event_name, handler)),
        dispatcher=types.SimpleNamespace(subscriptions=[]),
        unsubscribe=lambda _subscription: None,
    )

    await capture.setup_event_handlers()

    subscribed_names = {name for name, _handler in subscribed}
    assert "CONTACT_MSG_RECV" not in subscribed_names
    assert "CHANNEL_MSG_RECV" not in subscribed_names


@pytest.mark.asyncio
async def test_setup_event_handlers_subscribes_contact_when_direct_configured(
    monkeypatch: pytest.MonkeyPatch, capture: PacketCapture
) -> None:
    subscribed: list[tuple[str, object]] = []

    event_type = types.SimpleNamespace(
        RX_LOG_DATA="RX_LOG_DATA",
        RAW_DATA="RAW_DATA",
        STATUS_RESPONSE="STATUS_RESPONSE",
        CONTACT_MSG_RECV="CONTACT_MSG_RECV",
        CHANNEL_MSG_RECV="CHANNEL_MSG_RECV",
        DISCONNECTED="DISCONNECTED",
    )
    monkeypatch.setattr(pc_mod, "EventType", event_type)
    monkeypatch.setenv("PACKETCAPTURE_MQTT1_ENABLED", "true")
    monkeypatch.setenv("PACKETCAPTURE_MQTT1_TOPIC_DIRECT", "meshcore/private/{PUBLIC_KEY}/direct")

    capture.meshcore = types.SimpleNamespace(
        subscribe=lambda event_name, handler: subscribed.append((event_name, handler)),
        dispatcher=types.SimpleNamespace(subscriptions=[]),
        unsubscribe=lambda _subscription: None,
    )

    await capture.setup_event_handlers()

    subscribed_names = {name for name, _handler in subscribed}
    assert "CONTACT_MSG_RECV" in subscribed_names
    assert "CHANNEL_MSG_RECV" not in subscribed_names
