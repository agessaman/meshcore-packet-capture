"""Channel-message capture routing and subscription tests."""
from __future__ import annotations

import types

import pytest

from meshcore_packet_capture import packet_capture as pc_mod
from meshcore_packet_capture.packet_capture import PacketCapture


@pytest.mark.asyncio
async def test_handle_decoded_message_event_routes_channel_topic_per_broker(
    capture: PacketCapture,
) -> None:
    published: list[tuple[str | None, str]] = []

    capture.enable_mqtt = True
    capture.mqtt_connected = True
    capture.mqtt_clients = [{"client": object(), "broker_num": 1, "label": "mqtt1"}]

    def _get_topic(topic_type, broker_num=None):
        assert broker_num == 1
        if topic_type == "decoded":
            return "meshcore/private/ABC123/decoded"
        if topic_type == "direct":
            return "meshcore/private/ABC123/direct"
        if topic_type == "channel":
            return "meshcore/private/ABC123/channel/{CHANNEL}"
        return None

    def _publish(topic, payload, **_kwargs):
        published.append((topic, payload))
        return {"attempted": 1, "succeeded": 1}

    capture.get_topic = _get_topic  # type: ignore[method-assign]
    capture.safe_publish = _publish  # type: ignore[method-assign]

    event = types.SimpleNamespace(
        type="CHANNEL_MSG_RECV",
        payload={
            "type": "CHAN",
            "text": "hello channel",
            "from": "node-a",
            "channel_idx": 3,
            "msg_id": "msg-2",
        },
    )

    await capture.handle_decoded_message_event(event)

    assert published
    assert published[0][0] == "meshcore/private/ABC123/decoded"
    assert published[1][0] == "meshcore/private/ABC123/channel/3"


@pytest.mark.asyncio
async def test_setup_event_handlers_subscribes_channel_when_channel_configured(
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
    monkeypatch.setenv("PACKETCAPTURE_MQTT1_TOPIC_CHANNEL", "meshcore/private/{PUBLIC_KEY}/channel/{CHANNEL}")

    capture.meshcore = types.SimpleNamespace(
        subscribe=lambda event_name, handler: subscribed.append((event_name, handler)),
        dispatcher=types.SimpleNamespace(subscriptions=[]),
        unsubscribe=lambda _subscription: None,
    )

    await capture.setup_event_handlers()

    subscribed_names = {name for name, _handler in subscribed}
    assert "CONTACT_MSG_RECV" not in subscribed_names
    assert "CHANNEL_MSG_RECV" in subscribed_names
