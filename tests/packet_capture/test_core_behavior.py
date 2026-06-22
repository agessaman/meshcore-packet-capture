"""Core packet-capture behavior tests (parsing + retry/shutdown state)."""
from __future__ import annotations

import asyncio
import json
import types

import pytest

from meshcore_packet_capture import packet_capture as pc_mod
from meshcore_packet_capture.enums import PayloadType
from meshcore_packet_capture.packet_capture import PacketCapture


@pytest.fixture
def capture() -> PacketCapture:
    return PacketCapture(enable_mqtt=False)


def test_retry_delay_uses_backoff_and_jitter(monkeypatch: pytest.MonkeyPatch, capture: PacketCapture) -> None:
    capture.connection_retry_delay = 2
    capture.connection_retry_backoff_multiplier = 2.0
    capture.connection_retry_delay_max = 100
    capture.connection_retry_jitter = True

    # delay for attempt=3 => 2 * 2^(3-1) = 8 ; with jitter 1.25 => 10
    monkeypatch.setattr("random.uniform", lambda _a, _b: 1.25)
    assert capture.calculate_connection_retry_delay(3) == 10


def test_track_consecutive_failure_triggers_service_exit(capture: PacketCapture) -> None:
    capture.max_consecutive_failures = 2
    capture.max_service_failures = 1
    capture.service_failure_window = 3600

    assert capture.track_consecutive_failure("connection") is False
    assert capture.should_exit is False
    assert capture.track_consecutive_failure("connection") is True
    assert capture.should_exit is True


def test_ble_grace_period_allows_then_fails(capture: PacketCapture) -> None:
    capture.connection_type = "ble"
    capture.health_check_grace_period = 2
    capture.health_check_failure_count = 0
    capture.meshcore = types.SimpleNamespace(is_connected=True)

    assert capture._check_ble_grace_period("timed out") is True
    assert capture._check_ble_grace_period("timed out") is True
    assert capture._check_ble_grace_period("timed out") is False


@pytest.mark.asyncio
async def test_wait_with_shutdown_event_returns_true(capture: PacketCapture) -> None:
    capture.shutdown_event = asyncio.Event()
    capture.shutdown_event.set()
    assert await capture.wait_with_shutdown(0.01) is True


def test_decode_unknown_packet_version_returns_none(capture: PacketCapture) -> None:
    # header version bits set to 1 (unknown), payload type ADVERT, route FLOOD
    header = ((1 & 0x03) << 6) | ((PayloadType.ADVERT.value & 0x0F) << 2) | 0
    # one-byte path (path_len=1), one-byte path data, then advert-sized payload bytes
    raw_hex = bytes([header, 0x01, 0xAA]) .hex()
    assert capture.decode_and_publish_message(raw_hex) is None


def test_decode_path_length_overflow_returns_none(capture: PacketCapture) -> None:
    # Version 0, payload type ADVERT, route FLOOD
    header = ((0 & 0x03) << 6) | ((PayloadType.ADVERT.value & 0x0F) << 2) | 0
    # claim 10 hops with 1 byte/hop, but only provide 1 byte
    raw_hex = bytes([header, 0x0A, 0xAA]).hex()
    assert capture.decode_and_publish_message(raw_hex) is None


def test_resolve_topic_template_replaces_token_placeholder(monkeypatch: pytest.MonkeyPatch, capture: PacketCapture) -> None:
    capture.global_iata = "sea"
    capture.device_public_key = "ABCDEF"
    monkeypatch.setenv("PACKETCAPTURE_MQTT1_TOPIC_TOKEN", "tok123")
    topic = capture.resolve_topic_template("meshrank/uplink/{TOKEN}/{PUBLIC_KEY}/packets", broker_num=1)
    assert topic == "meshrank/uplink/tok123/ABCDEF/packets"


@pytest.mark.asyncio
async def test_refresh_stats_fetches_packet_stats(monkeypatch: pytest.MonkeyPatch, capture: PacketCapture) -> None:
    event_type = types.SimpleNamespace(
        ERROR="error",
        STATS_CORE="stats_core",
        STATS_RADIO="stats_radio",
        STATS_PACKETS="stats_packets",
    )
    monkeypatch.setattr(pc_mod, "EventType", event_type)

    async def _core():
        return types.SimpleNamespace(type=event_type.STATS_CORE, payload={"uptime": 10})

    async def _radio():
        return types.SimpleNamespace(type=event_type.STATS_RADIO, payload={"airtime": 20})

    async def _packets():
        return types.SimpleNamespace(
            type=event_type.STATS_PACKETS,
            payload={
                "recv": 1234,
                "sent": 567,
                "flood_tx": 400,
                "direct_tx": 167,
                "flood_rx": 900,
                "direct_rx": 334,
                "recv_errors": 12,
            },
        )

    async def _retry(command, *_args, **_kwargs):
        return await command()

    capture.meshcore = types.SimpleNamespace(
        is_connected=True,
        commands=types.SimpleNamespace(
            get_stats_core=_core,
            get_stats_radio=_radio,
            get_stats_packets=_packets,
        ),
    )
    capture.retryable_device_command = _retry

    stats = await capture.refresh_stats(force=True)

    assert stats["packets_received"] == 1234
    assert stats["packets_sent"] == 567
    assert stats["recv"] == 1234
    assert stats["sent"] == 567
    assert stats["flood_tx"] == 400
    assert stats["direct_rx"] == 334
    assert stats["recv_errors"] == 12


@pytest.mark.asyncio
async def test_publish_status_includes_packet_stats_aliases(capture: PacketCapture) -> None:
    published: list[dict] = []

    async def _firmware():
        return {"model": "companion", "version": "1.2.3"}

    async def _refresh_stats(force=False):
        return {
            "recv": 1234,
            "sent": 567,
            "packets_received": 1234,
            "packets_sent": 567,
        }

    def _publish(_topic, payload, **_kwargs):
        published.append(json.loads(payload))
        return {"attempted": 1, "succeeded": 1}

    capture.get_firmware_info = _firmware
    capture.refresh_stats = _refresh_stats
    capture.safe_publish = _publish
    capture.mqtt_connected = True
    capture.device_name = "node"
    capture.device_public_key = "abc"
    capture.radio_info = {"region": "US"}

    await capture.publish_status("online")

    assert published
    assert published[0]["stats"]["packets_received"] == 1234
    assert published[0]["stats"]["packets_sent"] == 567
