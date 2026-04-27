"""Core packet-capture behavior tests (parsing + retry/shutdown state)."""
from __future__ import annotations

import asyncio
import types

import pytest

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
