"""Tests for MQTT broker label resolution."""
from __future__ import annotations

import pytest

from meshcore_packet_capture.packet_capture import PacketCapture


@pytest.fixture
def capture() -> PacketCapture:
    return PacketCapture(enable_mqtt=False)


def test_get_broker_label_uses_configured_name(
    monkeypatch: pytest.MonkeyPatch, capture: PacketCapture
) -> None:
    monkeypatch.setenv("PACKETCAPTURE_MQTT1_NAME", "letsmesh-eu")
    monkeypatch.setenv("PACKETCAPTURE_MQTT1_SERVER", "mqtt-eu-v1.letsmesh.net")
    assert capture.get_broker_label(1) == "letsmesh-eu"


def test_get_broker_label_falls_back_to_server(
    monkeypatch: pytest.MonkeyPatch, capture: PacketCapture
) -> None:
    monkeypatch.delenv("PACKETCAPTURE_MQTT2_NAME", raising=False)
    monkeypatch.setenv("PACKETCAPTURE_MQTT2_SERVER", "mqtt-eu-v1.letsmesh.net")
    assert capture.get_broker_label(2) == "mqtt-eu-v1.letsmesh.net"


def test_get_broker_label_falls_back_to_slot(
    monkeypatch: pytest.MonkeyPatch, capture: PacketCapture
) -> None:
    monkeypatch.delenv("PACKETCAPTURE_MQTT3_NAME", raising=False)
    monkeypatch.delenv("PACKETCAPTURE_MQTT3_SERVER", raising=False)
    assert capture.get_broker_label(3) == "MQTT3"
