
"""Regression tests for MQTT health after failed startup connections."""

import pytest

from meshcore_packet_capture.packet_capture import PacketCapture


def test_failed_initial_mqtt_connection_becomes_unhealthy(monkeypatch):
    monkeypatch.setenv("PACKETCAPTURE_MQTT1_ENABLED", "true")

    capture = PacketCapture(enable_mqtt=True)
    capture.mqtt_clients = []
    capture.mqtt_grace_period = 180

    # Simulate the state after all initial MQTT connections failed.
    assert capture.check_mqtt_health() is True

    # The health check must start tracking the failed broker.
    assert 1 in capture.mqtt_disconnect_timestamps

    # Simulate the broker remaining unavailable beyond the grace period.
    for broker_num in (1,):
        capture.mqtt_disconnect_timestamps[broker_num] -= 181

    assert capture.check_mqtt_health() is False
