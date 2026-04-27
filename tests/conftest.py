"""Shared pytest fixtures and dependency stubs."""
from __future__ import annotations

import os
import sys
import types

import pytest


def _install_dependency_stubs() -> None:
    if "meshcore" not in sys.modules:
        meshcore_stub = types.ModuleType("meshcore")
        meshcore_stub.EventType = type("EventType", (), {"ERROR": "ERROR"})
        sys.modules["meshcore"] = meshcore_stub

    if "paho" not in sys.modules:
        paho_module = types.ModuleType("paho")
        mqtt_module = types.ModuleType("paho.mqtt")
        mqtt_client_module = types.ModuleType("paho.mqtt.client")
        mqtt_module.client = mqtt_client_module
        paho_module.mqtt = mqtt_module
        sys.modules["paho"] = paho_module
        sys.modules["paho.mqtt"] = mqtt_module
        sys.modules["paho.mqtt.client"] = mqtt_client_module


_install_dependency_stubs()


@pytest.fixture(autouse=True)
def isolate_packetcapture_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep PACKETCAPTURE_* env keys from leaking across tests."""
    for key in list(os.environ):
        if key.startswith("PACKETCAPTURE_") or key == "MESHCORE_PACKETCAPTURE_ENV_DIR":
            monkeypatch.delenv(key, raising=False)
