"""Tests for device connection-type selection and the connection TOML writer."""
from __future__ import annotations

import tomllib
from pathlib import Path
from types import SimpleNamespace

import pytest

from installer import config as cfg


def _parse(path: Path) -> dict:
    with open(path, "rb") as f:
        return tomllib.load(f)


# --- write_user_toml_base: each connection type --------------------------------

def test_write_base_serial(tmp_path: Path):
    dest = tmp_path / "u.toml"
    cfg.write_user_toml_base(str(dest), "SEA", "owner/repo", "main",
                             {"type": "serial", "serial_device": "/dev/ttyACM0"})
    data = _parse(dest)
    assert data["capture"]["connection_type"] == "serial"
    assert data["serial"]["ports"] == ["/dev/ttyACM0"]
    assert "ble_address" not in data["capture"] and "tcp_host" not in data["capture"]


def test_write_base_ble(tmp_path: Path):
    dest = tmp_path / "u.toml"
    cfg.write_user_toml_base(str(dest), "SEA", "owner/repo", "main",
                             {"type": "ble", "ble_address": "AA:BB:CC:DD:EE:FF",
                              "ble_device_name": "MeshCore-XYZ"})
    data = _parse(dest)
    assert data["capture"]["connection_type"] == "ble"
    assert data["capture"]["ble_address"] == "AA:BB:CC:DD:EE:FF"
    assert data["capture"]["ble_device_name"] == "MeshCore-XYZ"
    assert "serial" not in data  # no serial section for BLE


def test_write_base_ble_without_address_omits_fields(tmp_path: Path):
    dest = tmp_path / "u.toml"
    cfg.write_user_toml_base(str(dest), "SEA", "owner/repo", "main", {"type": "ble"})
    data = _parse(dest)
    assert data["capture"]["connection_type"] == "ble"
    assert "ble_address" not in data["capture"]


def test_write_base_tcp(tmp_path: Path):
    dest = tmp_path / "u.toml"
    cfg.write_user_toml_base(str(dest), "SEA", "owner/repo", "main",
                             {"type": "tcp", "tcp_host": "10.0.0.5", "tcp_port": 5000})
    data = _parse(dest)
    assert data["capture"]["connection_type"] == "tcp"
    assert data["capture"]["tcp_host"] == "10.0.0.5"
    assert data["capture"]["tcp_port"] == 5000
    assert "serial" not in data


def test_write_base_default_is_serial(tmp_path: Path):
    dest = tmp_path / "u.toml"
    cfg.write_user_toml_base(str(dest), "SEA", "owner/repo", "main")
    data = _parse(dest)
    assert data["capture"]["connection_type"] == "serial"
    assert data["serial"]["ports"] == ["/dev/ttyUSB0"]


# --- select_connection_type dispatch (interactive bits mocked) -----------------

def _ctx(tmp_path: Path):
    return SimpleNamespace(install_dir=str(tmp_path), repo_dir="", local_install="")


def test_select_serial(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.setattr(cfg, "prompt_input", lambda *a, **k: "2")  # choose serial
    monkeypatch.setattr("installer.system.select_serial_device", lambda: "/dev/ttyUSB1")
    conn = cfg.select_connection_type(_ctx(tmp_path))
    assert conn == {"type": "serial", "serial_device": "/dev/ttyUSB1"}


def test_select_tcp(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    answers = iter(["3", "host.local", "6000"])  # choice, host, port
    monkeypatch.setattr(cfg, "prompt_input", lambda *a, **k: next(answers))
    conn = cfg.select_connection_type(_ctx(tmp_path))
    assert conn == {"type": "tcp", "tcp_host": "host.local", "tcp_port": 6000}


def test_select_ble_manual_no_scan(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    # choice=BLE, decline scan, enter address + name; pairing skipped (no helper)
    inputs = iter(["1", "AA:BB:CC:DD:EE:FF", "MeshCore-ABC"])
    monkeypatch.setattr(cfg, "prompt_input", lambda *a, **k: next(inputs))
    monkeypatch.setattr(cfg, "prompt_yes_no", lambda *a, **k: False)  # no scan
    conn = cfg.select_connection_type(_ctx(tmp_path))
    assert conn == {"type": "ble", "ble_address": "AA:BB:CC:DD:EE:FF", "ble_device_name": "MeshCore-ABC"}


def test_tcp_invalid_port_defaults(monkeypatch: pytest.MonkeyPatch):
    answers = iter(["notaport"])
    monkeypatch.setattr(cfg, "prompt_input", lambda prompt, default="": (
        "localhost" if "host" in prompt else next(answers)
    ))
    conn = cfg.configure_tcp_connection()
    assert conn["tcp_port"] == 5000
