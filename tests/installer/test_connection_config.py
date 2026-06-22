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
    return SimpleNamespace(
        install_dir=str(tmp_path), repo_dir="", local_install="",
        repo="agessaman/meshcore-packet-capture", branch="main",
    )


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


# --- half-configured TOML detection + repair ----------------------------------

def test_has_connection_true_and_false(tmp_path: Path):
    has = tmp_path / "has.toml"
    has.write_text('[capture]\nconnection_type = "ble"\n')
    assert cfg._user_toml_has_connection(has) is True

    without = tmp_path / "without.toml"
    without.write_text('[general]\niata = "PAE"\n')  # aborted: no connection
    assert cfg._user_toml_has_connection(without) is False

    assert cfg._user_toml_has_connection(tmp_path / "missing.toml") is False


def test_apply_connection_preserves_existing_keys(tmp_path: Path):
    # Simulate a half-written config: IATA + a broker, but no connection.
    dest = tmp_path / "99-user.toml"
    dest.write_text(
        '[general]\niata = "PAE"\n\n'
        '[[broker]]\nname = "waev"\nenabled = true\nserver = "mqtt.waev.app"\n'
    )
    cfg.apply_connection_to_user_toml(dest, {
        "type": "ble", "ble_address": "AA:BB:CC:DD:EE:FF", "ble_device_name": "MeshCore-X",
    })
    data = _parse(dest)
    # Connection added…
    assert data["capture"]["connection_type"] == "ble"
    assert data["capture"]["ble_address"] == "AA:BB:CC:DD:EE:FF"
    # …and existing keys preserved.
    assert data["general"]["iata"] == "PAE"
    assert data["broker"][0]["name"] == "waev"


def test_apply_connection_switch_clears_stale_keys(tmp_path: Path):
    dest = tmp_path / "99-user.toml"
    dest.write_text(
        '[general]\niata = "PAE"\n\n'
        '[capture]\nconnection_type = "ble"\nble_address = "AA:BB:CC:DD:EE:FF"\n'
    )
    cfg.apply_connection_to_user_toml(dest, {"type": "serial", "serial_device": "/dev/ttyUSB0"})
    data = _parse(dest)
    assert data["capture"]["connection_type"] == "serial"
    assert "ble_address" not in data["capture"]  # stale BLE key removed
    assert data["serial"]["ports"] == ["/dev/ttyUSB0"]


def test_connection_type_helper(tmp_path: Path):
    p = tmp_path / "u.toml"
    p.write_text('[capture]\nconnection_type = "tcp"\n')
    assert cfg._user_toml_connection_type(p) == "tcp"
    assert cfg._user_toml_connection_type(tmp_path / "missing.toml") == ""


def test_configure_device_connection_writes_when_missing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    dest = tmp_path / "99-user.toml"  # does not exist
    monkeypatch.setattr(cfg, "select_connection_type",
                        lambda ctx, default_type="ble": {"type": "tcp", "tcp_host": "h", "tcp_port": 5000})
    cfg.configure_device_connection(_ctx(tmp_path), str(dest))
    assert _parse(dest)["capture"]["connection_type"] == "tcp"


def test_configure_device_connection_keeps_when_declined(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    dest = tmp_path / "99-user.toml"
    dest.write_text('[general]\niata = "PAE"\n\n[capture]\nconnection_type = "serial"\n\n[serial]\nports = ["/dev/ttyUSB0"]\n')
    monkeypatch.setattr(cfg, "prompt_yes_no", lambda *a, **k: False)  # decline reconfigure
    called = []
    monkeypatch.setattr(cfg, "select_connection_type", lambda *a, **k: called.append(1) or {})
    cfg.configure_device_connection(_ctx(tmp_path), str(dest))
    assert called == []  # never prompted for a new connection
    assert _parse(dest)["capture"]["connection_type"] == "serial"  # unchanged


def test_configure_device_connection_reconfigures_when_accepted(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    dest = tmp_path / "99-user.toml"
    dest.write_text('[general]\niata = "PAE"\n\n[capture]\nconnection_type = "serial"\n\n[serial]\nports = ["/dev/ttyUSB0"]\n')
    monkeypatch.setattr(cfg, "prompt_yes_no", lambda *a, **k: True)  # accept reconfigure
    seen_default = {}
    def _sel(ctx, default_type="ble", current=None):
        seen_default["v"] = default_type
        seen_default["current"] = current
        return {"type": "ble", "ble_address": "AA:BB:CC:DD:EE:FF", "ble_device_name": "X"}
    monkeypatch.setattr(cfg, "select_connection_type", _sel)
    cfg.configure_device_connection(_ctx(tmp_path), str(dest))
    data = _parse(dest)
    assert data["capture"]["connection_type"] == "ble"
    assert data["capture"]["ble_address"] == "AA:BB:CC:DD:EE:FF"
    assert "serial" not in data  # serial section dropped on switch
    assert data["general"]["iata"] == "PAE"  # preserved
    assert seen_default["v"] == "serial"  # menu defaulted to the current type
    assert seen_default["current"]["serial_device"] == "/dev/ttyUSB0"  # existing values passed as defaults


def test_ensure_bluez_noop_off_linux(monkeypatch: pytest.MonkeyPatch):
    from installer import system as sysmod
    monkeypatch.setattr(sysmod.platform, "system", lambda: "Darwin")
    assert sysmod.ensure_bluez() is True


def test_ensure_bluez_present_starts_service(monkeypatch: pytest.MonkeyPatch):
    from installer import system as sysmod
    monkeypatch.setattr(sysmod.platform, "system", lambda: "Linux")
    monkeypatch.setattr(sysmod.shutil, "which", lambda name: "/usr/bin/bluetoothctl" if name == "bluetoothctl" else None)
    calls = []
    monkeypatch.setattr(sysmod, "run_cmd", lambda cmd, **k: calls.append(cmd))
    assert sysmod.ensure_bluez() is True  # already present -> no install prompt
