"""Tests for packaging/systemd/ble-disconnect.sh (ExecStopPost BLE teardown)."""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "packaging" / "systemd" / "ble-disconnect.sh"

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")


def _fake_bluetoothctl(tmp_path: Path) -> Path:
    """A stub `bluetoothctl` on PATH that records its args."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    log = tmp_path / "btctl.log"
    stub = bindir / "bluetoothctl"
    stub.write_text(f'#!/bin/bash\necho "$@" >> "{log}"\n')
    stub.chmod(0o755)
    return bindir


def _run(config_d: Path, tmp_path: Path, with_btctl: bool = True):
    env = {"PATH": "/usr/bin:/bin"}
    if with_btctl:
        env["PATH"] = f"{_fake_bluetoothctl(tmp_path)}:{env['PATH']}"
    result = subprocess.run(
        ["bash", str(SCRIPT), str(config_d)],
        capture_output=True, text=True, env=env,
    )
    log = tmp_path / "btctl.log"
    invoked = log.read_text().strip() if log.exists() else ""
    return result, invoked


def test_syntax_ok():
    assert subprocess.run(["bash", "-n", str(SCRIPT)]).returncode == 0


def test_ble_with_address_disconnects(tmp_path: Path):
    cd = tmp_path / "config.d"
    cd.mkdir()
    (cd / "99-user.toml").write_text(
        '[capture]\nconnection_type = "ble"\nble_address = "E5:8B:A7:E3:51:56"\n'
    )
    result, invoked = _run(cd, tmp_path)
    assert result.returncode == 0
    assert invoked == "disconnect E5:8B:A7:E3:51:56"


def test_serial_is_noop(tmp_path: Path):
    cd = tmp_path / "config.d"
    cd.mkdir()
    (cd / "99-user.toml").write_text('[capture]\nconnection_type = "serial"\n\n[serial]\nports = ["/dev/ttyUSB0"]\n')
    result, invoked = _run(cd, tmp_path)
    assert result.returncode == 0
    assert invoked == ""  # bluetoothctl never called


def test_ble_without_address_is_noop(tmp_path: Path):
    cd = tmp_path / "config.d"
    cd.mkdir()
    (cd / "99-user.toml").write_text('[capture]\nconnection_type = "ble"\n')
    result, invoked = _run(cd, tmp_path)
    assert result.returncode == 0
    assert invoked == ""


def test_no_bluetoothctl_exits_clean(tmp_path: Path):
    cd = tmp_path / "config.d"
    cd.mkdir()
    (cd / "99-user.toml").write_text(
        '[capture]\nconnection_type = "ble"\nble_address = "AA:BB:CC:DD:EE:FF"\n'
    )
    result, _ = _run(cd, tmp_path, with_btctl=False)
    assert result.returncode == 0  # missing bluetoothctl must not fail the stop


def test_missing_config_dir_is_noop(tmp_path: Path):
    result, invoked = _run(tmp_path / "nonexistent", tmp_path)
    assert result.returncode == 0
    assert invoked == ""
