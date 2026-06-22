"""Focused tests for installer.system helpers."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest

from installer import system as sysmod


@dataclass
class _CmdResult:
    returncode: int = 0
    stdout: str = ""
    stderr: str = ""


def test_install_systemd_uses_template_and_rewrites_user_group(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    install_dir = tmp_path / "install"
    install_dir.mkdir(parents=True, exist_ok=True)
    (install_dir / "meshcore-packet-capture.service").write_text(
        "[Service]\n"
        "User=olduser\n"
        "Group=oldgroup\n"
        "ExecStart=/opt/meshcore-packet-capture/venv/bin/python3 -m meshcore_packet_capture\n"
    )

    unit_dir = tmp_path / "etc" / "systemd" / "system"
    unit_dir.mkdir(parents=True, exist_ok=True)

    def _fake_path(value: str | Path) -> Path:
        p = Path(value)
        if str(p).startswith("/etc/systemd/system/"):
            return unit_dir / p.name
        return p

    commands: list[list[str]] = []
    monkeypatch.setattr(sysmod, "Path", _fake_path)
    monkeypatch.setattr(
        sysmod,
        "run_cmd",
        lambda cmd, **_k: commands.append(cmd) or _CmdResult(returncode=1, stdout=""),
    )
    monkeypatch.setattr(sysmod, "prompt_yes_no", lambda *_a, **_k: False)

    ok = sysmod.install_systemd_service(str(install_dir), str(tmp_path / "cfg"), "svc-user")
    assert ok is True

    rendered = (unit_dir / "meshcore-packet-capture.service").read_text()
    assert "User=svc-user" in rendered
    assert "Group=svc-user" in rendered
    assert "ExecStart=/opt/meshcore-packet-capture/venv/bin/python3 -m meshcore_packet_capture" in rendered
    assert ["systemctl", "daemon-reload"] in commands


def test_install_systemd_fallback_preserves_ble_service_behavior(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    install_dir = tmp_path / "install"
    install_dir.mkdir(parents=True, exist_ok=True)
    unit_dir = tmp_path / "etc" / "systemd" / "system"
    unit_dir.mkdir(parents=True, exist_ok=True)

    real_path = sysmod.Path

    def _fake_path(value: str | Path) -> Path:
        p = real_path(value)
        if str(p).startswith("/etc/systemd/system/"):
            return unit_dir / p.name
        return p

    monkeypatch.setattr(sysmod, "Path", _fake_path)
    monkeypatch.setattr(sysmod, "run_cmd", lambda *_a, **_k: _CmdResult(returncode=1, stdout=""))
    monkeypatch.setattr(sysmod, "prompt_yes_no", lambda *_a, **_k: False)

    ok = sysmod.install_systemd_service(str(install_dir), str(tmp_path / "cfg"), "svc-user")
    assert ok is True

    rendered = (unit_dir / "meshcore-packet-capture.service").read_text()
    assert "After=time-sync.target network-online.target bluetooth.target" in rendered
    assert f"ExecStopPost={install_dir}/ble-disconnect.sh" in rendered
    assert 'Environment="PATH=/usr/local/bin:/usr/bin:/bin"' in rendered
    assert f"ReadWritePaths={install_dir} /var/lib/meshcore-packet-capture" in rendered


def test_create_system_user_adds_serial_and_bluetooth_groups(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls: list[list[str]] = []

    def _fake_run(cmd: list[str], **_kwargs) -> _CmdResult:
        calls.append(cmd)
        if cmd[:2] == ["getent", "group"]:
            return _CmdResult(returncode=0)
        if cmd[0] == "id":
            return _CmdResult(returncode=0)
        return _CmdResult(returncode=0)

    monkeypatch.setattr(sysmod.platform, "system", lambda: "Linux")
    monkeypatch.setattr(sysmod, "run_cmd", _fake_run)

    sysmod.create_system_user("svc-user", str(tmp_path / "install"))

    assert (
        ["usermod", "-aG", "dialout", "svc-user"] in calls
        or ["usermod", "-aG", "uucp", "svc-user"] in calls
    )
    assert ["usermod", "-aG", "bluetooth", "svc-user"] in calls


def test_pip_install_project_calls_expected_command(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    install_dir = tmp_path / "install"
    pip_path = install_dir / "venv" / "bin" / "pip"
    pip_path.parent.mkdir(parents=True, exist_ok=True)
    pip_path.write_text("#!/bin/sh\n")

    calls: list[list[str]] = []
    monkeypatch.setattr(sysmod, "run_cmd", lambda cmd, **_k: calls.append(cmd) or _CmdResult(returncode=0))

    sysmod.pip_install_project(str(install_dir), upgrade=True)
    assert calls == [[str(pip_path), "install", "--quiet", "--upgrade", str(install_dir)]]


def test_pip_install_project_requires_venv_pip(tmp_path: Path) -> None:
    with pytest.raises(SystemExit):
        sysmod.pip_install_project(str(tmp_path / "missing"))


def test_docker_group_args_resolves_gid(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        sysmod.grp, "getgrnam",
        lambda name: type("G", (), {"gr_gid": 4242})(),
    )
    assert sysmod.docker_group_args("meshcore-capture") == ["--group-add", "4242"]


def test_docker_group_args_empty_when_no_user_or_group(monkeypatch: pytest.MonkeyPatch) -> None:
    assert sysmod.docker_group_args("") == []

    def _raise(name):
        raise KeyError(name)

    monkeypatch.setattr(sysmod.grp, "getgrnam", _raise)
    assert sysmod.docker_group_args("nonexistent") == []
