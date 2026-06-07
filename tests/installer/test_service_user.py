"""Tests for installer.system.detect_service_user resolution logic."""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from installer import InstallerContext
from installer import system as sysmod


def _ctx(tmp_path: Path) -> InstallerContext:
    ctx = InstallerContext()
    ctx.install_dir = str(tmp_path / "opt")
    Path(ctx.install_dir).mkdir(parents=True, exist_ok=True)
    return ctx


def test_default_when_nothing_detected(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    ctx = _ctx(tmp_path)
    monkeypatch.setattr(sysmod.pwd, "getpwall", lambda: [])
    assert sysmod.detect_service_user(ctx) == ctx.svc_user


def test_inherits_passwd_user_matching_install_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    ctx = _ctx(tmp_path)
    entries = [
        SimpleNamespace(pw_name="root", pw_dir="/root"),
        SimpleNamespace(pw_name="meshcore-capture", pw_dir=ctx.install_dir),
    ]
    monkeypatch.setattr(sysmod.pwd, "getpwall", lambda: entries)
    assert sysmod.detect_service_user(ctx) == "meshcore-capture"


def test_inherits_unit_user_for_1_1_plus(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    ctx = _ctx(tmp_path)
    # 1.1+ install marker
    (Path(ctx.install_dir) / ".version_info").write_text(
        json.dumps({"installer_version": "1.1.0.0"})
    )
    unit = tmp_path / "unit.service"
    unit.write_text("[Service]\nUser=customsvc\n")

    real_path = sysmod.Path

    def _fake_path(value):
        if str(value) == "/etc/systemd/system/meshcore-packet-capture.service":
            return unit
        return real_path(value)

    monkeypatch.setattr(sysmod, "Path", _fake_path)
    monkeypatch.setattr(sysmod.pwd, "getpwall", lambda: [])
    assert sysmod.detect_service_user(ctx) == "customsvc"


def test_pre_1_1_install_ignores_unit_user(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    ctx = _ctx(tmp_path)
    (Path(ctx.install_dir) / ".version_info").write_text(
        json.dumps({"installer_version": "1.0.0"})
    )
    monkeypatch.setattr(sysmod.pwd, "getpwall", lambda: [])
    # Version too old to inherit a unit user -> falls back to default.
    assert sysmod.detect_service_user(ctx) == ctx.svc_user
