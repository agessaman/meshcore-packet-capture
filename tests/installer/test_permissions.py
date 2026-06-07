"""Tests for installer.system.set_permissions ownership/mode logic (no root needed)."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from installer import system as sysmod


def test_set_permissions_ownership_and_modes(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    install_dir = tmp_path / "opt"
    config_dir = tmp_path / "etc"
    (config_dir / "config.d").mkdir(parents=True)
    (config_dir / "config.toml").write_text("")
    install_dir.mkdir()

    chowns: list[tuple] = []
    chmods: dict[str, int] = {}
    monkeypatch.setattr(sysmod, "chown_recursive", lambda p, u, g: chowns.append((p, u, g)))
    monkeypatch.setattr(sysmod.os, "chmod", lambda p, mode: chmods.__setitem__(str(p), mode))

    sysmod.set_permissions(str(install_dir), str(config_dir), "svc")

    # /opt owned by svc:svc, /etc owned by root:svc
    assert (str(install_dir), "svc", "svc") in chowns
    assert (str(config_dir), "root", "svc") in chowns
    # config dir world-readable, config.d 0755, config.toml 0644
    assert chmods[str(config_dir)] == 0o755
    assert chmods[str(config_dir / "config.d")] == 0o755
    assert chmods[str(config_dir / "config.toml")] == 0o644


def test_set_permissions_skips_absent_optional_paths(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    install_dir = tmp_path / "opt"
    config_dir = tmp_path / "etc"
    config_dir.mkdir()
    install_dir.mkdir()

    chmods: dict[str, int] = {}
    monkeypatch.setattr(sysmod, "chown_recursive", lambda *a: None)
    monkeypatch.setattr(sysmod.os, "chmod", lambda p, mode: chmods.__setitem__(str(p), mode))

    sysmod.set_permissions(str(install_dir), str(config_dir), "svc")
    # Only the config dir itself is chmod'd; no config.d / config.toml present.
    assert set(chmods) == {str(config_dir)}
