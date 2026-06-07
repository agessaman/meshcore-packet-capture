"""Tests for the legacy-install detection / migration sentinel helpers."""
from __future__ import annotations

from pathlib import Path

import pytest

import installer.migrate_cmd as mc


def test_detect_old_installation_found(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    old = tmp_path / ".meshcore-packet-capture"
    old.mkdir()
    (old / "packet_capture.py").write_text("# legacy launcher\n")
    monkeypatch.setattr(mc, "_real_user_home", lambda: tmp_path)
    assert mc.detect_old_installation() == str(old)


def test_detect_old_installation_absent(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.setattr(mc, "_real_user_home", lambda: tmp_path)
    assert mc.detect_old_installation() is None


def test_detect_requires_launcher_marker(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    # Directory exists but has no packet_capture.py -> not a legacy install.
    (tmp_path / ".meshcore-packet-capture").mkdir()
    monkeypatch.setattr(mc, "_real_user_home", lambda: tmp_path)
    assert mc.detect_old_installation() is None


def test_migration_sentinel_roundtrip(tmp_path: Path):
    old = tmp_path / "old"
    old.mkdir()
    assert mc.is_already_migrated(str(old)) is False
    mc.mark_migrated(str(old), "/opt/meshcore-packet-capture")
    assert mc.is_already_migrated(str(old)) is True
    assert "/opt/meshcore-packet-capture" in (old / mc._MIGRATED_SENTINEL).read_text()
