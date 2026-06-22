"""Installer preset path helpers."""
from __future__ import annotations

from pathlib import Path

import pytest

from installer.config import PRESET_PREFIX, list_bundled_presets, preset_dest_path, copy_preset_to_config


def test_preset_dest_adds_prefix(tmp_path: Path):
    cfg = tmp_path / "etc"
    d = preset_dest_path(cfg, "letsmesh.toml")
    assert d.name == f"{PRESET_PREFIX}letsmesh.toml"
    assert "config.d" in str(d)


def test_preset_dest_idempotent_prefix(tmp_path: Path):
    cfg = tmp_path / "etc"
    name = f"{PRESET_PREFIX}foo.toml"
    d = preset_dest_path(cfg, name)
    assert d.name == name


def test_list_bundled_presets_repo_root():
    root = Path(__file__).resolve().parents[2]
    presets = list_bundled_presets(root)
    names = [p.name for p in presets]
    assert "letsmesh.toml" in names


def test_copy_preset_roundtrip(tmp_path: Path):
    root = Path(__file__).resolve().parents[2]
    src = root / "presets" / "letsmesh.toml"
    if not src.exists():
        pytest.skip("presets not present")
    cfg_dir = tmp_path / "etc"
    dest = copy_preset_to_config(src, cfg_dir)
    assert dest.exists()
    text = dest.read_text()
    assert "letsmesh-us" in text
