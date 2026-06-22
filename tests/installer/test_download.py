"""Tests for installer.system.download_repo_archive extraction logic (no network)."""
from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest

from installer import system as sysmod


def _repo_zip_bytes(top_dir: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(f"{top_dir}/README.md", "# repo\n")
        zf.writestr(f"{top_dir}/installer/__init__.py", "")
    return buf.getvalue()


def test_download_extracts_and_returns_repo_root(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    dest = tmp_path / "dl"
    dest.mkdir()
    # Simulate the network fetch by returning the archive bytes.
    monkeypatch.setattr(sysmod, "http_get", lambda *a, **k: _repo_zip_bytes("meshcore-packet-capture-main"))

    result = sysmod.download_repo_archive("agessaman/meshcore-packet-capture", "main", str(dest))
    assert result == str(dest / "meshcore-packet-capture-main")
    assert (Path(result) / "installer" / "__init__.py").exists()
    assert not (dest / "repo.zip").exists()  # cleaned up


def test_download_sanitizes_branch_with_slash(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    dest = tmp_path / "dl"
    dest.mkdir()
    monkeypatch.setattr(sysmod, "http_get", lambda *a, **k: _repo_zip_bytes("proj-feat-x"))

    result = sysmod.download_repo_archive("owner/proj", "feat/x", str(dest))
    assert result == str(dest / "proj-feat-x")


def test_download_file_uses_urllib(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    # No curl dependency: download_file must work purely via http_get (urllib).
    dest = tmp_path / "99-user.toml"
    monkeypatch.setattr(sysmod, "http_get", lambda url, **k: b'[general]\niata = "SEA"\n')

    sysmod.download_file("https://example/cfg.toml", str(dest), "99-user.toml")
    assert dest.read_text().startswith("[general]")


def test_download_file_raises_on_failure(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    dest = tmp_path / "99-user.toml"
    monkeypatch.setattr(sysmod, "http_get", lambda url, **k: None)

    with pytest.raises(RuntimeError):
        sysmod.download_file("https://example/cfg.toml", str(dest), "99-user.toml")
    assert not dest.exists()
