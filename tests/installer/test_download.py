"""Tests for installer.system.download_repo_archive extraction logic (no network)."""
from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from installer import system as sysmod


def _make_repo_zip(zip_path: Path, top_dir: str) -> None:
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr(f"{top_dir}/README.md", "# repo\n")
        zf.writestr(f"{top_dir}/installer/__init__.py", "")


def test_download_extracts_and_returns_repo_root(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    dest = tmp_path / "dl"
    dest.mkdir()
    # Simulate curl by pre-creating the archive that run_cmd would have downloaded.
    _make_repo_zip(dest / "repo.zip", "meshcore-packet-capture-main")
    monkeypatch.setattr(sysmod, "run_cmd", lambda *a, **k: None)

    result = sysmod.download_repo_archive("agessaman/meshcore-packet-capture", "main", str(dest))
    assert result == str(dest / "meshcore-packet-capture-main")
    assert (Path(result) / "installer" / "__init__.py").exists()
    assert not (dest / "repo.zip").exists()  # cleaned up


def test_download_sanitizes_branch_with_slash(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    dest = tmp_path / "dl"
    dest.mkdir()
    _make_repo_zip(dest / "repo.zip", "proj-feat-x")
    monkeypatch.setattr(sysmod, "run_cmd", lambda *a, **k: None)

    result = sysmod.download_repo_archive("owner/proj", "feat/x", str(dest))
    assert result == str(dest / "proj-feat-x")
