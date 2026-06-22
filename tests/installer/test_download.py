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


def test_download_tag_uses_tags_ref_and_strips_v(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    dest = tmp_path / "dl"
    dest.mkdir()
    seen = {}

    def _http_get(url, **k):
        seen["url"] = url
        return _repo_zip_bytes("meshcore-packet-capture-2.0.0")  # GitHub drops the leading 'v'

    monkeypatch.setattr(sysmod, "http_get", _http_get)

    result = sysmod.download_repo_archive(
        "agessaman/meshcore-packet-capture", "v2.0.0", str(dest), is_tag=True
    )
    assert "/archive/refs/tags/v2.0.0.zip" in seen["url"]
    assert result == str(dest / "meshcore-packet-capture-2.0.0")


def test_latest_release_tag(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(sysmod, "http_get", lambda url, **k: b'{"tag_name": "v2.3.1"}')
    assert sysmod.latest_release_tag("owner/repo") == "v2.3.1"

    monkeypatch.setattr(sysmod, "http_get", lambda url, **k: None)  # no releases / network fail
    assert sysmod.latest_release_tag("owner/repo") is None


def test_resolve_install_ref_precedence(monkeypatch: pytest.MonkeyPatch):
    # Explicit branch wins, no network lookup.
    monkeypatch.setattr(sysmod, "latest_release_tag", lambda r: pytest.fail("should not query"))
    assert sysmod.resolve_install_ref("o/r", branch="dev") == ("dev", False)
    # Explicit tag next.
    assert sysmod.resolve_install_ref("o/r", tag="v1.2.3") == ("v1.2.3", True)
    # Local install skips the network and uses main.
    assert sysmod.resolve_install_ref("o/r", local_install="/src") == ("main", False)


def test_resolve_install_ref_latest_then_fallback(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(sysmod, "latest_release_tag", lambda r: "v2.0.0")
    assert sysmod.resolve_install_ref("o/r") == ("v2.0.0", True)

    monkeypatch.setattr(sysmod, "latest_release_tag", lambda r: None)
    assert sysmod.resolve_install_ref("o/r") == ("main", False)
