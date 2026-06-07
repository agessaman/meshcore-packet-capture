"""Tests for InstallerContext defaults and version helpers."""
from __future__ import annotations

from pathlib import Path

import pytest

from installer import (
    InstallerContext,
    extract_version_from_file,
    parse_version_tuple,
)


def test_context_defaults_match_fhs_layout():
    ctx = InstallerContext()
    assert ctx.repo == "agessaman/meshcore-packet-capture"
    assert ctx.branch == "main"
    assert ctx.install_dir == "/opt/meshcore-packet-capture"
    assert ctx.config_dir == "/etc/meshcore-packet-capture"
    assert ctx.svc_user == "meshcore-capture"


def test_context_base_url_derived_from_repo_and_branch():
    ctx = InstallerContext(repo="owner/proj", branch="dev")
    assert ctx.base_url == "https://raw.githubusercontent.com/owner/proj/dev"


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("1.1.0.0", (1, 1, 0, 0)),
        ("1.2.3-preview", (1, 2, 3)),
        ("2.0", (2, 0)),
        ("garbage", (0,)),
    ],
)
def test_parse_version_tuple(raw, expected):
    assert parse_version_tuple(raw) == expected


def test_version_ordering_via_tuple():
    assert parse_version_tuple("1.1") >= (1, 1)
    assert parse_version_tuple("1.0.9") < (1, 1)


def test_extract_version_from_file(tmp_path: Path):
    f = tmp_path / "ver.py"
    f.write_text('__version__ = "1.4.2"\n')
    assert extract_version_from_file(f) == "1.4.2"


def test_extract_version_missing_returns_unknown(tmp_path: Path):
    f = tmp_path / "ver.py"
    f.write_text("x = 1\n")
    assert extract_version_from_file(f) == "unknown"
