"""MeshCore Packet Capture installer package."""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path


def parse_version_tuple(version_str: str) -> tuple[int, ...]:
    """Parse a version string like '1.1.0.0-preview' into a comparable tuple of ints.

    Non-numeric suffixes (e.g. '-preview') are stripped. Returns (0,) on failure.
    """
    # Strip suffixes like '-preview', '-beta', etc.
    base = version_str.split("-")[0]
    try:
        return tuple(int(p) for p in base.split(".") if p)
    except (ValueError, AttributeError):
        return (0,)


def extract_version_from_file(path: str | Path) -> str:
    """Extract __version__ string from a Python source file."""
    for line in Path(path).read_text().splitlines():
        if line.startswith("__version__"):
            match = re.search(r'"([^"]+)"', line)
            if match:
                return match.group(1)
            break
    return "unknown"


@dataclass
class InstallerContext:
    """Shared state passed between installer modules."""

    repo: str = "agessaman/meshcore-packet-capture"
    branch: str = "main"  # the git ref to install (branch name or release tag)
    ref_is_tag: bool = False  # True when `branch` holds a release tag, not a branch
    install_dir: str = "/opt/meshcore-packet-capture"
    config_dir: str = "/etc/meshcore-packet-capture"
    svc_user: str = "meshcore-capture"
    script_version: str = "unknown"
    install_method: str = ""  # "1" service, "2" docker, "3" manual
    local_install: str = ""  # LOCAL_INSTALL env var
    config_url: str = ""
    update_mode: bool = False
    base_url: str = ""
    repo_dir: str = ""  # path to extracted repo archive

    def __post_init__(self) -> None:
        self.base_url = f"https://raw.githubusercontent.com/{self.repo}/{self.branch}"
