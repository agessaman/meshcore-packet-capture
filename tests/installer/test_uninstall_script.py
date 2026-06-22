"""Static checks for uninstall.sh service path constants."""
from __future__ import annotations

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "uninstall.sh"


def test_uninstall_launchd_paths_match_installer_label() -> None:
    content = SCRIPT.read_text()

    assert "com.meshcore.meshcore_packet_capture" in content
    assert "/Library/LaunchDaemons/${label}.plist" in content
    assert "Library/LaunchAgents/${label}.plist" in content
    assert "meshcore-packet-capture.log" in content
    assert "com.meshcore.packet-capture" not in content
    assert "meshcore-capture.log" not in content
