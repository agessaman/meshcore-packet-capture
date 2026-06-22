"""Smoke tests for the bootstrap shell scripts (install.sh / uninstall.sh)."""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

pytestmark = pytest.mark.skipif(
    shutil.which("bash") is None, reason="bash not available"
)


@pytest.mark.parametrize("script", ["install.sh", "uninstall.sh"])
def test_script_parses(script: str):
    path = REPO_ROOT / script
    assert path.exists(), f"{script} missing"
    result = subprocess.run(["bash", "-n", str(path)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_install_sh_default_repo_and_branch():
    text = (REPO_ROOT / "install.sh").read_text()
    assert "agessaman/meshcore-packet-capture" in text
    assert ":-main}" in text  # BRANCH default
    # Runs the Python installer module rather than embedding logic.
    assert "python3 -m installer install" in text
    assert "python3 -m installer install" in text and "< /dev/tty" in text
    assert "interactive installs cannot be run with 'curl | sudo bash'" in text
    assert "tmp=\\$(mktemp)" in text
    # Honors the offline LOCAL_INSTALL path.
    assert "LOCAL_INSTALL" in text


def test_install_sh_release_ref_handling():
    text = (REPO_ROOT / "install.sh").read_text()
    # Accepts a pinned release tag and forwards it to the Python installer.
    assert "--tag)" in text
    assert 'EXTRA_ARGS+=("--tag" "$2")' in text
    # Downloads from either heads/ or tags/ depending on the chosen ref.
    assert "/archive/refs/$BOOT_KIND/$BOOT_REF.tar.gz" in text
    # Only pins INSTALL_BRANCH when the user explicitly chose a branch, so that an
    # unpinned install lets the Python layer resolve the latest release.
    assert 'if [ "$BRANCH_EXPLICIT" = true ]; then' in text
    assert "export INSTALL_BRANCH=" in text
