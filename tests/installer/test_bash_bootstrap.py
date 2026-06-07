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
    # Honors the offline LOCAL_INSTALL path.
    assert "LOCAL_INSTALL" in text
