"""Smoke tests for the bootstrap shell scripts (install.sh / uninstall.sh)."""
from __future__ import annotations

import os
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
    assert (
        'REPO="${MESHCORE_PACKET_CAPTURE_REPO:-'
        '${MESHCORE_PACKETCAPTURE_REPO:-'
        '${PACKETCAPTURE_REPO:-agessaman/meshcore-packet-capture}}}"'
    ) in text
    assert ":-main}" in text  # BRANCH default
    # Runs the Python installer module rather than embedding logic.
    assert "python3 -m installer install" in text
    assert "python3 -m installer install" in text and "< /dev/tty" in text
    assert "interactive installs cannot be run with 'curl | sudo bash'" in text
    assert "tmp=\\$(mktemp)" in text
    # Honors the offline LOCAL_INSTALL path.
    assert "LOCAL_INSTALL" in text


def test_install_sh_user_service_uses_repo_local_configs():
    text = (REPO_ROOT / "install.sh").read_text()

    assert "--user-service" in text
    assert "MESHCORE_PACKETCAPTURE_ENV_DIR=$REPO_DIR" in text
    assert "CONFIG_ARGS_ESCAPED" in text
    assert "systemd_quote_exec_arg" in text
    assert "ExecStart=env $PYTHON_EXECUTABLE -m meshcore_packet_capture" in text
    assert 'if [ -f "$REPO_DIR/config.toml" ]; then' in text
    assert "config.d" in text


def test_install_sh_managed_help_is_forwarded_to_python_installer():
    env = os.environ.copy()
    env["LOCAL_INSTALL"] = str(REPO_ROOT)

    result = subprocess.run(
        ["bash", str(REPO_ROOT / "install.sh"), "--help"],
        env=env,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert "--config CONFIG_URL" in result.stdout
    assert "--update" in result.stdout


def test_install_sh_user_service_help_stays_in_bootstrap():
    result = subprocess.run(
        [
            "bash",
            str(REPO_ROOT / "install.sh"),
            "--user-service",
            "--repo-dir",
            "/path/does/not/exist",
            "--help",
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert "install a per-user systemd service" in result.stdout
    assert "--remove-venv" not in result.stdout


def test_install_sh_release_ref_handling():
    text = (REPO_ROOT / "install.sh").read_text()
    # Accepts a pinned release tag and forwards it to the Python installer.
    assert "--tag)" in text
    assert 'TAG_ARGS=("--tag" "$2")' in text
    # Downloads from either heads/ or tags/ depending on the chosen ref.
    assert "/archive/refs/$BOOT_KIND/$BOOT_REF.tar.gz" in text
    # Only pins INSTALL_BRANCH when the user explicitly chose a branch, so that an
    # unpinned install lets the Python layer resolve the latest release.
    assert 'if [ "$BRANCH_EXPLICIT" = true ]; then' in text
    assert "export INSTALL_BRANCH=" in text


def test_install_sh_tag_placed_before_install_subcommand():
    """Regression test for #38: --tag must be a global argparse option placed
    before the install subcommand, not after."""
    text = (REPO_ROOT / "install.sh").read_text()
    assert 'python3 -m installer "${TAG_ARGS[@]}" install "${EXTRA_ARGS[@]}"' in text
