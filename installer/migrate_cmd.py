"""Migration from legacy ~/.meshcore-packet-capture to /opt/meshcore-packet-capture."""

from __future__ import annotations

import os
import platform
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

from .system import download_repo_archive, run_cmd
from .ui import (
    print_header,
    print_info,
    print_success,
    print_warning,
    prompt_yes_no,
)

if TYPE_CHECKING:
    from . import InstallerContext


# ---------------------------------------------------------------------------
# .env file parsing and TOML conversion (ported from embedded Python in bash)
# ---------------------------------------------------------------------------

def normalize_env_keys(env: dict[str, str]) -> dict[str, str]:
    """Map MCTOMQTT_* keys from legacy meshcoretomqtt-style .env to PACKETCAPTURE_."""
    out: dict[str, str] = {}
    for key, value in env.items():
        if key.startswith("MCTOMQTT_"):
            out["PACKETCAPTURE_" + key[len("MCTOMQTT_") :]] = value
        else:
            out[key] = value
    return out


def parse_env_file(path: str) -> dict[str, str]:
    """Parse a .env file into a dict."""
    env: dict[str, str] = {}
    if not path or not os.path.exists(path):
        return env
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            key, _, value = line.partition("=")
            value = value.strip()
            if "#" in value:
                quote: str | None = None
                cleaned: list[str] = []
                for idx, char in enumerate(value):
                    if char in ("'", '"'):
                        quote = None if quote == char else char if quote is None else quote
                    if char == "#" and quote is None and (idx == 0 or value[idx - 1].isspace()):
                        break
                    cleaned.append(char)
                value = "".join(cleaned).strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
                value = value[1:-1]
            env[key.strip()] = value
    return env


_MQTT_SLOT_RE = re.compile(r"^PACKETCAPTURE_MQTT(\d+)_")


def _max_broker_slot(env: dict[str, str]) -> int:
    """Highest MQTT broker slot number present in the env keys (0 if none)."""
    highest = 0
    for key in env:
        match = _MQTT_SLOT_RE.match(key)
        if match:
            highest = max(highest, int(match.group(1)))
    return highest


def env_to_toml(env: dict[str, str]) -> str:
    """Convert a merged .env dict to TOML config string."""
    lines: list[str] = []

    def _append_int(target: list[str], key: str, value: str, *, env_key: str) -> None:
        try:
            target.append(f"{key} = {int(value)}")
        except ValueError:
            print_warning(f"Skipping invalid numeric value for {env_key}: {value!r}")

    # General section
    general: dict[str, str] = {}
    iata = env.get("PACKETCAPTURE_IATA", "")
    if iata and iata != "XXX":
        general["iata"] = iata
    log_level = env.get("PACKETCAPTURE_LOG_LEVEL", "")
    if log_level and log_level != "INFO":
        general["log_level"] = log_level
    sync_time = env.get("PACKETCAPTURE_SYNC_TIME", "")
    if sync_time and sync_time.lower() != "true":
        general["sync_time"] = sync_time.lower()

    if general:
        lines.append("[general]")
        for k, v in general.items():
            if v in ("true", "false"):
                lines.append(f"{k} = {v}")
            else:
                lines.append(f'{k} = "{v}"')
        lines.append("")

    # Serial section
    ports = env.get("PACKETCAPTURE_SERIAL_PORTS", "")
    baud = env.get("PACKETCAPTURE_SERIAL_BAUD_RATE", "")
    timeout = env.get("PACKETCAPTURE_SERIAL_TIMEOUT", "")
    serial_lines: list[str] = []
    if ports or baud or timeout:
        if ports:
            port_list = [p.strip() for p in ports.split(",") if p.strip()]
            ports_str = ", ".join(f'"{p}"' for p in port_list)
            serial_lines.append(f"ports = [{ports_str}]")
        if baud and baud != "115200":
            _append_int(serial_lines, "baud_rate", baud, env_key="PACKETCAPTURE_SERIAL_BAUD_RATE")
        if timeout and timeout != "2":
            _append_int(serial_lines, "timeout", timeout, env_key="PACKETCAPTURE_SERIAL_TIMEOUT")
    if serial_lines:
        lines.append("[serial]")
        lines.extend(serial_lines)
        lines.append("")

    # Update section
    repo = env.get("PACKETCAPTURE_UPDATE_REPO", "")
    branch = env.get("PACKETCAPTURE_UPDATE_BRANCH", "")
    if repo or branch:
        lines.append("[update]")
        if repo:
            lines.append(f'repo = "{repo}"')
        if branch:
            lines.append(f'branch = "{branch}"')
        lines.append("")

    # Topics
    t_status = env.get("PACKETCAPTURE_TOPIC_STATUS", "")
    t_packets = env.get("PACKETCAPTURE_TOPIC_PACKETS", "")
    t_raw = env.get("PACKETCAPTURE_TOPIC_RAW", "")
    if t_status or t_packets or t_raw:
        lines.append("[topics]")
        if t_status:
            lines.append(f'status = "{t_status}"')
        if t_packets:
            lines.append(f'packets = "{t_packets}"')
        if t_raw:
            lines.append(f'raw = "{t_raw}"')
        lines.append("")

    capture_map = [
        ("connection_type", "PACKETCAPTURE_CONNECTION_TYPE"),
        ("timeout", "PACKETCAPTURE_TIMEOUT"),
        ("tcp_host", "PACKETCAPTURE_TCP_HOST"),
        ("tcp_port", "PACKETCAPTURE_TCP_PORT"),
        ("ble_address", "PACKETCAPTURE_BLE_ADDRESS"),
        ("ble_device", "PACKETCAPTURE_BLE_DEVICE"),
        ("ble_device_name", "PACKETCAPTURE_BLE_DEVICE_NAME"),
        ("ble_name", "PACKETCAPTURE_BLE_NAME"),
        ("origin", "PACKETCAPTURE_ORIGIN"),
        ("data_dir", "PACKETCAPTURE_DATA_DIR"),
        ("advert_interval_hours", "PACKETCAPTURE_ADVERT_INTERVAL_HOURS"),
    ]
    cap_lines: list[str] = []
    for tkey, ekey in capture_map:
        val = env.get(ekey, "")
        if val:
            if tkey in ("timeout", "tcp_port", "advert_interval_hours"):
                _append_int(cap_lines, tkey, val, env_key=ekey)
            else:
                cap_lines.append(f'{tkey} = "{val}"')
    if cap_lines:
        lines.append("[capture]")
        lines.extend(cap_lines)
        lines.append("")

    # Brokers. Discover slots dynamically rather than capping at a fixed count —
    # the legacy meshcoretomqtt .env format supported up to 6 (and the runtime
    # loader has no cap), so a hardcoded range would silently drop higher slots.
    for broker_num in range(1, _max_broker_slot(env) + 1):
        prefix = f"PACKETCAPTURE_MQTT{broker_num}_"
        enabled = env.get(f"{prefix}ENABLED", "false")
        server = env.get(f"{prefix}SERVER", "")
        if enabled != "true" or not server:
            continue

        port_val = env.get(f"{prefix}PORT", "1883")
        transport = env.get(f"{prefix}TRANSPORT", "tcp")
        use_tls = env.get(f"{prefix}USE_TLS", "false")
        tls_verify = env.get(f"{prefix}TLS_VERIFY", "true")
        use_auth_token = env.get(f"{prefix}USE_AUTH_TOKEN", "false")
        username = env.get(f"{prefix}USERNAME", "")
        password = env.get(f"{prefix}PASSWORD", "")
        token_audience = env.get(f"{prefix}TOKEN_AUDIENCE", "")
        token_owner = env.get(f"{prefix}TOKEN_OWNER", "")
        token_email = env.get(f"{prefix}TOKEN_EMAIL", "")
        keepalive = env.get(f"{prefix}KEEPALIVE", "60")
        qos = env.get(f"{prefix}QOS", "0")
        retain = env.get(f"{prefix}RETAIN", "true")

        if "letsmesh" in server:
            if "-us-" in server:
                broker_name = "letsmesh-us"
            elif "-eu-" in server:
                broker_name = "letsmesh-eu"
            else:
                broker_name = f"letsmesh-{broker_num}"
        else:
            broker_name = f"custom-{broker_num}"

        lines.append("[[broker]]")
        lines.append(f'name = "{broker_name}"')
        lines.append("enabled = true")
        lines.append(f'server = "{server}"')
        lines.append(f"port = {port_val}")
        lines.append(f'transport = "{transport}"')
        lines.append(f"keepalive = {keepalive}")
        lines.append(f"qos = {qos}")
        lines.append(f"retain = {retain}")
        lines.append("")

        if use_tls == "true":
            lines.append("[broker.tls]")
            lines.append("enabled = true")
            lines.append(f"verify = {tls_verify}")
            lines.append("")

        lines.append("[broker.auth]")
        if use_auth_token == "true":
            lines.append('method = "token"')
            if token_audience:
                lines.append(f'audience = "{token_audience}"')
            if token_owner:
                lines.append(f'owner = "{token_owner}"')
            if token_email:
                lines.append(f'email = "{token_email}"')
        elif username:
            lines.append('method = "password"')
            lines.append(f'username = "{username}"')
            lines.append(f'password = "{password}"')
        else:
            lines.append('method = "none"')
        lines.append("")

    return "\n".join(lines)


def _backup_existing_file(path: str | Path) -> None:
    """Backup an existing file before overwriting migration output."""
    target = Path(path)
    if not target.exists():
        return
    backup = target.with_suffix(target.suffix + ".backup")
    counter = 1
    while backup.exists():
        backup = target.with_suffix(target.suffix + f".backup-{counter}")
        counter += 1
    shutil.copy2(target, backup)
    print_info(f"Backed up existing configuration to {backup}")


# ---------------------------------------------------------------------------
# Migration command
# ---------------------------------------------------------------------------

def _real_user_home() -> Path:
    """Get the real user's home directory, even when running under sudo."""
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        import pwd
        return Path(pwd.getpwnam(sudo_user).pw_dir)
    return Path.home()


def detect_old_installation() -> str | None:
    """Check for legacy ~/.meshcore-packet-capture installation. Returns path or None."""
    old_dir = _real_user_home() / ".meshcore-packet-capture"
    if old_dir.is_dir() and (old_dir / "packet_capture.py").exists():
        return str(old_dir)
    return None


_MIGRATED_SENTINEL = ".migrated"


def is_already_migrated(old_dir: str) -> bool:
    """Return True if the legacy directory has already been migrated."""
    return (Path(old_dir) / _MIGRATED_SENTINEL).exists()


def mark_migrated(old_dir: str, install_dir: str) -> None:
    """Write a sentinel file so future migration runs are skipped."""
    (Path(old_dir) / _MIGRATED_SENTINEL).write_text(
        f"Migrated to {install_dir}\n"
    )


def run_migrate(ctx: InstallerContext) -> bool:
    """Migrate from ~/.meshcore-packet-capture to /opt/meshcore-packet-capture.

    Returns True if migration was performed, False if skipped/nothing to migrate.
    """
    old_dir = detect_old_installation()
    if old_dir is None:
        return False

    if is_already_migrated(old_dir):
        print_info("Legacy installation already migrated. Skipping.")
        return False

    print()
    print_header("Legacy Installation Detected")
    print_info(f"Found existing installation at: {old_dir}")
    print()

    if not prompt_yes_no(f"Migrate to new installation at {ctx.install_dir}?", "y"):
        print_info("Skipping migration. Old installation left in place.")
        return False

    # Step 1: Migrate config. Do this before touching old services so a failed
    # conversion does not leave users without their working legacy service.
    print_info("Migrating configuration to TOML format...")

    old_env = os.path.join(old_dir, ".env")
    old_env_local = os.path.join(old_dir, ".env.local")

    # Get repo's default .env for diffing
    repo_defaults: dict[str, str] = {}
    if os.path.exists(old_env):
        # Use already-downloaded repo archive if available, otherwise download it
        repo_dir = ctx.repo_dir
        if not repo_dir and ctx.local_install:
            repo_dir = ctx.local_install
        if not repo_dir:
            try:
                migrate_tmp = tempfile.mkdtemp()
                repo_dir = download_repo_archive(ctx.repo, ctx.branch, migrate_tmp)
                ctx.repo_dir = repo_dir
            except subprocess.CalledProcessError:
                repo_dir = ""

        if repo_dir:
            default_env = os.path.join(repo_dir, ".env")
            if os.path.exists(default_env):
                repo_defaults = parse_env_file(default_env)

    # Parse user's env files
    user_env = parse_env_file(old_env)
    user_env_local = parse_env_file(old_env_local)

    # Detect customizations in .env vs repo default
    env_customizations: dict[str, str] = {}
    for key, value in user_env.items():
        if key in repo_defaults and repo_defaults[key] != value:
            env_customizations[key] = value
        elif key not in repo_defaults:
            env_customizations[key] = value

    # Merge: env customizations + env.local overrides
    merged: dict[str, str] = {}
    merged.update(normalize_env_keys(env_customizations))
    merged.update(normalize_env_keys(user_env_local))

    # Create config directory
    os.makedirs(f"{ctx.config_dir}/config.d", exist_ok=True)

    migrated_toml_path = f"{ctx.config_dir}/config.d/99-user.toml"

    if not merged:
        print_warning("No user configuration found to migrate")
        print_info("Old installation left running; continue with install to configure it interactively.")
        return False
    else:
        toml_content = env_to_toml(merged)
        if not toml_content.strip():
            print_warning("Legacy configuration did not contain settings that map to TOML.")
            print_info("Old installation left running; continue with install to configure it interactively.")
            return False

        _backup_existing_file(migrated_toml_path)
        Path(migrated_toml_path).write_text(
            "# MeshCore Packet Capture - User Configuration\n"
            "# Migrated from legacy .env/.env.local installation\n\n"
            + toml_content
        )

        print_success(f"Configuration migrated to {migrated_toml_path}")
        print()
        print_info("Migrated configuration:")
        content = Path(migrated_toml_path).read_text()
        print(content)
        print()

    # Step 2: Stop old services
    _stop_old_services(old_dir)

    # Step 3: Remove old service units
    _cleanup_old_service_units()

    # Step 4: Mark migration as complete
    mark_migrated(old_dir, ctx.install_dir)

    # Step 5: Inform user about old directory
    print()
    print_info(f"Old installation preserved at: {old_dir}")
    print_info("You can remove it once you've verified the new installation works:")
    print(f"  rm -rf {old_dir}")
    print()

    return True


def _stop_old_services(old_dir: str) -> None:
    """Stop and disable old systemd/launchd services."""
    for unit in ("meshcore-capture.service", "meshcore-packet-capture.service"):
        unit_path = Path("/etc/systemd/system") / unit
        if unit_path.exists():
            print_info(f"Stopping old systemd service ({unit})...")
            run_cmd(["systemctl", "stop", unit], check=False)
            run_cmd(["systemctl", "disable", unit], check=False)
            print_success(f"Old service {unit} stopped and disabled")

    if platform.system() == "Darwin":
        for plist_name in (
            "com.meshcore.packet-capture.plist",
            "com.meshcore.meshcore_packet_capture.plist",
            "meshcore-capture.plist",
        ):
            old_plist = _real_user_home() / "Library" / "LaunchAgents" / plist_name
            if old_plist.exists():
                print_info("Stopping old launchd service...")
                run_cmd(["launchctl", "unload", str(old_plist)], check=False)
                print_success("Old launchd service stopped")


def _cleanup_old_service_units() -> None:
    """Remove old systemd/launchd unit files."""
    removed = False
    for unit in ("meshcore-capture.service", "meshcore-packet-capture.service"):
        p = Path("/etc/systemd/system") / unit
        if p.exists():
            print_info(f"Removing old systemd unit {unit}...")
            p.unlink(missing_ok=True)
            removed = True
    if removed:
        run_cmd(["systemctl", "daemon-reload"])
        print_success("Old systemd unit(s) removed")

    if platform.system() == "Darwin":
        for plist_name in (
            "com.meshcore.packet-capture.plist",
            "com.meshcore.meshcore_packet_capture.plist",
            "meshcore-capture.plist",
        ):
            old_plist = _real_user_home() / "Library" / "LaunchAgents" / plist_name
            if old_plist.exists():
                os.unlink(old_plist)
                print_success("Old launchd plist removed")
