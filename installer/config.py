"""Configuration: TOML generation, validation, IATA search, and config flows."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import tomllib
import time
import urllib.request
import urllib.error
from urllib.parse import urlparse
from pathlib import Path
from typing import Any, TYPE_CHECKING

from .ui import (
    print_error,
    print_header,
    print_info,
    print_success,
    print_warning,
    prompt_input,
    prompt_yes_no,
)

if TYPE_CHECKING:
    from . import InstallerContext

IATA_API_BASE = "https://api.letsmesh.net/api/iata"
USER_CONFIG_FILENAME = "99-user.toml"
LEGACY_USER_CONFIG_FILENAME = "00-user.toml"
PRESET_PREFIX = "10-"


def user_config_path(config_dir: str | Path) -> Path:
    """Return the canonical user override path."""
    return Path(config_dir) / "config.d" / USER_CONFIG_FILENAME


def legacy_user_config_path(config_dir: str | Path) -> Path:
    """Return the legacy user override path."""
    return Path(config_dir) / "config.d" / LEGACY_USER_CONFIG_FILENAME


def migrate_user_config_filename(config_dir: str | Path) -> Path:
    """Rename legacy 00-user.toml to 99-user.toml so user overrides load last."""
    new_path = user_config_path(config_dir)
    old_path = legacy_user_config_path(config_dir)

    if old_path.exists() and new_path.exists():
        print_error(
            f"Both {old_path} and {new_path} exist. Remove or merge one before continuing."
        )
        raise SystemExit(1)

    if old_path.exists():
        old_path.rename(new_path)
        print_success(f"Migrated user config to {new_path}")

    return new_path


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

def validate_meshcore_pubkey(key: str) -> str | None:
    """Validate and normalize a MeshCore public key. Returns normalized key or None."""
    key = key.replace(" ", "").upper()
    if len(key) != 64:
        return None
    if not re.fullmatch(r"[0-9A-F]{64}", key):
        return None
    return key


def validate_email(email: str) -> str | None:
    """Validate and normalize an email address. Returns lowercase email or None."""
    if "@" not in email or "." not in email.split("@", 1)[1]:
        return None
    if email.startswith((".", "@")) or email.endswith((".", "@")):
        return None
    if ".." in email or " " in email:
        return None

    local_part, domain = email.split("@", 1)
    if len(local_part) < 1 or len(domain) < 3:
        return None
    if "." not in domain:
        return None

    return email.lower()


# ---------------------------------------------------------------------------
# TOML string escaping
# ---------------------------------------------------------------------------

def toml_escape(val: str) -> str:
    """Escape a string value for use in a TOML quoted string."""
    val = val.replace("\\", "\\\\")
    val = val.replace('"', '\\"')
    return val


# ---------------------------------------------------------------------------
# TOML generation helpers
# ---------------------------------------------------------------------------

def write_user_toml_base(
    dest: str,
    iata: str,
    repo: str,
    branch: str,
    connection: dict[str, Any] | None = None,
) -> None:
    """Write the initial user TOML with general settings and the chosen connection.

    ``connection`` describes the device link and is one of:
      {"type": "serial", "serial_device": "/dev/ttyUSB0"}
      {"type": "ble", "ble_address": "...", "ble_device_name": "..."}
      {"type": "tcp", "tcp_host": "host", "tcp_port": 5000}
    Defaults to serial on /dev/ttyUSB0 when not provided.
    """
    if connection is None:
        connection = {"type": "serial", "serial_device": "/dev/ttyUSB0"}
    ctype = connection.get("type", "serial")

    lines = [
        "# MeshCore Packet Capture - User Configuration",
        "# This file contains your local overrides to the defaults in config.toml",
        "",
        "[general]",
        f'iata = "{toml_escape(iata)}"',
        "",
        "[capture]",
        f'connection_type = "{toml_escape(ctype)}"',
    ]
    if ctype == "ble":
        if connection.get("ble_address"):
            lines.append(f'ble_address = "{toml_escape(connection["ble_address"])}"')
        if connection.get("ble_device_name"):
            lines.append(f'ble_device_name = "{toml_escape(connection["ble_device_name"])}"')
    elif ctype == "tcp":
        lines.append(f'tcp_host = "{toml_escape(connection.get("tcp_host", "localhost"))}"')
        lines.append(f"tcp_port = {int(connection.get('tcp_port', 5000))}")
    lines.append("")

    if ctype == "serial":
        lines.append("[serial]")
        lines.append(f'ports = ["{toml_escape(connection.get("serial_device", "/dev/ttyUSB0"))}"]')
        lines.append("")

    lines.append("[update]")
    lines.append(f'repo = "{toml_escape(repo)}"')
    lines.append(f'branch = "{toml_escape(branch)}"')
    lines.append("")
    Path(dest).write_text("\n".join(lines))


# ---------------------------------------------------------------------------
# Device connection configuration (serial / BLE / TCP)
# ---------------------------------------------------------------------------

def _venv_python(ctx: InstallerContext) -> str:
    """Path to the venv python (has bleak/meshcore); falls back to system python3."""
    candidate = os.path.join(ctx.install_dir, "venv", "bin", "python3")
    return candidate if os.path.isfile(candidate) else "python3"


def _devtools_helper(ctx: InstallerContext, name: str) -> str | None:
    """Locate a bundled devtools helper in the source tree available at config time."""
    repo_dir = ctx.repo_dir or ctx.local_install
    if not repo_dir:
        return None
    path = os.path.join(repo_dir, "devtools", name)
    return path if os.path.isfile(path) else None


def scan_and_select_ble_device(ctx: InstallerContext) -> tuple[str | None, str | None]:
    """Scan for MeshCore BLE devices and let the user pick one.

    Returns (address, name); falls back to manual entry when scanning is
    unavailable or finds nothing. Returns (None, None) if the user enters nothing.
    """
    helper = _devtools_helper(ctx, "ble_scan_helper.py")
    devices: list[dict[str, Any]] = []
    if helper:
        try:
            print_info("Scanning for nearby BLE devices (~10s)...")
            result = subprocess.run(
                [_venv_python(ctx), helper],
                capture_output=True, text=True, timeout=45,
            )
            if result.stdout.strip():
                devices = json.loads(result.stdout.strip().splitlines()[-1])
        except (subprocess.SubprocessError, json.JSONDecodeError, OSError) as e:
            print_warning(f"BLE scan failed: {e}")
    else:
        print_warning("BLE scan helper not available; enter the device manually.")

    if devices:
        print_success(f"Found {len(devices)} MeshCore BLE device(s):")
        for i, dev in enumerate(devices, 1):
            print(f"  {i}) {dev.get('name', 'Unknown')} ({dev.get('address', '?')})")
        print(f"  {len(devices) + 1}) Enter manually")
        print()
        choice = prompt_input(f"Select device [1-{len(devices) + 1}]", "1")
        try:
            idx = int(choice)
        except ValueError:
            idx = 1
        if 1 <= idx <= len(devices):
            dev = devices[idx - 1]
            return dev.get("address"), dev.get("name")

    # Manual entry
    address = prompt_input("Enter BLE device MAC address / UUID", "").strip()
    name = prompt_input("Enter device name (optional)", "").strip()
    return (address or None), (name or None)


def pair_ble_device(ctx: InstallerContext, address: str, name: str) -> bool:
    """Best-effort BLE pairing via the bundled helper. Never blocks the install.

    Returns True if paired / already paired / pairing was skipped; False only when
    the user explicitly gives up after a failure.
    """
    helper = _devtools_helper(ctx, "ble_pairing_helper.py")
    if not helper:
        print_info("BLE pairing helper not available; skipping automatic pairing.")
        return True

    pin: str | None = None
    while True:
        cmd = [_venv_python(ctx), helper, address, name or address]
        if pin:
            cmd.append(pin)
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        except subprocess.SubprocessError as e:
            print_warning(f"Pairing check failed to run: {e}; continuing without pairing.")
            return True

        # Helper emits a JSON status line: paired | not_paired | not_found |
        # timeout | pairing_failed | error (see devtools/ble_pairing_helper.py).
        status = "error"
        if result.stdout.strip():
            try:
                status = json.loads(result.stdout.strip().splitlines()[-1]).get("status", "error")
            except json.JSONDecodeError:
                pass

        if status == "paired":
            print_success(f"BLE device ready: {name or address} ({address})")
            return True
        if status == "not_paired":
            # Linux/PIN-based devices need a PIN; macOS shows a system dialog instead.
            pin = prompt_input("Device requires pairing. Enter PIN (blank to skip)", "").strip()
            if not pin:
                print_warning("Skipping pairing; you may need to pair the device manually.")
                return True
            continue
        # not_found / timeout / pairing_failed / error
        print_warning(f"Could not pair with {address} (status: {status}).")
        if not prompt_yes_no("Retry pairing?", "n"):
            return True


def configure_tcp_connection(host_default: str = "localhost", port_default: str = "5000") -> dict[str, Any]:
    """Prompt for TCP host/port (e.g. a ser2net bridge)."""
    host = prompt_input("Enter TCP host (IP or hostname)", host_default).strip() or host_default
    port_raw = prompt_input("Enter TCP port", port_default).strip()
    try:
        port = int(port_raw)
    except ValueError:
        print_warning(f"Invalid port '{port_raw}'; using 5000.")
        port = 5000
    return {"type": "tcp", "tcp_host": host, "tcp_port": port}


def select_connection_type(
    ctx: InstallerContext,
    default_type: str = "ble",
    current: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Interactive device-connection selection (BLE / serial / TCP).

    ``default_type`` (ble/serial/tcp) pre-selects the menu default and
    ``current`` supplies existing sub-field values (BLE address/name, TCP
    host/port) as prompt defaults — pass both when reconfiguring. Returns a
    connection dict suitable for write_user_toml_base().
    """
    current = current or {}
    default_choice = {"ble": "1", "serial": "2", "tcp": "3"}.get(default_type, "1")
    print()
    print_header("Device Connection Configuration")
    print()
    print_info("How would you like to connect to your MeshCore device?")
    print("  1) Bluetooth Low Energy (BLE) - wireless; T1000e and compatible devices")
    print("  2) Serial - direct USB/serial cable")
    print("  3) TCP - network bridge (e.g. ser2net)")
    print()

    while True:
        choice = prompt_input("Select connection type [1-3]", default_choice)
        if choice == "1":
            print_info("Selected: Bluetooth Low Energy (BLE)")
            from .system import ensure_bluez
            ensure_bluez()
            address, name = (None, None)
            if prompt_yes_no("Scan for nearby BLE devices?", "y"):
                address, name = scan_and_select_ble_device(ctx)
            else:
                addr_default = str(current.get("ble_address") or "")
                name_default = str(current.get("ble_device_name") or "")
                address = prompt_input("Enter BLE device MAC address / UUID", addr_default).strip() or None
                name = prompt_input("Enter device name (optional)", name_default).strip() or None
            if address:
                pair_ble_device(ctx, address, name or "")
            return {"type": "ble", "ble_address": address or "", "ble_device_name": name or ""}
        if choice == "2":
            print_info("Selected: Serial Connection")
            from .system import select_serial_device
            return {"type": "serial", "serial_device": select_serial_device()}
        if choice == "3":
            print_info("Selected: TCP Connection")
            return configure_tcp_connection(
                str(current.get("tcp_host") or "localhost"),
                str(current.get("tcp_port") or "5000"),
            )
        print_error("Invalid choice. Please enter 1, 2, or 3.")


def _user_toml_connection_type(path: str | Path) -> str:
    """Return the configured [capture] connection_type, or '' if unset/unreadable."""
    try:
        data = _load_user_toml(path)
    except (tomllib.TOMLDecodeError, OSError):
        return ""
    return str((data.get("capture") or {}).get("connection_type") or "")


def _user_toml_connection_details(path: str | Path) -> dict[str, Any]:
    """Return the existing connection sub-fields (BLE address/name, TCP host/port)."""
    try:
        data = _load_user_toml(path)
    except (tomllib.TOMLDecodeError, OSError):
        return {}
    capture = data.get("capture") or {}
    serial = data.get("serial") or {}
    ports = serial.get("ports") if isinstance(serial, dict) else None
    return {
        "type": str(capture.get("connection_type") or ""),
        "ble_address": str(capture.get("ble_address") or ""),
        "ble_device_name": str(capture.get("ble_device_name") or ""),
        "tcp_host": str(capture.get("tcp_host") or ""),
        "tcp_port": str(capture.get("tcp_port") or ""),
        "serial_device": str(ports[0]) if isinstance(ports, list) and ports else "",
    }


def _user_toml_has_connection(path: str | Path) -> bool:
    """True if the user TOML already declares a [capture] connection_type."""
    return bool(_user_toml_connection_type(path))


def apply_connection_to_user_toml(path: str | Path, connection: dict[str, Any]) -> None:
    """Merge a connection selection into an existing user TOML, preserving other keys.

    Used to repair a half-written config (e.g. from an aborted install) without
    clobbering an already-set IATA, [update], or broker blocks.
    """
    data = _load_user_toml(path)
    ctype = connection.get("type", "serial")
    capture = dict(data.get("capture") or {})
    capture["connection_type"] = ctype
    # Drop any stale keys from a previously-selected connection type.
    for stale in ("ble_address", "ble_device_name", "tcp_host", "tcp_port"):
        capture.pop(stale, None)
    if ctype == "ble":
        if connection.get("ble_address"):
            capture["ble_address"] = connection["ble_address"]
        if connection.get("ble_device_name"):
            capture["ble_device_name"] = connection["ble_device_name"]
    elif ctype == "tcp":
        capture["tcp_host"] = connection.get("tcp_host", "localhost")
        capture["tcp_port"] = int(connection.get("tcp_port", 5000))
    data["capture"] = capture
    if ctype == "serial":
        data["serial"] = {"ports": [connection.get("serial_device", "/dev/ttyUSB0")]}
    else:
        data.pop("serial", None)
    _write_user_toml(path, data)


def _persist_connection(ctx: InstallerContext, user_toml: str, connection: dict[str, Any]) -> None:
    """Write a connection selection: full base for a new file, merge for an existing one
    (overwriting only if the existing file is unreadable)."""
    if not Path(user_toml).exists():
        write_user_toml_base(user_toml, "XXX", ctx.repo, ctx.branch, connection)
        return
    try:
        apply_connection_to_user_toml(user_toml, connection)
    except (tomllib.TOMLDecodeError, OSError):
        write_user_toml_base(user_toml, "XXX", ctx.repo, ctx.branch, connection)


def configure_device_connection(ctx: InstallerContext, user_toml: str) -> None:
    """Ensure a device connection is configured; offer to change an existing one.

    - No file / no connection set: prompt and write (mandatory).
    - Connection already set: show it and offer to reconfigure (default: keep).
    """
    if not Path(user_toml).exists():
        _persist_connection(ctx, user_toml, select_connection_type(ctx))
        return

    current = _user_toml_connection_type(user_toml)
    if not current:
        print_warning(
            "Existing configuration has no device connection set "
            "(likely a previous aborted install) — let's configure it."
        )
        _persist_connection(ctx, user_toml, select_connection_type(ctx))
        return

    print_info(f"Device connection is currently: {current}")
    if prompt_yes_no("Reconfigure the device connection?", "n"):
        details = _user_toml_connection_details(user_toml)
        _persist_connection(
            ctx, user_toml,
            select_connection_type(ctx, default_type=current, current=details),
        )


def append_disabled_broker_toml(dest: str, broker_name: str) -> None:
    """Append a broker block that disables a base-config broker by name."""
    block = f"""
[[broker]]
name = "{toml_escape(broker_name)}"
enabled = false
"""
    with open(dest, "a") as f:
        f.write(block)


def append_letsmesh_broker_toml(
    dest: str,
    broker_name: str,
    server: str,
    audience: str,
    owner: str,
    email: str,
) -> None:
    """Append a LetsMesh broker block to a TOML file."""
    block = f"""
[[broker]]
name = "{toml_escape(broker_name)}"
enabled = true
server = "{toml_escape(server)}"
port = 443
transport = "websockets"
keepalive = 60
qos = 0
retain = true

[broker.tls]
enabled = true
verify = true

[broker.auth]
method = "token"
audience = "{toml_escape(audience)}"
owner = "{toml_escape(owner)}"
email = "{toml_escape(email)}"
"""
    with open(dest, "a") as f:
        f.write(block)


def append_custom_broker_toml(
    dest: str,
    broker_name: str,
    server: str,
    port: str,
    transport: str,
    use_tls: str,
    tls_verify: str,
    auth_method: str,
    username: str = "",
    password: str = "",
    audience: str = "",
    owner: str = "",
    email: str = "",
) -> None:
    """Append a custom broker block to a TOML file."""
    lines = [
        "",
        "[[broker]]",
        f'name = "{toml_escape(broker_name)}"',
        "enabled = true",
        f'server = "{toml_escape(server)}"',
        f"port = {port}",
        f'transport = "{toml_escape(transport)}"',
        "keepalive = 60",
        "qos = 0",
        "retain = true",
    ]

    if use_tls == "true":
        lines.extend(["", "[broker.tls]", "enabled = true", f"verify = {tls_verify}"])

    lines.extend(["", "[broker.auth]", f'method = "{toml_escape(auth_method)}"'])

    if auth_method == "password":
        lines.append(f'username = "{toml_escape(username)}"')
        lines.append(f'password = "{toml_escape(password)}"')
    elif auth_method == "token":
        if audience:
            lines.append(f'audience = "{toml_escape(audience)}"')
        if owner:
            lines.append(f'owner = "{toml_escape(owner)}"')
        if email:
            lines.append(f'email = "{toml_escape(email)}"')

    lines.append("")
    with open(dest, "a") as f:
        f.write("\n".join(lines))


def append_token_owner_overrides_toml(
    dest: str,
    broker_names: list[str],
    owner: str,
    email: str,
) -> None:
    """Append local auth metadata overrides for token-auth preset brokers."""
    if not owner and not email:
        return

    lines: list[str] = []
    for broker_name in broker_names:
        lines.extend([
            "",
            "[[broker]]",
            f'name = "{toml_escape(broker_name)}"',
            "",
            "[broker.auth]",
        ])
        if owner:
            lines.append(f'owner = "{toml_escape(owner)}"')
        if email:
            lines.append(f'email = "{toml_escape(email)}"')

    lines.append("")
    with open(dest, "a") as f:
        f.write("\n".join(lines))


def _rewrite_token_owner_overrides_toml(
    dest: str,
    broker_names: list[str],
    owner: str,
    email: str,
) -> None:
    """Replace local auth metadata overrides for the given brokers."""
    path = Path(dest)
    data = _load_user_toml(path)

    brokers = data.get("broker")
    if not isinstance(brokers, list):
        brokers = []
        data["broker"] = brokers

    by_name: dict[str, dict[str, Any]] = {
        broker["name"]: broker
        for broker in brokers
        if isinstance(broker, dict) and isinstance(broker.get("name"), str)
    }

    for broker_name in broker_names:
        broker = by_name.get(broker_name)
        if broker is None:
            broker = {"name": broker_name}
            by_name[broker_name] = broker
            brokers.append(broker)
        auth = broker.get("auth")
        if not isinstance(auth, dict):
            auth = {}
            broker["auth"] = auth
        if owner:
            auth["owner"] = owner
        else:
            auth.pop("owner", None)
        if email:
            auth["email"] = email
        else:
            auth.pop("email", None)

    _write_user_toml(path, data)


def _remove_broker_overrides_toml(dest: str | Path, broker_names: list[str]) -> None:
    """Remove local broker override blocks for the given broker names."""
    path = Path(dest)
    if not path.exists():
        return

    data = _load_user_toml(path)

    brokers = data.get("broker")
    if not isinstance(brokers, list):
        return

    remove_names = set(broker_names)
    remaining = [
        broker for broker in brokers
        if not isinstance(broker, dict) or broker.get("name") not in remove_names
    ]
    if remaining:
        data["broker"] = remaining
    else:
        # Drop the key entirely rather than emitting `broker = []`, which would
        # otherwise clash with a later text-appended [[broker]] block.
        data.pop("broker", None)
    _write_user_toml(path, data)


USER_CONFIG_HEADER = (
    "# MeshCore Packet Capture - User Configuration\n"
    "# This file contains your local overrides to the defaults in config.toml\n\n"
)


def _load_user_toml(path: str | Path) -> dict[str, Any]:
    """Load a user TOML file, returning an empty dict if it doesn't exist."""
    p = Path(path)
    if not p.exists():
        return {}
    with open(p, "rb") as f:
        return tomllib.load(f)


def _write_user_toml(path: str | Path, data: dict[str, Any]) -> None:
    """Serialize a user TOML document, prepending the standard header."""
    Path(path).write_text(USER_CONFIG_HEADER + _toml_dumps(data))


_BARE_KEY_RE = re.compile(r"^[A-Za-z0-9_-]+$")


def _toml_key(key: str) -> str:
    """Render a TOML key, quoting if it can't be a bare key."""
    if _BARE_KEY_RE.match(key):
        return key
    return f'"{toml_escape(key)}"'


def _toml_value(value: Any) -> str:
    """Render a single TOML scalar/array value."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return repr(value)
    if isinstance(value, str):
        return f'"{toml_escape(value)}"'
    if isinstance(value, list):
        return "[" + ", ".join(_toml_value(item) for item in value) + "]"
    raise TypeError(f"Unsupported TOML value type: {type(value).__name__}")


def _is_array_of_tables(value: Any) -> bool:
    return isinstance(value, list) and len(value) > 0 and all(isinstance(item, dict) for item in value)


def _split_kinds(data: dict[str, Any]) -> tuple[list[tuple[str, Any]], list[tuple[str, dict]], list[tuple[str, list[dict]]]]:
    """Split a table's items into (scalars, sub-tables, arrays-of-tables) preserving order."""
    scalars: list[tuple[str, Any]] = []
    tables: list[tuple[str, dict]] = []
    arrays: list[tuple[str, list[dict]]] = []
    for key, value in data.items():
        if isinstance(value, dict):
            tables.append((key, value))
        elif _is_array_of_tables(value):
            arrays.append((key, value))
        else:
            scalars.append((key, value))
    return scalars, tables, arrays


def _emit_table(lines: list[str], prefix: list[str], data: dict[str, Any]) -> None:
    """Emit a table whose path is `prefix`. Top-level call uses prefix=[]."""
    scalars, tables, arrays = _split_kinds(data)
    header = ".".join(_toml_key(seg) for seg in prefix) if prefix else ""

    if scalars:
        if header:
            lines.append(f"[{header}]")
        for key, value in scalars:
            lines.append(f"{_toml_key(key)} = {_toml_value(value)}")
        lines.append("")
    elif header and not tables and not arrays:
        # Empty leaf table — emit explicit header so it round-trips.
        lines.append(f"[{header}]")
        lines.append("")

    for key, table in tables:
        _emit_table(lines, prefix + [key], table)

    for key, items in arrays:
        item_header = ".".join(_toml_key(seg) for seg in prefix + [key])
        for item in items:
            lines.append(f"[[{item_header}]]")
            _emit_array_table_body(lines, prefix + [key], item)


def _emit_array_table_body(lines: list[str], prefix: list[str], data: dict[str, Any]) -> None:
    """Emit the body of one array-of-tables element (header already emitted)."""
    scalars, tables, arrays = _split_kinds(data)

    for key, value in scalars:
        lines.append(f"{_toml_key(key)} = {_toml_value(value)}")
    if scalars or (not tables and not arrays):
        lines.append("")

    for key, table in tables:
        _emit_table(lines, prefix + [key], table)

    for key, items in arrays:
        item_header = ".".join(_toml_key(seg) for seg in prefix + [key])
        for item in items:
            lines.append(f"[[{item_header}]]")
            _emit_array_table_body(lines, prefix + [key], item)


def _toml_dumps(data: dict[str, Any]) -> str:
    """Serialize a dict to TOML, preserving all keys and insertion order.

    Comments are not preserved (tomllib drops them on load). Section ordering
    follows the parsed dict's insertion order, with scalars-before-tables within
    each table to satisfy TOML's parsing rules.
    """
    lines: list[str] = []
    _emit_table(lines, [], data)
    return "\n".join(lines).rstrip() + "\n"


# ---------------------------------------------------------------------------
# Preset helpers
# ---------------------------------------------------------------------------

def _safe_preset_basename(name: str) -> str:
    """Validate and return a safe TOML preset basename."""
    basename = Path(name).name
    if basename != name or not basename or basename in (".", ".."):
        raise ValueError("Preset filename must be a simple basename")
    if "/" in basename or "\\" in basename:
        raise ValueError("Preset filename must not contain path separators")
    if not basename.endswith(".toml"):
        raise ValueError("Preset filename must end with .toml")
    if basename.startswith("."):
        raise ValueError("Preset filename must not be hidden")
    return basename


def preset_dest_path(config_dir: str | Path, original_filename: str) -> Path:
    """Return the active config.d path for a preset filename."""
    basename = _safe_preset_basename(original_filename)
    if basename.startswith(PRESET_PREFIX):
        dest_name = basename
    else:
        dest_name = f"{PRESET_PREFIX}{basename}"
    return Path(config_dir) / "config.d" / dest_name


def validate_preset_toml(path: str | Path) -> dict[str, Any]:
    """Load and validate a broker preset TOML file."""
    with open(path, "rb") as f:
        data = tomllib.load(f)

    brokers = data.get("broker")
    if not isinstance(brokers, list) or not brokers:
        raise ValueError("Preset must contain at least one [[broker]] block")

    for broker in brokers:
        if not isinstance(broker, dict) or not broker.get("name"):
            raise ValueError("Every preset broker must have a name")

    return data


def list_bundled_presets(repo_dir: str | Path) -> list[Path]:
    """List bundled preset TOML files from the checked-out or downloaded repo."""
    preset_dir = Path(repo_dir) / "presets"
    if not preset_dir.is_dir():
        return []
    return sorted(p for p in preset_dir.glob("*.toml") if p.is_file())


def copy_preset_to_config(source: str | Path, config_dir: str | Path) -> Path:
    """Validate and copy a preset into config.d with the preset prefix."""
    source_path = Path(source)
    dest = preset_dest_path(config_dir, source_path.name)
    validate_preset_toml(source_path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source_path, dest)
    return dest


def _filename_from_url(url: str) -> str:
    parsed = urlparse(url)
    return Path(parsed.path).name


def import_preset_to_config(source: str, config_dir: str | Path) -> Path:
    """Import a preset from a local path or URL into config.d."""
    if re.match(r"^https?://", source):
        filename = _safe_preset_basename(_filename_from_url(source))
        dest = preset_dest_path(config_dir, filename)
        dest.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp_path = Path(tmp.name)
        try:
            req = urllib.request.Request(
                source,
                headers={"User-Agent": "meshcore-packet-capture-installer"},
            )
            with urllib.request.urlopen(req, timeout=60) as resp:
                tmp_path.write_bytes(resp.read())
            validate_preset_toml(tmp_path)
            shutil.copy2(tmp_path, dest)
        finally:
            tmp_path.unlink(missing_ok=True)
        return dest

    source_path = Path(source).expanduser()
    _safe_preset_basename(source_path.name)
    return copy_preset_to_config(source_path, config_dir)


def token_broker_names_from_preset(path: str | Path) -> list[tuple[str, str]]:
    """Return (preset filename, broker name) entries for token-auth brokers."""
    data = validate_preset_toml(path)
    names: list[tuple[str, str]] = []
    for broker in data.get("broker", []):
        auth = broker.get("auth", {})
        if isinstance(auth, dict) and auth.get("method") == "token":
            names.append((Path(path).name, str(broker["name"])))
    return names


def token_preset_brokers(config_dir: str | Path) -> dict[Path, list[str]]:
    """Return token-auth broker names grouped by active preset file."""
    config_d = Path(config_dir) / "config.d"
    result: dict[Path, list[str]] = {}
    if not config_d.is_dir():
        return result

    for preset in sorted(config_d.glob(f"{PRESET_PREFIX}*.toml")):
        try:
            broker_names = [name for _preset, name in token_broker_names_from_preset(preset)]
        except (OSError, ValueError, tomllib.TOMLDecodeError):
            continue
        if broker_names:
            result[preset] = broker_names
    return result


def configured_presets(config_dir: str | Path) -> dict[Path, list[str]]:
    """Return active preset files and their broker names."""
    config_d = Path(config_dir) / "config.d"
    result: dict[Path, list[str]] = {}
    if not config_d.is_dir():
        return result

    for preset in sorted(config_d.glob(f"{PRESET_PREFIX}*.toml")):
        try:
            data = validate_preset_toml(preset)
        except (OSError, ValueError, tomllib.TOMLDecodeError):
            result[preset] = []
            continue
        brokers = data.get("broker", [])
        names = [
            str(broker["name"]) for broker in brokers
            if isinstance(broker, dict) and broker.get("name")
        ]
        result[preset] = names
    return result


def _broker_auth_metadata(config_dir: str | Path, broker_name: str) -> tuple[str, str]:
    """Return effective owner/email for a broker from config.d load order."""
    owner = ""
    email = ""
    config_d = Path(config_dir) / "config.d"
    if not config_d.is_dir():
        return owner, email

    for path in sorted(config_d.glob("*.toml")):
        try:
            data = validate_preset_toml(path) if path.name.startswith(PRESET_PREFIX) else _load_toml_file(path)
        except (OSError, ValueError, tomllib.TOMLDecodeError):
            continue
        brokers = data.get("broker", [])
        if not isinstance(brokers, list):
            continue
        for broker in brokers:
            if not isinstance(broker, dict) or broker.get("name") != broker_name:
                continue
            auth = broker.get("auth", {})
            if not isinstance(auth, dict):
                continue
            if "owner" in auth:
                owner = str(auth.get("owner") or "")
            if "email" in auth:
                email = str(auth.get("email") or "")
    return owner, email


def _load_toml_file(path: str | Path) -> dict[str, Any]:
    with open(path, "rb") as f:
        return tomllib.load(f)


# ---------------------------------------------------------------------------
# IATA API helpers (replaces jq dependency)
# ---------------------------------------------------------------------------

def _iata_api_url(params: str, script_version: str = "unknown") -> str:
    return f"{IATA_API_BASE}?{params}&source=installer-{script_version}"


def _iata_request(url: str) -> bytes:
    """Make an HTTP request to the IATA API with a proper User-Agent."""
    req = urllib.request.Request(url, headers={"User-Agent": "meshcore-packet-capture-installer"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        return resp.read()


def search_iata_api(query: str, script_version: str = "unknown") -> list[tuple[str, str]]:
    """Search IATA airports. Returns list of (code, name) tuples."""
    url = _iata_api_url(f"search={urllib.request.quote(query)}", script_version)
    try:
        data = json.loads(_iata_request(url))
        return [(entry["iata"], entry["name"]) for entry in data]
    except (urllib.error.URLError, json.JSONDecodeError, KeyError, OSError):
        return []


def _lookup_iata_code_with_retry(
    code: str,
    script_version: str = "unknown",
    attempts: int = 3,
) -> tuple[str | None, bool]:
    """Look up an IATA code. Returns (airport name, validation_unavailable)."""
    url = _iata_api_url(f"code={urllib.request.quote(code)}", script_version)
    for attempt in range(1, attempts + 1):
        try:
            data = json.loads(_iata_request(url))
            if not isinstance(data, dict):
                return None, False
            return data.get("name"), False
        except (urllib.error.URLError, json.JSONDecodeError, KeyError, OSError):
            if attempt == attempts:
                return None, True
            time.sleep(1)
    return None, True


def lookup_iata_code(code: str, script_version: str = "unknown") -> str | None:
    """Look up a specific IATA code. Returns airport name or None."""
    name, _validation_unavailable = _lookup_iata_code_with_retry(code, script_version)
    return name


# ---------------------------------------------------------------------------
# Interactive IATA prompts
# ---------------------------------------------------------------------------

def prompt_iata_simple(existing: str = "") -> str:
    """Simple IATA prompt - just asks for 3-letter code."""
    print()
    print_info("IATA code is a 3-letter airport code identifying your region (e.g., SEA, LAX, NYC)")
    print_info("Search/view all IATA codes on a map: https://analyzer.letsmesh.net/map/iata")
    print()

    while True:
        iata = prompt_input("Enter your IATA code (3 letters)", existing).upper().replace(" ", "")

        if not iata or iata == "XXX":
            print_error("Please enter a valid IATA code")
            continue

        if len(iata) != 3:
            print_warning("IATA codes are typically 3 letters")
            if not prompt_yes_no(f"Use '{iata}' anyway?", "n"):
                continue

        return iata


def prompt_iata_letsmesh(existing: str = "", script_version: str = "unknown") -> str:
    """Interactive IATA selection with API search (LetsMesh only)."""
    print()
    print_header("IATA Region Selection")
    print()
    print_info("Your IATA code identifies your geographic region (e.g., SEA, LAX, NYC, LON)")
    print_info("Type to search by airport code or city name")
    print_info("View all IATA codes on a map: https://analyzer.letsmesh.net/map/iata")
    print()

    while True:
        search_query = prompt_input("Search (or enter IATA code directly)")
        if not search_query:
            print_error("Please enter a search term")
            continue

        upper_query = search_query.upper().replace(" ", "")

        # If exactly 3 uppercase letters, try direct lookup
        if re.fullmatch(r"[A-Z]{3}", upper_query):
            print_info(f"Looking up {upper_query}...")
            name, validation_unavailable = _lookup_iata_code_with_retry(upper_query, script_version)
            if name:
                print()
                print_success(f"Found: {upper_query} - {name}")
                print()
                if prompt_yes_no("Use this IATA code?", "y"):
                    print()
                    print_success(f"Selected: {upper_query} - {name}")
                    return upper_query
                print()
                continue
            if validation_unavailable:
                print_warning(f"Could not validate IATA code '{upper_query}' after retrying")
                if prompt_yes_no(f"Use '{upper_query}' without validation?", "y"):
                    print()
                    print_success(f"Selected: {upper_query}")
                    return upper_query
                print()
                continue
            else:
                print_warning(f"IATA code '{upper_query}' was not found in the LetsMesh database")
                if prompt_yes_no(f"Use '{upper_query}' anyway?", "y"):
                    print()
                    print_success(f"Selected: {upper_query}")
                    return upper_query
                print()
                continue

        # Search via API
        print_info("Searching...")
        results = search_iata_api(search_query, script_version)

        if not results:
            print_error(f"No matching airports found for '{search_query}'")
            print()
            continue

        # Display results
        print()
        print_info("Matching airports:")
        print()
        for i, (iata, name) in enumerate(results, 1):
            print(f"  {i}) {iata} - {name}")
        print()
        print("  s) Search again")
        print()

        choice = prompt_input(f"Select [1-{len(results)}] or 's' to search again")

        if choice.lower() == "s":
            print()
            continue

        if choice.isdigit() and 1 <= int(choice) <= len(results):
            idx = int(choice) - 1
            selected_iata, selected_name = results[idx]
            print()
            print_success(f"Selected: {selected_iata} - {selected_name}")
            return selected_iata

        print_error("Invalid selection")
        print()


# ---------------------------------------------------------------------------
# Interactive prompts for owner info and companions
# ---------------------------------------------------------------------------

def prompt_owner_email(existing: str = "") -> str:
    """Prompt for owner email with validation. Returns email or empty string."""
    print()
    print_info("Owner email")
    print()

    while True:
        email = prompt_input("Enter owner email (or leave empty to skip)", existing)

        if not email:
            return ""

        validated = validate_email(email)
        if validated is not None:
            return validated

        print_error("Invalid email format")
        if not prompt_yes_no("Try again?", "y"):
            return ""


def prompt_owner_pubkey(existing: str = "") -> str:
    """Prompt for owner public key with validation. Returns key or empty string."""
    print()
    print_info("Owner public key is a 64-character hex string (MeshCore companion public key)")
    print_info("Example: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    print()

    while True:
        owner = prompt_input("Enter owner public key (or leave empty to skip)", existing)

        if not owner:
            return ""

        validated = validate_meshcore_pubkey(owner)
        if validated is not None:
            return validated

        print_error("Invalid public key format. Must be 64 hex characters (32 bytes)")
        if not prompt_yes_no("Try again?", "y"):
            return ""


# ---------------------------------------------------------------------------
# Configure custom broker (interactive)
# ---------------------------------------------------------------------------

def _user_custom_broker_names(config_dir: str | Path) -> list[str]:
    """Names of full custom broker definitions in the user TOML (those with a server)."""
    data = _load_user_toml(user_config_path(config_dir))
    brokers = data.get("broker")
    if not isinstance(brokers, list):
        return []
    return [
        str(b["name"]) for b in brokers
        if isinstance(b, dict) and b.get("name") and b.get("server")
    ]


def _custom_broker_fields(config_dir: str | Path, broker_name: str) -> dict[str, str]:
    """Read an existing custom broker's fields from the user TOML as prompt defaults."""
    data = _load_user_toml(user_config_path(config_dir))
    brokers = data.get("broker")
    if not isinstance(brokers, list):
        return {}
    for b in brokers:
        if not isinstance(b, dict) or b.get("name") != broker_name:
            continue
        tls = b.get("tls") if isinstance(b.get("tls"), dict) else {}
        auth = b.get("auth") if isinstance(b.get("auth"), dict) else {}
        return {
            "server": str(b.get("server") or ""),
            "port": str(b.get("port") or "1883"),
            "transport": str(b.get("transport") or "tcp"),
            "use_tls": "true" if tls.get("enabled") else "false",
            "tls_verify": "false" if tls.get("verify") is False else "true",
            "auth_method": str(auth.get("method") or "none"),
            "username": str(auth.get("username") or ""),
            "password": str(auth.get("password") or ""),
            "audience": str(auth.get("audience") or ""),
            "owner": str(auth.get("owner") or ""),
            "email": str(auth.get("email") or ""),
        }
    return {}


def _existing_owner_email(config_dir: str | Path) -> tuple[str, str]:
    """Best-effort existing owner/email to reuse as a default for new brokers."""
    data = _load_user_toml(user_config_path(config_dir))
    brokers = data.get("broker") if isinstance(data.get("broker"), list) else []
    owner = email = ""
    for b in brokers:
        if not isinstance(b, dict):
            continue
        auth = b.get("auth") if isinstance(b.get("auth"), dict) else {}
        owner = owner or str(auth.get("owner") or "")
        email = email or str(auth.get("email") or "")
    return owner, email


def configure_custom_broker(broker_num: int, config_dir: str, *, existing_name: str | None = None) -> None:
    """Configure a single custom MQTT broker interactively.

    When ``existing_name`` is given, the broker's current values are read and
    offered as prompt defaults, and the old block is replaced (edit in place).
    """
    user_toml = str(migrate_user_config_filename(config_dir))
    cur = _custom_broker_fields(config_dir, existing_name) if existing_name else {}

    print()
    if existing_name:
        print_header(f"Editing MQTT Broker: {existing_name}")
    else:
        print_header(f"Configuring MQTT Broker {broker_num}")

    server = prompt_input("Server hostname/IP", cur.get("server", ""))
    if not server:
        print_warning(f"Server hostname required - skipping broker {broker_num}")
        return

    port = prompt_input("Port", cur.get("port", "1883"))
    transport = "websockets" if prompt_yes_no(
        "Use WebSockets transport?", "y" if cur.get("transport") == "websockets" else "n"
    ) else "tcp"

    use_tls = "false"
    tls_verify = "true"
    if prompt_yes_no("Use TLS/SSL encryption?", "y" if cur.get("use_tls") == "true" else "n"):
        use_tls = "true"
        if not prompt_yes_no("Verify TLS certificates?", "n" if cur.get("tls_verify") == "false" else "y"):
            tls_verify = "false"

    print()
    print_info("Authentication method:")
    print("  1) Username/Password")
    print("  2) MeshCore Auth Token")
    print("  3) None (anonymous)")
    auth_default = {"password": "1", "token": "2", "none": "3"}.get(cur.get("auth_method", ""), "1")
    auth_choice = prompt_input("Choose authentication method [1-3]", auth_default)

    auth_method = "none"
    username = password = audience = owner = email = ""

    if auth_choice == "2":
        auth_method = "token"
        audience = prompt_input("Token audience (optional)", cur.get("audience", ""))
        # Reuse an already-entered owner identity as the default for new brokers.
        shared_owner, shared_email = _existing_owner_email(config_dir)
        owner = prompt_owner_pubkey(cur.get("owner") or shared_owner)
        email = prompt_owner_email(cur.get("email") or shared_email)

        parts = []
        if owner and email:
            parts.append(f"Owner info set: {owner} ({email})")
        elif owner:
            parts.append(f"Owner public key set: {owner}")
        elif email:
            parts.append(f"Owner email set: {email}")
        if parts:
            print_success(parts[0])

    if auth_choice == "1":
        auth_method = "password"
        username = prompt_input("Username", cur.get("username", ""))
        if username:
            password = prompt_input("Password", cur.get("password", ""))

    broker_name = existing_name or f"custom-{broker_num}"
    if existing_name:
        # Replace the existing block rather than appending a duplicate.
        _remove_broker_overrides_toml(user_toml, [existing_name])
    append_custom_broker_toml(
        user_toml, broker_name, server, port, transport,
        use_tls, tls_verify, auth_method,
        username, password, audience, owner, email,
    )
    print_success(f"Broker '{broker_name}' configured")


# ---------------------------------------------------------------------------
# Configure MQTT brokers (main flow)
# ---------------------------------------------------------------------------

def _select_custom_broker_to_edit(config_dir: str) -> str | None:
    """Offer to edit an existing custom broker; return its name, or None to add new."""
    existing = _user_custom_broker_names(config_dir)
    if not existing:
        return None

    print()
    print_info("Existing custom brokers:")
    for idx, name in enumerate(existing, 1):
        print(f"  {idx}) {name}")
    add_choice = len(existing) + 1
    print(f"  {add_choice}) Add a new custom broker")

    raw = prompt_input(f"Edit an existing broker or add new [1-{add_choice}]", str(add_choice)).strip()
    if raw.isdigit() and 1 <= int(raw) <= len(existing):
        return existing[int(raw) - 1]
    return None


def configure_mqtt_brokers(ctx: InstallerContext) -> None:
    """Interactive MQTT broker configuration flow."""
    user_toml_path = migrate_user_config_filename(ctx.config_dir)
    user_toml = str(user_toml_path)

    # Device connection: prompt+write when missing (incl. aborted-install repair),
    # or show the current connection and offer to change it.
    configure_device_connection(ctx, user_toml)

    added_brokers = False
    had_existing_brokers = _config_dir_has_broker(ctx.config_dir)

    while True:
        print()
        print_header("MQTT Broker Configuration")
        print()
        _print_configured_presets(ctx.config_dir)
        print_info("Choose how to configure MQTT brokers:")
        print("  1) Select bundled broker presets")
        print("  2) Import a preset from a URL or local path")
        print("  3) Configure a custom MQTT broker")
        print("  4) Manage existing presets")
        print("  5) Finish without adding or changing brokers")
        print()

        choice = prompt_input("Choose broker setup option [1-5]", "1")

        if choice == "1":
            selected = _select_bundled_presets(ctx)
            if selected:
                for preset in selected:
                    try:
                        copied = copy_preset_to_config(preset, ctx.config_dir)
                        print_success(f"Preset installed: {copied.name}")
                        added_brokers = True
                    except (OSError, ValueError, tomllib.TOMLDecodeError) as exc:
                        print_error(f"Failed to install preset {preset.name}: {exc}")
            else:
                print_warning("No bundled presets selected")
        elif choice == "2":
            source = prompt_input("Preset URL or local path")
            if not source:
                print_warning("No preset source provided")
            else:
                try:
                    copied = import_preset_to_config(source, ctx.config_dir)
                    print_success(f"Preset installed: {copied.name}")
                    added_brokers = True
                except (OSError, ValueError, tomllib.TOMLDecodeError, urllib.error.URLError) as exc:
                    print_error(f"Failed to import preset: {exc}")
        elif choice == "3":
            _configure_iata_simple(user_toml)
            target = _select_custom_broker_to_edit(ctx.config_dir)
            if target:
                configure_custom_broker(0, ctx.config_dir, existing_name=target)
            else:
                configure_custom_broker(_next_custom_broker_number(ctx.config_dir), ctx.config_dir)
            added_brokers = True
        elif choice == "4":
            _manage_existing_presets(ctx.config_dir)
        elif choice == "5":
            break
        else:
            print_error("Invalid selection")
            continue

        if not prompt_yes_no("Add or manage another broker preset or custom broker?", "n"):
            break

    if configured_presets(ctx.config_dir):
        _configure_iata_for_presets(user_toml, ctx)
    if token_preset_brokers(ctx.config_dir):
        _configure_token_preset_overrides(ctx.config_dir)

    if not added_brokers and not had_existing_brokers:
        print_warning(f"No MQTT brokers configured - you'll need to edit {user_toml} manually")

    # Fix ownership after writing config
    if platform.system() != "Darwin" and ctx.svc_user:
        import shutil as _shutil
        _shutil.chown(user_toml, "root", ctx.svc_user)
        os.chmod(user_toml, 0o644)


def _configure_iata_simple(user_toml: str) -> None:
    """Prompt for simple IATA and update the user TOML."""
    existing_iata = _read_existing_iata(user_toml)
    if not existing_iata or existing_iata == "XXX":
        iata = prompt_iata_simple()
        _update_iata_in_file(user_toml, iata)
        print_success(f"IATA code set to: {iata}")


def _configure_iata_for_presets(user_toml: str, ctx: InstallerContext) -> None:
    """Prompt for IATA for preset brokers if the user config still needs it."""
    existing_iata = _read_existing_iata(user_toml)
    if not existing_iata or existing_iata == "XXX":
        iata = prompt_iata_letsmesh("", ctx.script_version)
        _update_iata_in_file(user_toml, iata)
        print_success(f"IATA code set to: {iata}")


def _configure_token_preset_overrides(config_dir: str) -> None:
    """Configure owner/email overrides for token-auth presets.

    Owner identity is almost always the same person for every broker, so by
    default we ask once and apply the answer to all token-authenticated brokers.
    A per-preset path is still offered when the user has more than one preset and
    wants different identities for each.
    """
    user_toml = str(user_config_path(config_dir))
    presets = token_preset_brokers(config_dir)
    if not presets:
        return

    print()
    print_info("Token-authenticated broker presets support optional owner identification")
    print_info("This links your observer to your MeshCore public key and email")

    # Gather metadata for every token broker across all presets.
    metadata: dict[str, tuple[str, str]] = {}
    all_broker_names: list[str] = []
    for broker_names in presets.values():
        for broker_name in broker_names:
            all_broker_names.append(broker_name)
            metadata[broker_name] = _broker_auth_metadata(config_dir, broker_name)

    has_owner_info = any(owner or email for owner, email in metadata.values())

    print()
    for preset_path, broker_names in presets.items():
        print_info(f"{preset_path.name}:")
        for broker_name in broker_names:
            owner, email = metadata[broker_name]
            print(f"  - {broker_name}")
            print(f"    owner: {owner or '(not set)'}")
            print(f"    email: {email or '(not set)'}")

    if has_owner_info and not prompt_yes_no("Update owner info for token-authenticated brokers?", "n"):
        return

    multiple_presets = len(presets) > 1
    if not multiple_presets or prompt_yes_no(
        "Use the same owner public key and email for all token-authenticated brokers?", "y"
    ):
        owner_default = _shared_metadata_default(metadata, 0)
        email_default = _shared_metadata_default(metadata, 1)
        owner_pubkey = prompt_owner_pubkey(owner_default)
        owner_email = prompt_owner_email(email_default)
        _rewrite_token_owner_overrides_toml(user_toml, all_broker_names, owner_pubkey, owner_email)
        print_success("Owner info updated for all token-authenticated brokers")
        return

    # Per-preset path: the user wants a different identity per preset.
    for preset_path, broker_names in presets.items():
        print()
        print_header(f"Owner Info: {preset_path.name}")
        preset_meta = {name: metadata[name] for name in broker_names}
        owner_default = _shared_metadata_default(preset_meta, 0)
        email_default = _shared_metadata_default(preset_meta, 1)
        owner_pubkey = prompt_owner_pubkey(owner_default)
        owner_email = prompt_owner_email(email_default)
        _rewrite_token_owner_overrides_toml(user_toml, broker_names, owner_pubkey, owner_email)
        print_success(f"Owner info updated for {preset_path.name}")


def _shared_metadata_default(metadata: dict[str, tuple[str, str]], idx: int) -> str:
    """Return the shared existing owner/email value if all brokers agree."""
    values = {pair[idx] for pair in metadata.values() if pair[idx]}
    return values.pop() if len(values) == 1 else ""


def _print_configured_presets(config_dir: str) -> None:
    """Print a summary of active preset files."""
    presets = configured_presets(config_dir)
    if not presets:
        print_info("Configured broker presets: none")
        print()
        return

    print_info("Configured broker presets:")
    for preset, broker_names in presets.items():
        brokers = ", ".join(broker_names) if broker_names else "no valid broker blocks"
        print(f"  - {preset.name}: {brokers}")
    print()


def _manage_existing_presets(config_dir: str) -> None:
    """Delete configured preset files and matching user overrides."""
    presets = configured_presets(config_dir)
    if not presets:
        print_warning("No configured presets found")
        return

    print()
    print_info("Configured broker presets:")
    preset_items = list(presets.items())
    for idx, (preset, broker_names) in enumerate(preset_items, 1):
        brokers = ", ".join(broker_names) if broker_names else "no valid broker blocks"
        print(f"  {idx}) {preset.name}: {brokers}")
    print()

    raw = prompt_input(f"Select presets to delete (enter without a selection to return) [1-{len(preset_items)}], comma-separated")
    selected = _parse_number_selection(raw, len(preset_items))
    if not selected:
        print_warning("No presets selected")
        return

    user_toml = user_config_path(config_dir)
    for idx in selected:
        preset, broker_names = preset_items[idx - 1]
        if not prompt_yes_no(f"Delete {preset.name}?", "n"):
            continue
        preset.unlink(missing_ok=True)
        _remove_broker_overrides_toml(user_toml, broker_names)
        print_success(f"Deleted {preset.name} and removed matching user overrides")


def _parse_number_selection(raw: str, max_value: int) -> list[int]:
    """Parse comma-separated numeric selections."""
    selected: list[int] = []
    seen: set[int] = set()
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        if not part.isdigit():
            print_warning(f"Ignoring invalid selection: {part}")
            continue
        idx = int(part)
        if idx < 1 or idx > max_value:
            print_warning(f"Ignoring out-of-range selection: {part}")
            continue
        if idx not in seen:
            selected.append(idx)
            seen.add(idx)
    return selected


def _select_bundled_presets(ctx: InstallerContext) -> list[Path]:
    """Prompt for one or more bundled presets."""
    presets = list_bundled_presets(ctx.repo_dir)
    if not presets:
        print_warning("No bundled presets found")
        return []

    default_idx = 1
    for idx, preset in enumerate(presets, 1):
        if preset.name == "letsmesh.toml":
            default_idx = idx
            break

    print()
    print_info("Available broker presets:")
    for idx, preset in enumerate(presets, 1):
        print(f"  {idx}) {preset.name}")
    print()

    raw = prompt_input(f"Select presets [1-{len(presets)}], comma-separated", str(default_idx))
    return [presets[idx - 1] for idx in _parse_number_selection(raw, len(presets))]


def _next_custom_broker_number(config_dir: str) -> int:
    """Choose the next custom broker number based on active config snippets."""
    config_d = Path(config_dir) / "config.d"
    existing_count = 0
    for path in config_d.glob("*.toml"):
        existing_count += path.read_text().count("[[broker]]")
    return existing_count + 1


def _config_dir_has_broker(config_dir: str) -> bool:
    """Return whether any active config drop-in already contains broker blocks."""
    config_d = Path(config_dir) / "config.d"
    if not config_d.is_dir():
        return False
    return any("[[broker]]" in path.read_text() for path in config_d.glob("*.toml"))


# ---------------------------------------------------------------------------
# Update owner info for existing config
# ---------------------------------------------------------------------------

def update_owner_info(config_dir: str) -> None:
    """Update owner public key and email for existing token-auth brokers."""
    user_toml = str(migrate_user_config_filename(config_dir))

    if not Path(user_toml).exists():
        print_error("No configuration file found")
        return

    print()
    print_header("Update Owner Information")

    content = Path(user_toml).read_text()
    has_token_presets = bool(token_preset_brokers(config_dir))
    if 'method = "token"' not in content and not has_token_presets:
        print_warning("No brokers configured with auth token authentication")
        return

    if has_token_presets:
        _configure_token_preset_overrides(config_dir)
        if 'method = "token"' not in content:
            return

    print_info("This will update owner and email for all token-auth brokers")
    print()

    # Extract existing owner and email
    existing_owner = ""
    existing_email = ""
    owner_match = re.search(r'^owner\s*=\s*"([^"]*)"', content, re.MULTILINE)
    if owner_match:
        existing_owner = owner_match.group(1)
    email_match = re.search(r'^email\s*=\s*"([^"]*)"', content, re.MULTILINE)
    if email_match:
        existing_email = email_match.group(1)

    if existing_owner:
        print_info(f"Current owner: {existing_owner}")
    if existing_email:
        print_info(f"Current email: {existing_email}")

    new_owner = prompt_owner_pubkey(existing_owner)
    new_email = prompt_owner_email(existing_email)

    # Back up config
    import shutil
    from datetime import datetime
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    shutil.copy2(user_toml, f"{user_toml}.backup-{timestamp}")

    # Update owner and email
    if new_owner:
        content = re.sub(r'^(owner\s*=\s*).*$', f'\\1"{new_owner}"', content, flags=re.MULTILINE)
    if new_email:
        content = re.sub(r'^(email\s*=\s*).*$', f'\\1"{new_email}"', content, flags=re.MULTILINE)
    Path(user_toml).write_text(content)

    # Summary
    changes = []
    if new_owner:
        changes.append(f"owner: {new_owner}")
    if new_email:
        changes.append(f"email: {new_email}")

    if changes:
        print_success(f"Updated configuration: {', '.join(changes)}")
    else:
        print_success("No changes made")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _read_existing_iata(user_toml: str) -> str:
    """Read the existing IATA code from a user TOML."""
    if not Path(user_toml).exists():
        return ""
    content = Path(user_toml).read_text()
    match = re.search(r'^\s*iata\s*=\s*"([^"]*)"', content, re.MULTILINE)
    return match.group(1) if match else ""


def _update_iata_in_file(user_toml: str, iata: str) -> None:
    """Update the iata value in a user TOML."""
    content = Path(user_toml).read_text()
    content = re.sub(r'^(iata\s*=\s*).*$', f'\\1"{iata}"', content, flags=re.MULTILINE)
    Path(user_toml).write_text(content)


# Need platform for the import in configure_mqtt_brokers
import platform
