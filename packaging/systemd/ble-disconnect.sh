#!/bin/bash
# Best-effort BLE teardown, run from the systemd unit's ExecStopPost.
#
# Only acts when the configured connection is BLE: it requires both
# connection_type = "ble" and a ble_address in the TOML config, then asks
# bluetoothctl to drop the link so a stale bond doesn't block the next start.
# Serial/TCP installs are a no-op. Never fails the service stop.
set -u

CONFIG_D="${1:-/etc/meshcore-packet-capture/config.d}"

# Gate: only proceed for BLE connections (authoritative value lives in config.d,
# where the installer writes the chosen connection_type).
grep -rhiq 'connection_type[[:space:]]*=[[:space:]]*"ble"' --include='*.toml' "$CONFIG_D" 2>/dev/null || exit 0

# Extract the configured BLE address (text between the first pair of quotes).
addr=$(grep -rhi 'ble_address[[:space:]]*=' --include='*.toml' "$CONFIG_D" 2>/dev/null | head -1 | cut -d'"' -f2)
[ -n "$addr" ] || exit 0

command -v bluetoothctl >/dev/null 2>&1 || exit 0

echo "Disconnecting BLE device ${addr}..."
bluetoothctl disconnect "$addr" || true
exit 0
