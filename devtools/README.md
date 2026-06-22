# Developer tools

Optional scripts for BLE debugging and network scanning. They are **not** installed by the main installer to `/opt/meshcore-packet-capture`.

| Script | Purpose |
|--------|---------|
| `scan_meshcore_network.py` | Scan LAN for MeshCore TCP nodes |
| `debug_ble_connection.py` | BLE connection debugging |
| `ble_scan_helper.py` | BLE scan helper |
| `ble_pairing_helper.py` | Linux BLE pairing helper |

Run from repo root with `PYTHONPATH=src` if a script needs the `meshcore_packet_capture` package, or use a venv where you have run `pip install -e .`.
