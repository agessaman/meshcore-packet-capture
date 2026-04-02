#!/usr/bin/env python3
import sys
import types
import unittest


def _install_dependency_stubs() -> None:
    """Install minimal stubs so packet_capture can import in test environments."""
    if "meshcore" not in sys.modules:
        meshcore_stub = types.ModuleType("meshcore")
        meshcore_stub.EventType = type("EventType", (), {})
        sys.modules["meshcore"] = meshcore_stub

    if "paho" not in sys.modules:
        paho_module = types.ModuleType("paho")
        mqtt_module = types.ModuleType("paho.mqtt")
        mqtt_client_module = types.ModuleType("paho.mqtt.client")
        mqtt_module.client = mqtt_client_module
        paho_module.mqtt = mqtt_module
        sys.modules["paho"] = paho_module
        sys.modules["paho.mqtt"] = mqtt_module
        sys.modules["paho.mqtt.client"] = mqtt_client_module


_install_dependency_stubs()

from enums import PayloadType, PayloadVersion, RouteType
from packet_capture import PacketCapture


def _build_packet_hex(
    payload: bytes,
    *,
    route_type: int = RouteType.FLOOD.value,
    payload_type: int = PayloadType.ADVERT.value,
    path_len_byte: int = 0x01,
    path_bytes: bytes = b"\xAA",
    transport_bytes: bytes = b"",
) -> str:
    header = ((PayloadVersion.VER_1.value & 0x03) << 6) | ((payload_type & 0x0F) << 2) | (route_type & 0x03)
    packet = bytes([header]) + transport_bytes + bytes([path_len_byte]) + path_bytes + payload
    return packet.hex()


def _make_valid_advert_payload() -> bytes:
    pub_key = bytes.fromhex("11" * 32)
    advert_time = (123456).to_bytes(4, byteorder="little", signed=False)
    signature = bytes.fromhex("22" * 64)
    appdata = b"\x01"  # ADV_TYPE_CHAT
    return pub_key + advert_time + signature + appdata


class TestAdvertDecodeRobustness(unittest.TestCase):
    def setUp(self) -> None:
        self.capture = PacketCapture(enable_mqtt=False)

    def test_short_advert_payload_is_rejected(self) -> None:
        short_payload = bytes.fromhex("33" * 68)
        raw_hex = _build_packet_hex(short_payload)
        decoded = self.capture.decode_and_publish_message(raw_hex)
        self.assertIsNone(decoded)

    def test_valid_advert_payload_decodes_with_required_fields(self) -> None:
        raw_hex = _build_packet_hex(_make_valid_advert_payload())
        decoded = self.capture.decode_and_publish_message(raw_hex)
        self.assertIsNotNone(decoded)
        self.assertEqual(decoded["payload_type"], PayloadType.ADVERT.name)
        self.assertTrue(decoded["advert_parse_ok"])
        self.assertIn("public_key", decoded)
        self.assertIn("advert_time", decoded)
        self.assertIn("signature", decoded)

    def test_packed_two_byte_hops_slice_payload_correctly(self) -> None:
        # path_len_byte: high bits 01 => 2 bytes/hop, low bits 02 => 2 hops => 4 path bytes
        raw_hex = _build_packet_hex(
            _make_valid_advert_payload(),
            path_len_byte=0x42,
            path_bytes=bytes.fromhex("A1B2C3D4"),
        )
        decoded = self.capture.decode_and_publish_message(raw_hex)
        self.assertIsNotNone(decoded)
        self.assertEqual(decoded["path_hash_bytes"], 2)
        self.assertEqual(decoded["path_byte_len"], 4)
        self.assertTrue(decoded["advert_parse_ok"])
        self.assertIn("public_key", decoded)

    def test_issue24_sample_does_not_raise_keyerror(self) -> None:
        # Reported packet from issue #24
        sample_hex = (
            "114096acef6f63bce25f06983cfb0040d39395fd2eb5769395504d020a422d6e94b6d75"
            "245669186ecb0a975a410c21aa6d6710793204ac9d22e5637c7fa22cd16884fa656eaed2"
            "a1a489c671967f5f9bdede9d54892ec21d4461cb82d0d8f89a058bdae2b029291065b020"
            "2f4c1f944454e2d5041524b522d524a48504b2d52452d39364143"
        )
        decoded = self.capture.decode_and_publish_message(sample_hex)
        if decoded is not None and decoded.get("payload_type") == PayloadType.ADVERT.name:
            self.assertIn("public_key", decoded)

    def test_reserved_mode_falls_back_to_legacy_length(self) -> None:
        path_byte_len, path_hash_bytes = self.capture._decode_packed_path_length(0xC2)
        self.assertEqual(path_byte_len, 0xC2)
        self.assertEqual(path_hash_bytes, 1)


if __name__ == "__main__":
    unittest.main()
