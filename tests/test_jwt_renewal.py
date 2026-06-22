"""Tests for per-broker JWT metadata and renewal behavior."""
from __future__ import annotations

import pytest
import time
from types import SimpleNamespace

from meshcore_packet_capture.auth_token import AuthTokenPayload
from meshcore_packet_capture import packet_capture as pc_mod
from meshcore_packet_capture.packet_capture import PacketCapture


def _next_renewal(tokens: dict, *, threshold: int = 300, interval: int = 3600) -> float:
    """Call PacketCapture.seconds_until_next_renewal without constructing the
    (heavy) class, by binding it to a minimal stand-in object."""
    fake = SimpleNamespace(
        jwt_tokens=tokens,
        jwt_renewal_threshold=threshold,
        jwt_renewal_interval=interval,
    )
    return PacketCapture.seconds_until_next_renewal(fake)


def test_no_tokens_falls_back_to_interval_cap():
    assert _next_renewal({}, interval=3600) == 3600.0


def test_short_lived_token_renewed_before_expiry():
    now = time.time()
    # 1h token -> renew 300s before expiry -> ~3300s from now
    wait = _next_renewal({1: {"expires_at": now + 3600}})
    assert 3290 <= wait <= 3300


def test_long_lived_token_capped_at_interval():
    now = time.time()
    # 24h token would be ~86100s out, but the interval cap keeps periodic checks
    wait = _next_renewal({1: {"expires_at": now + 86400}}, interval=3600)
    assert wait == 3600.0


def test_already_due_token_clamped_to_floor():
    now = time.time()
    # Token within (or past) the renewal threshold -> don't busy-loop, sleep the 5s floor
    wait = _next_renewal({1: {"expires_at": now + 100}}, threshold=300)
    assert wait == 5.0


def test_soonest_token_wins_in_mixed_set():
    now = time.time()
    wait = _next_renewal(
        {
            1: {"expires_at": now + 86400},  # 24h
            2: {"expires_at": now + 3600},   # 1h -> drives the schedule
        }
    )
    assert 3290 <= wait <= 3300


def test_tokens_without_expiry_are_ignored():
    now = time.time()
    wait = _next_renewal({1: {"token": "x"}, 2: {"expires_at": now + 3600}})
    assert 3290 <= wait <= 3300


def test_disabled_interval_uses_default_cap():
    # interval <= 0 disables the loop elsewhere, but the cap math still defaults to 3600
    assert _next_renewal({}, interval=0) == 3600.0


class _FakeCap:
    """Minimal stand-in exposing get_env + logger for resolve_token_ttl."""

    def __init__(self, env: dict):
        self._env = env
        self.warnings: list[str] = []
        self.logger = SimpleNamespace(warning=lambda msg, *a, **k: self.warnings.append(msg))

    def get_env(self, key: str, default: str = "") -> str:
        return self._env.get(key, default)


def _resolve_ttl(env: dict, broker_num=1):
    cap = _FakeCap(env)
    return PacketCapture.resolve_token_ttl(cap, broker_num), cap.warnings


def test_token_ttl_valid_value():
    ttl, warns = _resolve_ttl({"MQTT1_TOKEN_TTL": "3600"})
    assert ttl == 3600 and warns == []


def test_token_ttl_unset_uses_default():
    ttl, warns = _resolve_ttl({})
    assert ttl == 86400 and warns == []


def test_token_ttl_none_broker_uses_default():
    assert PacketCapture.resolve_token_ttl(_FakeCap({}), None) == 86400


def test_token_ttl_non_integer_warns_and_defaults():
    ttl, warns = _resolve_ttl({"MQTT1_TOKEN_TTL": "abc"})
    assert ttl == 86400 and len(warns) == 1


def test_token_ttl_non_positive_warns_and_defaults():
    ttl, warns = _resolve_ttl({"MQTT1_TOKEN_TTL": "0"})
    assert ttl == 86400 and len(warns) == 1


def test_payload_carries_custom_exp():
    iat = 1_000_000
    ttl = 3600
    payload = AuthTokenPayload(public_key="ab" * 32, iat=iat, exp=iat + ttl).to_dict()
    assert payload["exp"] == iat + ttl
    assert payload["iat"] == iat


@pytest.mark.asyncio
async def test_jwt_uses_broker_specific_owner_email(monkeypatch: pytest.MonkeyPatch):
    captured: dict = {}

    async def _fake_create_auth_token_async(public_key, **kwargs):
        captured["public_key"] = public_key
        captured["kwargs"] = kwargs
        payload = {
            "publicKey": public_key.upper(),
            "iat": 1,
            "exp": 2,
            "aud": kwargs.get("aud"),
            "owner": kwargs.get("owner"),
            "email": kwargs.get("email"),
            "client": kwargs.get("client"),
        }
        import base64
        import json

        encoded_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        return f"header.{encoded_payload}.signature"

    monkeypatch.setattr(pc_mod, "create_auth_token_async", _fake_create_auth_token_async)
    monkeypatch.setattr(pc_mod, "create_auth_token", None)
    monkeypatch.setenv("PACKETCAPTURE_OWNER_PUBLIC_KEY", "B" * 64)
    monkeypatch.setenv("PACKETCAPTURE_OWNER_EMAIL", "global@example.com")

    cap = SimpleNamespace(
        meshcore=None,
        device_public_key="c" * 64,
        device_private_key="d" * 128,
        debug=False,
        jwt_tokens={},
        logger=SimpleNamespace(
            info=lambda *_a, **_k: None,
            warning=lambda *_a, **_k: None,
            error=lambda *_a, **_k: None,
            debug=lambda *_a, **_k: None,
        ),
        _env={
            "MQTT1_TOKEN_OWNER": "A" * 64,
            "MQTT1_TOKEN_EMAIL": "User@Example.COM",
            "MQTT1_TOKEN_TTL": "3600",
        },
        get_env=lambda key, default="": cap._env.get(key, default),
        resolve_token_ttl=lambda broker_num: 3600,
        _load_client_version=lambda: "meshcore-packet-capture/test",
    )

    async def _create_jwt_with_private_key(audience, expiry_seconds=86400, broker_num=None):
        return await PacketCapture.create_jwt_with_private_key(
            cap,
            audience,
            expiry_seconds=expiry_seconds,
            broker_num=broker_num,
        )

    cap.create_jwt_with_private_key = _create_jwt_with_private_key

    token = await PacketCapture.create_auth_token_jwt(cap, "mqtt.waev.app", 1)

    assert token is not None
    assert captured["kwargs"]["owner"] == "A" * 64
    assert captured["kwargs"]["email"] == "user@example.com"
    assert captured["kwargs"]["aud"] == "mqtt.waev.app"
    assert captured["kwargs"]["expiry_seconds"] == 3600
    assert cap.jwt_tokens[1]["audience"] == "mqtt.waev.app"


@pytest.mark.asyncio
async def test_jwt_owner_email_falls_back_to_global(monkeypatch: pytest.MonkeyPatch):
    captured: dict = {}

    async def _fake_create_auth_token_async(_public_key, **kwargs):
        captured["kwargs"] = kwargs
        return "header.payload.signature"

    monkeypatch.setattr(pc_mod, "create_auth_token_async", _fake_create_auth_token_async)
    monkeypatch.setattr(pc_mod, "create_auth_token", None)
    monkeypatch.setenv("PACKETCAPTURE_OWNER_PUBLIC_KEY", "B" * 64)
    monkeypatch.setenv("PACKETCAPTURE_OWNER_EMAIL", "Global@Example.COM")

    cap = SimpleNamespace(
        meshcore=None,
        device_public_key="c" * 64,
        device_private_key="d" * 128,
        debug=False,
        jwt_tokens={},
        logger=SimpleNamespace(
            info=lambda *_a, **_k: None,
            warning=lambda *_a, **_k: None,
            error=lambda *_a, **_k: None,
            debug=lambda *_a, **_k: None,
        ),
        _env={"MQTT1_TOKEN_TTL": "3600"},
        get_env=lambda key, default="": cap._env.get(key, default),
        resolve_token_ttl=lambda broker_num: 3600,
        _load_client_version=lambda: "meshcore-packet-capture/test",
    )

    await PacketCapture.create_jwt_with_private_key(
        cap,
        "mqtt.waev.app",
        expiry_seconds=3600,
        broker_num=1,
    )

    assert captured["kwargs"]["owner"] == "B" * 64
    assert captured["kwargs"]["email"] == "global@example.com"
