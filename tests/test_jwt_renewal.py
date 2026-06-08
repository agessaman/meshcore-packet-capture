"""Tests for per-broker JWT TTL: the expiry-driven renewal scheduler computation
and that a custom expiry is carried in the token payload."""
from __future__ import annotations

import time
from types import SimpleNamespace

from meshcore_packet_capture.auth_token import AuthTokenPayload
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


def test_payload_carries_custom_exp():
    iat = 1_000_000
    ttl = 3600
    payload = AuthTokenPayload(public_key="ab" * 32, iat=iat, exp=iat + ttl).to_dict()
    assert payload["exp"] == iat + ttl
    assert payload["iat"] == iat
