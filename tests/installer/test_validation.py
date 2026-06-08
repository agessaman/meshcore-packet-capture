"""Tests for installer.config input validation and small TOML helpers."""
from __future__ import annotations

import pytest

from installer.config import (
    toml_escape,
    validate_email,
    validate_meshcore_pubkey,
)


# --- pubkey ----------------------------------------------------------------

def test_pubkey_valid_normalizes_case_and_spaces():
    raw = "ab cd " + "0" * 60  # 64 hex chars once spaces removed
    assert validate_meshcore_pubkey(raw) == ("ABCD" + "0" * 60)


def test_pubkey_wrong_length_rejected():
    assert validate_meshcore_pubkey("ABCD") is None
    assert validate_meshcore_pubkey("A" * 65) is None


def test_pubkey_non_hex_rejected():
    assert validate_meshcore_pubkey("Z" * 64) is None


# --- email -----------------------------------------------------------------

@pytest.mark.parametrize("email", ["user@example.com", "First.Last@sub.domain.org"])
def test_email_valid(email):
    assert validate_email(email) == email.lower()


@pytest.mark.parametrize(
    "email",
    [
        "no-at-sign",
        "user@nodot",
        "@example.com",
        "user@example.com.",
        ".user@example.com",
        "user..name@example.com",
        "user name@example.com",
    ],
)
def test_email_invalid(email):
    assert validate_email(email) is None


# --- toml helpers ----------------------------------------------------------

def test_toml_escape_quotes_and_backslashes():
    assert toml_escape(r'a"b\c') == r'a\"b\\c'
