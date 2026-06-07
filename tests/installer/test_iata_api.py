"""Tests for installer.config IATA API helpers (network mocked)."""
from __future__ import annotations

import json

import pytest

from installer import config as cfg


def test_iata_api_url_includes_source_and_params():
    url = cfg._iata_api_url("code=SEA", "1.2.3")
    assert url.startswith(cfg.IATA_API_BASE + "?")
    assert "code=SEA" in url
    assert "source=installer-1.2.3" in url


def test_search_iata_api_parses_results(monkeypatch: pytest.MonkeyPatch):
    payload = json.dumps([
        {"iata": "SEA", "name": "Seattle-Tacoma"},
        {"iata": "PDX", "name": "Portland Intl"},
    ]).encode()
    monkeypatch.setattr(cfg, "_iata_request", lambda url: payload)
    assert cfg.search_iata_api("sea") == [("SEA", "Seattle-Tacoma"), ("PDX", "Portland Intl")]


def test_search_iata_api_returns_empty_on_error(monkeypatch: pytest.MonkeyPatch):
    def _boom(url):
        raise OSError("network down")

    monkeypatch.setattr(cfg, "_iata_request", _boom)
    assert cfg.search_iata_api("sea") == []


def test_lookup_iata_code_returns_name(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(cfg, "_iata_request", lambda url: json.dumps({"name": "Seattle"}).encode())
    assert cfg.lookup_iata_code("SEA") == "Seattle"


def test_lookup_iata_code_unavailable_returns_none(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(cfg, "time", type("T", (), {"sleep": staticmethod(lambda *_: None)}))

    def _boom(url):
        raise OSError("network down")

    monkeypatch.setattr(cfg, "_iata_request", _boom)
    assert cfg.lookup_iata_code("SEA") is None
