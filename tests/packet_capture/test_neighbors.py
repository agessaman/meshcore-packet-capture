"""Tests for the MQTT neighbors feature (discovery, scopes, payload, gating)."""
from __future__ import annotations

import asyncio
import json

import pytest

from meshcore_packet_capture import neighbors as nb


# --------------------------------------------------------------------------
# Interval clamping (firmware band: 12-336h, default 24h)
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "given,expected",
    [(11, 12), (12, 12), (24, 24), (48, 48), (336, 336), (400, 336), (0, 24), (-5, 24)],
)
def test_clamp_interval_hours(given, expected):
    assert nb.clamp_interval_hours(given) == expected


def test_interval_seconds_uses_clamped_value():
    assert nb.NeighborsConfig(interval_hours=1).interval_seconds == 12 * 3600
    assert nb.NeighborsConfig(interval_hours=9999).interval_seconds == 336 * 3600


# --------------------------------------------------------------------------
# Ordering: most recently heard, then stronger SNR, then pubkey
# --------------------------------------------------------------------------

def _entry(pubkey_byte: str, snr: float, heard_at: float) -> nb.NeighborEntry:
    return nb.NeighborEntry(pubkey=pubkey_byte * 64, snr=snr, heard_at=heard_at)


def test_sort_prefers_most_recently_heard():
    older = _entry("a", 20.0, 100.0)
    newer = _entry("b", -5.0, 200.0)
    assert nb.sort_entries([older, newer]) == [newer, older]


def test_sort_breaks_recency_tie_by_snr():
    weak = _entry("a", 1.0, 100.0)
    strong = _entry("b", 9.0, 100.0)
    assert nb.sort_entries([weak, strong]) == [strong, weak]


def test_sort_breaks_full_tie_by_pubkey_ascending():
    first = _entry("1", 5.0, 100.0)
    second = _entry("2", 5.0, 100.0)
    assert nb.sort_entries([second, first]) == [first, second]


# --------------------------------------------------------------------------
# Payload shape and tail-drop
# --------------------------------------------------------------------------

def test_message_matches_firmware_contract():
    entry = nb.NeighborEntry(pubkey="ab" * 32, snr=9.75, heard_at=100.0, scopes="DEN,APRS")
    entry.status = nb.STATUS_RESPONDED
    message, dropped = nb.build_neighbors_message(
        "MeshCore-HOWL", "A1B2", "DEN,APRS", [entry], timestamp="2024-01-01T12:00:00+00:00", now=142.0
    )
    assert dropped == 0
    # Firmware key order (MQTTPayloadBuilder.cpp:200-210).
    assert list(message.keys()) == [
        "timestamp", "origin", "origin_id",
        "total_neighbors", "queried_neighbors", "truncated",
        "self", "neighbors",
    ]
    assert message["origin"] == "MeshCore-HOWL"
    assert message["origin_id"] == "A1B2"
    assert message["self"] == {"scopes": "DEN,APRS"}

    assert message["total_neighbors"] == 1
    assert message["queried_neighbors"] == 1
    assert message["truncated"] is False

    (published,) = message["neighbors"]
    assert list(published.keys()) == ["pubkey", "snr", "heard_secs_ago", "scopes", "status"]
    assert published["pubkey"] == ("ab" * 32).upper()
    assert published["snr"] == 9.75
    assert published["heard_secs_ago"] == 42
    assert published["status"] == "responded"


def test_heard_secs_ago_never_negative():
    entry = nb.NeighborEntry(pubkey="cd" * 32, snr=0.0, heard_at=500.0)
    # Clock stepped backwards between discovery and publish.
    assert entry.heard_secs_ago(now=100.0) == 0


def test_default_status_is_timeout():
    assert nb.NeighborEntry(pubkey="ef" * 32, snr=0.0, heard_at=1.0).status == nb.STATUS_TIMEOUT


def test_tail_is_dropped_at_budget_keeping_most_useful():
    # Newest first: heard_at descending is the retention order.
    entries = [
        nb.NeighborEntry(pubkey=f"{i:02x}" * 32, snr=0.0, heard_at=float(i), scopes="X" * 40)
        for i in range(40)
    ]
    message, dropped = nb.build_neighbors_message(
        "o", "id", "", entries, timestamp="T", now=100.0, budget=1024
    )
    assert dropped > 0
    assert len(message["neighbors"]) + dropped == len(entries)
    assert len(json.dumps(message)) < 1024
    # The retained entries are the highest heard_at values.
    retained = {e["pubkey"].lower() for e in message["neighbors"]}
    expected_first = (f"{39:02x}" * 32)
    assert expected_first in retained


def test_budget_not_applied_when_payload_fits():
    entries = [nb.NeighborEntry(pubkey="11" * 32, snr=1.0, heard_at=1.0)]
    message, dropped = nb.build_neighbors_message("o", "id", "", entries, timestamp="T", now=1.0)
    assert dropped == 0
    assert len(message["neighbors"]) == 1


# --------------------------------------------------------------------------
# Zero-hop contact override (the mechanism from plan section 3.1)
# --------------------------------------------------------------------------

class _FakeLogger:
    def __init__(self):
        self.messages = []

    def _record(self, msg, *a, **k):
        self.messages.append(str(msg))

    debug = info = warning = error = _record


def test_zero_hop_contact_is_direct_with_empty_path():
    contact = nb._zero_hop_contact("aa" * 32)
    # out_path_len == 0 keeps meshcore_py off its out_path_len == -1 branch, so it
    # issues no change_contact_path/reset_path writes to the device.
    assert contact["out_path_len"] == 0
    assert contact["out_path"] == ""
    assert contact["public_key"] == "aa" * 32


class _ContactCacheMeshCore:
    """Mirrors MeshCore: `contacts` is a property returning the live dict."""

    def __init__(self, initial=None):
        self._contacts = dict(initial or {})

    @property
    def contacts(self):
        return self._contacts


def test_override_injects_then_removes_when_no_prior_contact():
    mc = _ContactCacheMeshCore()
    key = "bb" * 32
    with nb.zero_hop_contact_override(mc, key, _FakeLogger()) as ok:
        assert ok is True
        assert mc._contacts[key]["out_path_len"] == 0
    assert key not in mc._contacts


def test_override_restores_preexisting_contact_exactly():
    key = "cc" * 32
    real = {"public_key": key, "out_path_len": 3, "out_path": "aabbcc", "adv_name": "repeater"}
    mc = _ContactCacheMeshCore({key: real})
    with nb.zero_hop_contact_override(mc, key, _FakeLogger()):
        # A stale multi-hop path must not route the probe the long way.
        assert mc._contacts[key]["out_path_len"] == 0
    assert mc._contacts[key] is real
    assert mc._contacts[key]["out_path_len"] == 3


def test_override_restores_even_when_body_raises():
    key = "dd" * 32
    real = {"public_key": key, "out_path_len": 2, "out_path": "1122"}
    mc = _ContactCacheMeshCore({key: real})
    with pytest.raises(RuntimeError):
        with nb.zero_hop_contact_override(mc, key, _FakeLogger()):
            raise RuntimeError("scope request blew up")
    assert mc._contacts[key] is real


def test_override_reports_false_without_contact_cache():
    class FakeMeshCore:
        pass

    with nb.zero_hop_contact_override(FakeMeshCore(), "ee" * 32, _FakeLogger()) as ok:
        assert ok is False


# --------------------------------------------------------------------------
# Scope collection: pacing, status assignment, budget
# --------------------------------------------------------------------------

class _FakeCommands:
    def __init__(self, responses):
        self._responses = responses
        self.calls = []

    async def req_regions_sync(self, pubkey, timeout=0, min_timeout=0):
        self.calls.append({"pubkey": pubkey, "timeout": timeout, "min_timeout": min_timeout})
        result = self._responses.get(pubkey, None)
        # The real function returns None for every device/library failure -- send()
        # swallows exceptions into Event(ERROR) and req_regions_sync maps that to
        # None. Only a genuine transport-level blow-up propagates, so exceptions
        # here are opt-in per test rather than the default failure mode.
        # BaseException, not Exception: CancelledError is not an Exception subclass.
        if isinstance(result, BaseException):
            raise result
        return result


class _FakeMeshCore:
    def __init__(self, responses):
        self.commands = _FakeCommands(responses)
        self._contacts: dict = {}

    @property
    def contacts(self):
        return self._contacts


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture(autouse=True)
def no_real_waiting(monkeypatch: pytest.MonkeyPatch):
    """Collapse the discover window and settle gaps to a bare event-loop yield.

    Yielding rather than skipping matters: EventDispatcher spawns async callbacks
    as background tasks, so the collection path only works if control is handed
    back to the loop.
    """
    real_sleep = asyncio.sleep

    async def instant(_seconds):
        await real_sleep(0)

    monkeypatch.setattr(nb.asyncio, "sleep", instant)


def test_collect_scopes_assigns_statuses():
    responded = _entry("a", 5.0, 300.0)
    timed_out = _entry("b", 5.0, 200.0)
    entries = [responded, timed_out]

    mc = _FakeMeshCore({responded.pubkey: "DEN,APRS", timed_out.pubkey: None})
    cfg = nb.NeighborsConfig(scope_gap=0.0)
    _run(nb.collect_scopes(mc, entries, cfg, _FakeLogger()))

    assert (responded.status, responded.scopes) == (nb.STATUS_RESPONDED, "DEN,APRS")
    # None covers a real timeout and a device-level rejection alike.
    assert timed_out.status == nb.STATUS_TIMEOUT


def test_collect_scopes_reports_send_failed_when_no_contact_cache():
    """No contact cache means nothing was transmitted at all.

    Reporting that as a timeout would assert on the topic that the neighbor was
    asked and stayed silent, when in fact no frame ever left the radio.
    """
    class NoCacheMeshCore:
        def __init__(self):
            self.commands = _FakeCommands({})

    entry = _entry("a", 5.0, 100.0)
    mc = NoCacheMeshCore()
    logger = _FakeLogger()
    _run(nb.collect_scopes(mc, [entry], nb.NeighborsConfig(scope_gap=0.0), logger))

    assert entry.status == nb.STATUS_SEND_FAILED
    assert mc.commands.calls == []
    assert any("contact cache unavailable" in m for m in logger.messages)


def test_collect_scopes_reports_send_failed_on_transport_exception():
    entry = _entry("a", 5.0, 100.0)
    mc = _FakeMeshCore({entry.pubkey: RuntimeError("serial write blew up")})
    _run(nb.collect_scopes(mc, [entry], nb.NeighborsConfig(scope_gap=0.0), _FakeLogger()))
    assert entry.status == nb.STATUS_SEND_FAILED


def test_collect_scopes_responded_with_empty_scope_string():
    entry = _entry("a", 1.0, 100.0)
    mc = _FakeMeshCore({entry.pubkey: ""})
    _run(nb.collect_scopes(mc, [entry], nb.NeighborsConfig(scope_gap=0.0), _FakeLogger()))
    # An empty reply still means the neighbor answered - it just has no scopes.
    assert entry.status == nb.STATUS_RESPONDED
    assert entry.scopes == ""


def test_collect_scopes_passes_auto_timeout_and_floor():
    entry = _entry("a", 1.0, 100.0)
    mc = _FakeMeshCore({entry.pubkey: "X"})
    cfg = nb.NeighborsConfig(scope_gap=0.0, scope_timeout=0.0, scope_min_timeout=8.0)
    _run(nb.collect_scopes(mc, [entry], cfg, _FakeLogger()))
    # timeout=0 lets the device's own suggested_timeout drive the wait.
    assert mc.commands.calls[0]["timeout"] == 0
    assert mc.commands.calls[0]["min_timeout"] == 8.0


def test_collect_scopes_honours_explicit_timeout_override():
    entry = _entry("a", 1.0, 100.0)
    mc = _FakeMeshCore({entry.pubkey: "X"})
    cfg = nb.NeighborsConfig(scope_gap=0.0, scope_timeout=25.0)
    _run(nb.collect_scopes(mc, [entry], cfg, _FakeLogger()))
    assert mc.commands.calls[0]["timeout"] == 25.0


def test_collect_scopes_queries_one_at_a_time_in_sorted_order():
    entries = nb.sort_entries([_entry("a", 1.0, 100.0), _entry("b", 1.0, 300.0)])
    mc = _FakeMeshCore({e.pubkey: "S" for e in entries})
    _run(nb.collect_scopes(mc, entries, nb.NeighborsConfig(scope_gap=0.0), _FakeLogger()))
    # Newest-heard neighbor is queried first, so a truncated cycle covers it.
    assert [c["pubkey"] for c in mc.commands.calls] == [entries[0].pubkey, entries[1].pubkey]


def test_collect_scopes_stops_at_cycle_budget_leaving_rest_as_timeout(
    monkeypatch: pytest.MonkeyPatch,
):
    entries = [_entry(f"{i}", 1.0, float(100 - i)) for i in range(4)]
    mc = _FakeMeshCore({e.pubkey: "S" for e in entries})
    cfg = nb.NeighborsConfig(scope_gap=0.0, cycle_timeout=30.0)

    # Jump the clock past the budget after the second neighbor is queried.
    clock = {"t": 1000.0}
    real_sync = mc.commands.req_regions_sync

    async def ticking_sync(pubkey, timeout=0, min_timeout=0):
        result = await real_sync(pubkey, timeout=timeout, min_timeout=min_timeout)
        if len(mc.commands.calls) == 2:
            clock["t"] += cfg.cycle_timeout + 1
        return result

    mc.commands.req_regions_sync = ticking_sync
    monkeypatch.setattr(nb.time, "time", lambda: clock["t"])

    logger = _FakeLogger()
    _run(nb.collect_scopes(mc, entries, cfg, logger))

    assert len(mc.commands.calls) == 2
    # The two that were reached answered; the rest keep the firmware's fallback.
    assert [e.status for e in entries[:2]] == [nb.STATUS_RESPONDED, nb.STATUS_RESPONDED]
    assert [e.status for e in entries[2:]] == [nb.STATUS_TIMEOUT, nb.STATUS_TIMEOUT]
    assert any("cycle budget" in m and "2 of 4" in m for m in logger.messages)


def test_collect_scopes_handles_empty_list():
    mc = _FakeMeshCore({})
    _run(nb.collect_scopes(mc, [], nb.NeighborsConfig(), _FakeLogger()))
    assert mc.commands.calls == []


def test_collect_scopes_leaves_contact_cache_clean():
    entries = [_entry("a", 1.0, 100.0), _entry("b", 1.0, 90.0)]
    mc = _FakeMeshCore({entries[0].pubkey: "S", entries[1].pubkey: RuntimeError("boom")})
    _run(nb.collect_scopes(mc, entries, nb.NeighborsConfig(scope_gap=0.0), _FakeLogger()))
    assert mc._contacts == {}


def test_collect_scopes_propagates_cancellation():
    entry = _entry("a", 1.0, 100.0)
    mc = _FakeMeshCore({entry.pubkey: asyncio.CancelledError()})
    with pytest.raises(asyncio.CancelledError):
        _run(nb.collect_scopes(mc, [entry], nb.NeighborsConfig(scope_gap=0.0), _FakeLogger()))


# --------------------------------------------------------------------------
# Self scopes
# --------------------------------------------------------------------------

def test_self_scopes_override_wins_without_querying():
    class Commands:
        async def get_default_flood_scope(self):
            raise AssertionError("must not query when overridden")

    class MC:
        commands = Commands()

    cfg = nb.NeighborsConfig(self_scopes="DEN,APRS")
    assert _run(nb.fetch_self_scopes(MC(), cfg, _FakeLogger())) == "DEN,APRS"


def test_self_scopes_absent_command_returns_empty():
    class MC:
        class commands:
            pass

    assert _run(nb.fetch_self_scopes(MC(), nb.NeighborsConfig(), _FakeLogger())) == ""


# --------------------------------------------------------------------------
# Discovery filter constants match the firmware
# --------------------------------------------------------------------------

def test_discover_filter_is_repeater_bitmask():
    # sendNodeDiscoverReq: data[1] = (1 << ADV_TYPE_REPEATER)
    assert nb.ADV_TYPE_REPEATER == 0x02
    assert nb.DISCOVER_FILTER_REPEATER == 0x04


def test_json_budget_matches_firmware_buffer():
    # MQTTBridge::NEIGHBORS_JSON_BUFFER_SIZE
    assert nb.NEIGHBORS_JSON_BUDGET == 10240


# --------------------------------------------------------------------------
# Stage 1: discovery response collection and filtering
# --------------------------------------------------------------------------

class _FakeEvent:
    def __init__(self, etype, payload):
        self.type = etype
        self.payload = payload


# Sentinels for "tag matching this discovery round"; the fake fills in the real one,
# in lowercase hex or uppercase hex respectively.
ROUND_TAG = object()
ROUND_TAG_UPPER = object()


def _resp(pubkey: str, snr: float, tag=ROUND_TAG, node_type: int = 0x02) -> dict:
    return {"pubkey": pubkey, "SNR": snr, "node_type": node_type, "tag": tag}


class _DiscoverMeshCore:
    """Replays DISCOVER_RESPONSE events into the handler during the window."""

    def __init__(self, responses, *, send_error=False):
        self._responses = responses
        self._send_error = send_error
        self.unsubscribed = []
        self.sent = None
        self._handler = None
        outer = self

        class Commands:
            async def send_node_discover_req(self, filter, prefix_only=True, tag=None, since=None):
                outer.sent = {"filter": filter, "prefix_only": prefix_only, "tag": tag}
                # The caller must know the tag before subscribing, otherwise a
                # response arriving here would dodge the tag check.
                assert tag is not None, "caller must supply the tag"
                if outer._send_error:
                    return _FakeEvent("ERROR", {"reason": "unsupported"})
                round_tag = tag.to_bytes(4, "little").hex()
                for payload in outer._responses:
                    event = dict(payload)
                    if event["tag"] is ROUND_TAG:
                        event["tag"] = round_tag
                    elif event["tag"] is ROUND_TAG_UPPER:
                        event["tag"] = round_tag.upper()
                    else:
                        event["tag"] = int(event["tag"]).to_bytes(4, "little").hex()
                    await outer._handler(_FakeEvent("discover_response", event))
                return _FakeEvent("OK", {"tag": tag})

        self.commands = Commands()

    def subscribe(self, event_type, handler):
        self._handler = handler
        return f"sub:{event_type}"

    def unsubscribe(self, subscription):
        self.unsubscribed.append(subscription)


def test_discover_requests_full_pubkeys_from_repeaters_only():
    mc = _DiscoverMeshCore([])
    _run(nb.discover_neighbors(mc, nb.NeighborsConfig(discover_window=0.0), None, _FakeLogger()))
    # sendNodeDiscoverReq: filter = 1 << ADV_TYPE_REPEATER, prefix_only = 0
    assert mc.sent["filter"] == nb.DISCOVER_FILTER_REPEATER
    assert mc.sent["prefix_only"] is False


def test_discover_supplies_its_own_tag():
    mc = _DiscoverMeshCore([])
    _run(nb.discover_neighbors(mc, nb.NeighborsConfig(discover_window=0.0), None, _FakeLogger()))
    # A caller-generated tag is what closes the subscribe/send race.
    assert isinstance(mc.sent["tag"], int)
    assert 1 <= mc.sent["tag"] <= 0xFFFFFFFF


def test_discover_collects_matching_responses():
    a, b = "aa" * 32, "bb" * 32
    mc = _DiscoverMeshCore([_resp(a, 5.0), _resp(b, 9.0)])
    entries = _run(
        nb.discover_neighbors(mc, nb.NeighborsConfig(discover_window=0.0), None, _FakeLogger())
    )
    assert {e.pubkey for e in entries} == {a, b}


def test_discover_filters_non_repeaters_short_keys_self_and_wrong_tag():
    good = "aa" * 32
    self_key = "bb" * 32
    mc = _DiscoverMeshCore([
        _resp(good, 5.0),
        _resp("cc" * 32, 5.0, node_type=0x01),      # companion, not a repeater
        _resp("dd" * 8, 5.0),                       # 8-byte prefix, not a full pubkey
        _resp(self_key, 5.0),                       # ourselves
        _resp("ee" * 32, 5.0, tag=0x99999999),      # a different discovery round
    ])
    entries = _run(
        nb.discover_neighbors(
            mc, nb.NeighborsConfig(discover_window=0.0), self_key.upper(), _FakeLogger()
        )
    )
    assert [e.pubkey for e in entries] == [good]


def test_discover_normalises_pubkey_case():
    key = "AB" * 32
    mc = _DiscoverMeshCore([_resp(key, 5.0)])
    entries = _run(
        nb.discover_neighbors(mc, nb.NeighborsConfig(discover_window=0.0), None, _FakeLogger())
    )
    # Pubkeys are normalised to lowercase for consistent comparison/dedupe.
    assert [e.pubkey for e in entries] == [key.lower()]


def test_discover_matches_tag_case_insensitively():
    key = "aa" * 32
    mc = _DiscoverMeshCore([_resp(key, 5.0, tag=ROUND_TAG_UPPER)])
    entries = _run(
        nb.discover_neighbors(mc, nb.NeighborsConfig(discover_window=0.0), None, _FakeLogger())
    )
    assert [e.pubkey for e in entries] == [key]


def test_discover_dedupes_across_pubkey_case():
    key = "aa" * 32
    mc = _DiscoverMeshCore([_resp(key, 3.0), _resp(key.upper(), 11.0)])
    entries = _run(
        nb.discover_neighbors(mc, nb.NeighborsConfig(discover_window=0.0), None, _FakeLogger())
    )
    assert len(entries) == 1
    assert entries[0].snr == 11.0


def test_discover_dedupes_keeping_strongest_snr():
    key = "aa" * 32
    mc = _DiscoverMeshCore([_resp(key, 3.0), _resp(key, 11.0), _resp(key, 7.0)])
    entries = _run(
        nb.discover_neighbors(mc, nb.NeighborsConfig(discover_window=0.0), None, _FakeLogger())
    )
    assert len(entries) == 1
    assert entries[0].snr == 11.0


def test_discover_returns_sorted_entries():
    mc = _DiscoverMeshCore([_resp("aa" * 32, 1.0), _resp("bb" * 32, 20.0)])
    entries = _run(
        nb.discover_neighbors(mc, nb.NeighborsConfig(discover_window=0.0), None, _FakeLogger())
    )
    assert entries == nb.sort_entries(entries)


def test_discover_returns_none_when_request_rejected():
    mc = _DiscoverMeshCore([], send_error=True)
    assert _run(
        nb.discover_neighbors(mc, nb.NeighborsConfig(discover_window=0.0), None, _FakeLogger())
    ) is None


def test_discover_always_unsubscribes():
    mc = _DiscoverMeshCore([], send_error=True)
    _run(nb.discover_neighbors(mc, nb.NeighborsConfig(discover_window=0.0), None, _FakeLogger()))
    # The handler is per-run; leaving it attached would leak across reconnects.
    assert mc.unsubscribed == ["sub:discover_response"]


def test_discover_empty_result_is_empty_list_not_none():
    mc = _DiscoverMeshCore([])
    assert _run(
        nb.discover_neighbors(mc, nb.NeighborsConfig(discover_window=0.0), None, _FakeLogger())
    ) == []


# --------------------------------------------------------------------------
# PacketCapture integration: topic resolution, per-broker gating, scheduling
# --------------------------------------------------------------------------

from meshcore_packet_capture import packet_capture as pc_mod  # noqa: E402
from meshcore_packet_capture.packet_capture import PacketCapture  # noqa: E402


@pytest.fixture
def capture(monkeypatch: pytest.MonkeyPatch) -> PacketCapture:
    monkeypatch.setenv("PACKETCAPTURE_IATA", "SEA")
    cap = PacketCapture(enable_mqtt=False)
    cap.device_public_key = "ab" * 32
    cap.device_name = "MeshCore-TEST"
    return cap


def test_neighbors_topic_defaults_to_iata_route(capture: PacketCapture):
    assert capture.get_topic("neighbors", 1) == f"meshcore/SEA/{('ab' * 32)}/neighbors"


def test_neighbors_topic_none_without_iata(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("PACKETCAPTURE_IATA", "LOC")  # the unconfigured default
    cap = PacketCapture(enable_mqtt=False)
    cap.device_public_key = "ab" * 32
    # No classic meshcore/neighbors fallback: the firmware only routes this topic
    # on MeshCore-style topics, which require an IATA.
    assert cap.get_topic("neighbors", 1) is None


def test_neighbors_topic_explicit_override_works_without_iata(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("PACKETCAPTURE_IATA", "LOC")
    monkeypatch.setenv("PACKETCAPTURE_MQTT1_TOPIC_NEIGHBORS", "custom/{PUBLIC_KEY}/neighbors")
    cap = PacketCapture(enable_mqtt=False)
    cap.device_public_key = "ab" * 32
    assert cap.get_topic("neighbors", 1) == f"custom/{('ab' * 32)}/neighbors"


@pytest.mark.parametrize("value,expected", [
    ("true", True), ("True", True), ("1", True), ("yes", True), ("on", True),
    ("false", False), ("0", False), ("off", False), ("", False),
])
def test_broker_wants_neighbors_parsing(monkeypatch: pytest.MonkeyPatch, value, expected):
    monkeypatch.setenv("PACKETCAPTURE_MQTT1_NEIGHBORS", value)
    cap = PacketCapture(enable_mqtt=False)
    assert cap._broker_wants_neighbors(1) is expected


def test_broker_wants_neighbors_defaults_off(capture: PacketCapture):
    # Unset must be off, matching the firmware's mqtt_neighbors_enabled default.
    assert capture._broker_wants_neighbors(1) is False


def test_neighbors_broker_nums_requires_enabled_and_opted_in(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("PACKETCAPTURE_IATA", "SEA")
    monkeypatch.setenv("PACKETCAPTURE_MQTT1_ENABLED", "true")
    monkeypatch.setenv("PACKETCAPTURE_MQTT1_NEIGHBORS", "true")
    monkeypatch.setenv("PACKETCAPTURE_MQTT2_ENABLED", "true")   # enabled, not opted in
    monkeypatch.setenv("PACKETCAPTURE_MQTT3_ENABLED", "false")  # opted in but disabled
    monkeypatch.setenv("PACKETCAPTURE_MQTT3_NEIGHBORS", "true")
    cap = PacketCapture(enable_mqtt=False)
    assert cap.neighbors_broker_nums() == [1]


def test_neighbors_broker_nums_empty_when_none_opted_in(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("PACKETCAPTURE_MQTT1_ENABLED", "true")
    cap = PacketCapture(enable_mqtt=False)
    assert cap.neighbors_broker_nums() == []


def test_safe_publish_skips_brokers_that_did_not_opt_in(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("PACKETCAPTURE_IATA", "SEA")
    monkeypatch.setenv("PACKETCAPTURE_MQTT1_NEIGHBORS", "true")
    # broker 2 deliberately left off
    cap = PacketCapture(enable_mqtt=True)
    cap.device_public_key = "ab" * 32
    cap.mqtt_connected = True

    published = []

    class FakeClient:
        def __init__(self, num):
            self.num = num

        def is_connected(self):
            return True

        def publish(self, topic, payload, qos=0, retain=False):
            published.append((self.num, topic, retain))
            return type("R", (), {"rc": 0})()

    cap.mqtt_clients = [
        {"client": FakeClient(1), "broker_num": 1, "label": "one"},
        {"client": FakeClient(2), "broker_num": 2, "label": "two"},
    ]

    metrics = cap.safe_publish(None, "{}", retain=False, topic_type="neighbors")
    assert [p[0] for p in published] == [1]
    assert metrics == {"attempted": 1, "succeeded": 1}


def test_safe_publish_neighbors_is_not_retained(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("PACKETCAPTURE_IATA", "SEA")
    monkeypatch.setenv("PACKETCAPTURE_MQTT1_NEIGHBORS", "true")
    cap = PacketCapture(enable_mqtt=True)
    cap.device_public_key = "ab" * 32
    cap.mqtt_connected = True

    seen = {}

    class FakeClient:
        def is_connected(self):
            return True

        def publish(self, topic, payload, qos=0, retain=False):
            seen.update({"topic": topic, "retain": retain, "qos": qos})
            return type("R", (), {"rc": 0})()

    cap.mqtt_clients = [{"client": FakeClient(), "broker_num": 1, "label": "one"}]
    cap.safe_publish(None, "{}", retain=False, topic_type="neighbors")
    assert seen["retain"] is False
    assert seen["topic"].endswith("/neighbors")


def test_neighbors_state_roundtrip_preserves_advert_time(tmp_path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("PACKETCAPTURE_DATA_DIR", str(tmp_path))
    cap = PacketCapture(enable_mqtt=False)

    import time as _time
    now = _time.time()
    cap.last_advert_time = now - 100
    cap._save_advert_state()
    cap.last_neighbors_publish = now - 50
    cap._save_neighbors_state()

    # Saving one key must not clobber the other: both live in advert_state.json.
    reloaded = PacketCapture(enable_mqtt=False)
    assert reloaded.last_advert_time == pytest.approx(now - 100)
    assert reloaded.last_neighbors_publish == pytest.approx(now - 50)


def test_neighbors_state_rejects_future_timestamp(tmp_path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("PACKETCAPTURE_DATA_DIR", str(tmp_path))
    cap = PacketCapture(enable_mqtt=False)
    import time as _time
    cap.last_neighbors_publish = _time.time() + 86400
    cap._save_neighbors_state()
    # A future stamp would suppress publishing indefinitely, so it is discarded.
    assert PacketCapture(enable_mqtt=False).last_neighbors_publish == 0


def test_neighbors_config_reads_env(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("PACKETCAPTURE_NEIGHBORS_INTERVAL_HOURS", "400")  # above the band
    monkeypatch.setenv("PACKETCAPTURE_NEIGHBORS_SCOPE_GAP", "3.5")
    monkeypatch.setenv("PACKETCAPTURE_NEIGHBORS_MAX", "8")
    monkeypatch.setenv("PACKETCAPTURE_NEIGHBORS_SELF_SCOPES", " DEN,APRS ")
    cap = PacketCapture(enable_mqtt=False)
    assert cap.neighbors_config.interval_hours == 336
    assert cap.neighbors_config.scope_gap == 3.5
    assert cap.neighbors_config.max_neighbors == 8
    assert cap.neighbors_config.self_scopes == "DEN,APRS"


def test_neighbors_commands_available_detection(capture: PacketCapture):
    import types as _types
    capture.meshcore = _types.SimpleNamespace(commands=_types.SimpleNamespace())
    assert capture.neighbors_commands_available() is False

    capture.meshcore = _types.SimpleNamespace(commands=_types.SimpleNamespace(
        send_node_discover_req=lambda *a, **k: None,
        req_regions_sync=lambda *a, **k: None,
    ))
    assert capture.neighbors_commands_available() is True


def test_neighbors_cycle_skips_when_no_broker_opted_in(capture: PacketCapture):
    capture.enable_mqtt = True
    capture.mqtt_connected = True
    capture.connected = True
    import types as _types
    capture.meshcore = _types.SimpleNamespace(is_connected=True, commands=_types.SimpleNamespace(
        send_node_discover_req=lambda *a, **k: None,
        req_regions_sync=lambda *a, **k: None,
    ))
    assert _run(capture.run_neighbors_cycle()) is False


def test_sort_uses_published_seconds_so_snr_breaks_ties():
    # Both publish heard_secs_ago = 0 at now=101.0, so SNR must decide rather
    # than the sub-second clock difference.
    weak_later = nb.NeighborEntry(pubkey="aa" * 32, snr=1.0, heard_at=100.9)
    strong_earlier = nb.NeighborEntry(pubkey="bb" * 32, snr=9.0, heard_at=100.1)
    ordered = nb.sort_entries([weak_later, strong_earlier], now=101.0)
    assert ordered == [strong_earlier, weak_later]


def test_published_order_is_monotonic_in_heard_secs_ago():
    """Ordering must match the field actually published, not the raw clock.

    Quantising differently from heard_secs_ago let the payload come out
    non-monotonic in its own sort key.
    """
    entries = [
        nb.NeighborEntry(pubkey="aa" * 32, snr=9.0, heard_at=100.00),
        nb.NeighborEntry(pubkey="bb" * 32, snr=1.0, heard_at=100.99),
    ]
    message, _ = nb.build_neighbors_message(
        "o", "id", "", entries, timestamp="T", now=101.5
    )
    ages = [e["heard_secs_ago"] for e in message["neighbors"]]
    assert ages == sorted(ages), f"published order not monotonic: {ages}"


def test_sort_still_prefers_a_genuinely_later_second():
    older_strong = nb.NeighborEntry(pubkey="aa" * 32, snr=20.0, heard_at=100.0)
    newer_weak = nb.NeighborEntry(pubkey="bb" * 32, snr=-5.0, heard_at=102.0)
    assert nb.sort_entries([older_strong, newer_weak]) == [newer_weak, older_strong]


# --------------------------------------------------------------------------
# Discovery against real EventDispatcher semantics
# --------------------------------------------------------------------------

def test_discover_collects_through_real_event_dispatcher():
    """Collection must work when callbacks are spawned as background tasks.

    The hand-rolled fake invokes the handler inline, which would hide a failure
    to yield control to the loop. This drives a dispatcher that behaves like the
    library's: queue the event, then run the callback as a separate task.
    """
    class SpawningDispatcher:
        def __init__(self):
            self._subs = {}
            self._tasks = []

        def subscribe(self, event_type, handler):
            self._subs[event_type] = handler
            return event_type

        def unsubscribe(self, sub):
            self._subs.pop(sub, None)

        def emit(self, event):
            handler = self._subs.get(event.type)
            if handler is not None:
                self._tasks.append(asyncio.create_task(handler(event)))

    class MC:
        def __init__(self):
            self.dispatcher = SpawningDispatcher()
            outer = self

            class Commands:
                async def send_node_discover_req(s, filter, prefix_only=True, tag=None, since=None):
                    th = tag.to_bytes(4, "little").hex()
                    for pk, snr in (("aa" * 32, 5.0), ("bb" * 32, 9.0)):
                        outer.dispatcher.emit(_FakeEvent(
                            "discover_response",
                            {"pubkey": pk, "SNR": snr, "node_type": 2, "tag": th},
                        ))
                    return _FakeEvent("OK", {"tag": tag})

            self.commands = Commands()

        def subscribe(self, et, handler):
            return self.dispatcher.subscribe(et, handler)

        def unsubscribe(self, sub):
            self.dispatcher.unsubscribe(sub)

    mc = MC()
    entries = _run(
        nb.discover_neighbors(mc, nb.NeighborsConfig(), None, _FakeLogger())
    )
    assert {e.pubkey for e in entries} == {"aa" * 32, "bb" * 32}


def test_discover_ignores_responses_arriving_after_the_window():
    """A straggler must not mutate entries already snapshotted and returned."""
    captured = {}

    class MC:
        def __init__(self):
            outer = self

            class Commands:
                async def send_node_discover_req(s, filter, prefix_only=True, tag=None, since=None):
                    th = tag.to_bytes(4, "little").hex()
                    await outer.handler(_FakeEvent(
                        "discover_response",
                        {"pubkey": "aa" * 32, "SNR": 5.0, "node_type": 2, "tag": th},
                    ))
                    captured["tag"] = th
                    return _FakeEvent("OK", {"tag": tag})

            self.commands = Commands()

        def subscribe(self, et, handler):
            self.handler = handler
            return "sub"

        def unsubscribe(self, sub):
            pass  # deliberately leave the handler reachable

    async def scenario():
        mc = MC()
        entries = await nb.discover_neighbors(mc, nb.NeighborsConfig(), None, _FakeLogger())
        # A late event for a pubkey ALREADY collected: without the latch this
        # mutates the very NeighborEntry we just returned. Asserting on a new
        # pubkey instead would prove nothing, since sort_entries returns a copy.
        await mc.handler(_FakeEvent(
            "discover_response",
            {"pubkey": "aa" * 32, "SNR": 30.0, "node_type": 2, "tag": captured["tag"]},
        ))
        return entries

    entries = _run(scenario())
    assert [e.pubkey for e in entries] == ["aa" * 32]
    assert entries[0].snr == 5.0, "a straggler mutated an already-returned entry"


# --------------------------------------------------------------------------
# Unroutable brokers must not trigger on-air work
# --------------------------------------------------------------------------

def test_neighbors_broker_nums_excludes_broker_with_unresolvable_topic(
    monkeypatch: pytest.MonkeyPatch,
):
    """Opted in but no IATA and no override: the topic can never resolve.

    Including it would spend a discover window plus one on-air scope request per
    neighbor every cycle and then throw the result away.
    """
    monkeypatch.setenv("PACKETCAPTURE_IATA", "LOC")  # the unconfigured default
    monkeypatch.setenv("PACKETCAPTURE_MQTT1_ENABLED", "true")
    monkeypatch.setenv("PACKETCAPTURE_MQTT1_NEIGHBORS", "true")
    cap = PacketCapture(enable_mqtt=False)
    cap.device_public_key = "ab" * 32

    assert cap.neighbors_broker_nums() == []

    logged = []
    cap.logger = type("L", (), {
        "warning": lambda _s, m: logged.append(m),
        "info": lambda _s, m: None,
        "debug": lambda _s, m: None,
        "error": lambda _s, m, **k: None,
    })()
    assert cap.neighbors_broker_nums(warn_unroutable=True) == []
    assert any("no neighbors topic could be resolved" in m for m in logged)


def test_neighbors_broker_nums_keeps_broker_with_explicit_topic(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setenv("PACKETCAPTURE_IATA", "LOC")
    monkeypatch.setenv("PACKETCAPTURE_MQTT1_ENABLED", "true")
    monkeypatch.setenv("PACKETCAPTURE_MQTT1_NEIGHBORS", "true")
    monkeypatch.setenv("PACKETCAPTURE_MQTT1_TOPIC_NEIGHBORS", "custom/n")
    cap = PacketCapture(enable_mqtt=False)
    cap.device_public_key = "ab" * 32
    assert cap.neighbors_broker_nums() == [1]


def test_broker_requires_iata_considers_neighbors_topic(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("PACKETCAPTURE_MQTT1_TOPIC_NEIGHBORS", "x/{IATA}/{PUBLIC_KEY}/neighbors")
    monkeypatch.setenv("PACKETCAPTURE_MQTT1_NEIGHBORS", "true")
    cap = PacketCapture(enable_mqtt=False)
    # For a broker that opted in, an IATA-templated neighbors topic must count,
    # or it silently publishes to the literal default.
    assert cap.broker_requires_iata(1) is True


def test_neighbors_topic_does_not_disable_a_broker_that_opted_out(
    monkeypatch: pytest.MonkeyPatch,
):
    """A global [topics] neighbors template must not disable unrelated brokers.

    broker_requires_iata() gates whether a broker connects at all, so counting
    NEIGHBORS unconditionally would stop a plain local broker from publishing
    packets and status just because a neighbors template exists somewhere.
    """
    monkeypatch.setenv("PACKETCAPTURE_TOPIC_NEIGHBORS", "meshcore/{IATA}/{PUBLIC_KEY}/neighbors")
    cap = PacketCapture(enable_mqtt=False)
    assert cap._broker_wants_neighbors(1) is False
    assert cap.broker_requires_iata(1) is False


# --------------------------------------------------------------------------
# Config validation floors
# --------------------------------------------------------------------------

def test_config_floors_reject_values_that_collect_nothing():
    cfg = nb.NeighborsConfig(discover_window=0.0, max_neighbors=0, cycle_timeout=0.0, scope_gap=-1)
    assert cfg.discover_window == nb.MIN_DISCOVER_WINDOW
    assert cfg.max_neighbors == 1
    assert cfg.cycle_timeout == nb.MIN_CYCLE_TIMEOUT
    assert cfg.scope_gap == 0.0


def test_out_of_band_interval_is_warned_not_silently_clamped(monkeypatch: pytest.MonkeyPatch):
    import logging
    monkeypatch.setenv("PACKETCAPTURE_NEIGHBORS_INTERVAL_HOURS", "1")
    warnings = []
    # The warning fires inside __init__, before an instance logger can be patched.
    monkeypatch.setattr(
        logging.Logger, "warning", lambda self, msg, *a, **k: warnings.append(str(msg))
    )
    cap = PacketCapture(enable_mqtt=False)
    assert cap.neighbors_config.interval_hours == 12
    assert any("outside the supported 12-336h range" in m for m in warnings)


# --------------------------------------------------------------------------
# run_neighbors_cycle happy path and scheduler
# --------------------------------------------------------------------------

class _CycleMeshCore:
    is_connected = True

    def __init__(self, scopes):
        self._contacts = {}
        outer = self

        class Commands:
            async def send_node_discover_req(s, filter, prefix_only=True, tag=None, since=None):
                th = tag.to_bytes(4, "little").hex()
                for pk in scopes:
                    await outer.handler(_FakeEvent(
                        "discover_response",
                        {"pubkey": pk, "SNR": 5.0, "node_type": 2, "tag": th},
                    ))
                return _FakeEvent("OK", {"tag": tag})

            async def req_regions_sync(s, pubkey, timeout=0, min_timeout=0):
                assert outer._contacts[pubkey]["out_path_len"] == 0
                return scopes[pubkey]

            async def get_default_flood_scope(s):
                return _FakeEvent("default_flood_scope", {"scope_name": "SEATTLE"})

        self.commands = Commands()

    @property
    def contacts(self):
        return self._contacts

    def subscribe(self, et, handler):
        self.handler = handler
        return "sub"

    def unsubscribe(self, sub):
        pass


def _cycle_capture(monkeypatch: pytest.MonkeyPatch, tmp_path, scopes):
    monkeypatch.setenv("PACKETCAPTURE_IATA", "SEA")
    monkeypatch.setenv("PACKETCAPTURE_MQTT1_ENABLED", "true")
    monkeypatch.setenv("PACKETCAPTURE_MQTT1_NEIGHBORS", "true")
    monkeypatch.setenv("PACKETCAPTURE_DATA_DIR", str(tmp_path))
    cap = PacketCapture(enable_mqtt=True)
    cap.connected = True
    cap.mqtt_connected = True
    cap.device_public_key = "ff" * 32
    cap.device_name = "MeshCore-CYCLE"
    cap.meshcore = _CycleMeshCore(scopes)
    return cap


def test_run_neighbors_cycle_publishes_and_persists(monkeypatch: pytest.MonkeyPatch, tmp_path):
    scopes = {"aa" * 32: "DEN,APRS", "bb" * 32: None}
    cap = _cycle_capture(monkeypatch, tmp_path, scopes)

    calls = []
    cap.safe_publish = lambda topic, payload, retain=False, **kw: (
        calls.append({"payload": payload, "retain": retain, "kw": kw})
        or {"attempted": 1, "succeeded": 1}
    )

    assert _run(cap.run_neighbors_cycle()) is True
    assert len(calls) == 1
    assert calls[0]["kw"]["topic_type"] == "neighbors"
    assert calls[0]["retain"] is False

    msg = json.loads(calls[0]["payload"])
    assert msg["origin"] == "MeshCore-CYCLE"
    assert msg["origin_id"] == ("ff" * 32).upper()
    assert msg["self"]["scopes"] == "SEATTLE"
    statuses = {e["pubkey"].lower(): e["status"] for e in msg["neighbors"]}
    assert statuses == {"aa" * 32: "responded", "bb" * 32: "timeout"}

    # Contact cache clean and the schedule advanced.
    assert cap.meshcore.contacts == {}
    assert cap.last_neighbors_publish > 0
    assert PacketCapture(enable_mqtt=False).last_neighbors_publish == pytest.approx(
        cap.last_neighbors_publish
    )


def test_run_neighbors_cycle_warns_when_no_broker_accepts(
    monkeypatch: pytest.MonkeyPatch, tmp_path
):
    cap = _cycle_capture(monkeypatch, tmp_path, {"aa" * 32: "DEN"})
    cap.safe_publish = lambda *a, **k: {"attempted": 0, "succeeded": 0}
    logged = []
    monkeypatch.setattr(cap.logger, "warning", lambda m: logged.append(m))

    assert _run(cap.run_neighbors_cycle()) is False
    # Discovery cost airtime, so a silent no-op must not look like success.
    assert any("no broker accepted the publish" in m for m in logged)


def test_run_neighbors_cycle_warns_once_on_repeated_discover_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path
):
    cap = _cycle_capture(monkeypatch, tmp_path, {})

    async def failing(*a, **k):
        return _FakeEvent("ERROR", {"reason": "unsupported"})

    cap.meshcore.commands.send_node_discover_req = failing
    warnings = []
    monkeypatch.setattr(cap.logger, "warning", lambda m: warnings.append(m))

    for _ in range(4):
        assert _run(cap.run_neighbors_cycle()) is False

    # An unsupported build fails every cycle; ~288 warnings/day is noise.
    assert len(warnings) == 1
    assert cap.neighbors_discover_failures == 4


def test_neighbors_scheduler_waits_then_runs_then_exits(
    monkeypatch: pytest.MonkeyPatch, tmp_path
):
    cap = _cycle_capture(monkeypatch, tmp_path, {})
    cap.last_neighbors_publish = 0  # due immediately
    ran = []

    async def fake_cycle():
        ran.append(1)
        cap.last_neighbors_publish = 12345.0  # stamp, as the real one does
        cap.should_exit = True
        return True

    cap.run_neighbors_cycle = fake_cycle
    waits = []

    async def fake_wait(seconds):
        waits.append(seconds)
        return cap.should_exit

    cap.wait_with_shutdown = fake_wait
    _run(cap.neighbors_scheduler())
    assert ran == [1]


def test_neighbors_scheduler_sleeps_when_not_yet_due(
    monkeypatch: pytest.MonkeyPatch, tmp_path
):
    import time as _time
    cap = _cycle_capture(monkeypatch, tmp_path, {})
    cap.last_neighbors_publish = _time.time()  # just published
    ran = []
    cap.run_neighbors_cycle = lambda: ran.append(1)

    waits = []

    async def fake_wait(seconds):
        waits.append(seconds)
        cap.should_exit = True   # break out after the first sleep
        return True

    cap.wait_with_shutdown = fake_wait
    _run(cap.neighbors_scheduler())

    assert ran == []
    # Sleeps the remaining interval, not a busy-loop tick.
    assert waits and waits[0] > cap.neighbors_config.interval_seconds - 60


def test_neighbors_scheduler_backs_off_when_cycle_cannot_run(
    monkeypatch: pytest.MonkeyPatch, tmp_path
):
    cap = _cycle_capture(monkeypatch, tmp_path, {})
    cap.last_neighbors_publish = 0  # due
    attempts = []

    async def bailing_cycle():
        attempts.append(1)   # returns without stamping, as early exits do
        return False

    cap.run_neighbors_cycle = bailing_cycle
    waits = []

    async def fake_wait(seconds):
        waits.append(seconds)
        cap.should_exit = True
        return True

    cap.wait_with_shutdown = fake_wait
    _run(cap.neighbors_scheduler())

    # One attempt, then a bounded backoff instead of spinning on the due check.
    assert attempts == [1]
    assert waits == [300]


def test_neighbors_scheduler_survives_cycle_exception(
    monkeypatch: pytest.MonkeyPatch, tmp_path
):
    cap = _cycle_capture(monkeypatch, tmp_path, {})
    cap.last_neighbors_publish = 0

    async def boom():
        raise RuntimeError("device vanished mid-cycle")

    cap.run_neighbors_cycle = boom
    waits = []

    async def fake_wait(seconds):
        waits.append(seconds)
        cap.should_exit = True
        return True

    cap.wait_with_shutdown = fake_wait
    _run(cap.neighbors_scheduler())   # must not propagate
    assert waits == [300]


# --------------------------------------------------------------------------
# Manual trigger (--neighbors-now)
# --------------------------------------------------------------------------

def test_manual_trigger_defaults_off(capture: PacketCapture):
    assert capture.neighbors_run_now is False
    assert capture.neighbors_exit_after_run is False


def test_manual_trigger_runs_cycle_and_can_exit(monkeypatch: pytest.MonkeyPatch, tmp_path):
    cap = _cycle_capture(monkeypatch, tmp_path, {})
    cap.neighbors_run_now = True
    cap.neighbors_exit_after_run = True
    ran = []

    async def fake_cycle():
        ran.append(1)
        return True

    cap.run_neighbors_cycle = fake_cycle
    _run(_drive_manual_cycle(cap))

    assert ran == [1]
    assert cap.should_exit is True
    # --neighbors-exit must not leave a scheduler running behind it.
    assert cap.neighbors_task is None


def test_manual_trigger_without_exit_starts_scheduler(
    monkeypatch: pytest.MonkeyPatch, tmp_path
):
    import time as _time
    cap = _cycle_capture(monkeypatch, tmp_path, {})
    cap.neighbors_run_now = True
    ran = []

    async def fake_cycle():
        ran.append(1)
        cap.last_neighbors_publish = _time.time()  # the real cycle stamps on success
        return True

    cap.run_neighbors_cycle = fake_cycle

    async def scenario():
        await _drive_manual_cycle(cap)
        # Let the scheduler take its first pass; a just-stamped run is not due,
        # so the manual cycle must not be immediately repeated.
        await asyncio.sleep(0)
        return cap.neighbors_task

    task = _run(scenario())

    assert ran == [1]
    assert cap.should_exit is False
    assert task is not None


def test_manual_trigger_errors_when_no_broker_opted_in(
    monkeypatch: pytest.MonkeyPatch, tmp_path
):
    monkeypatch.setenv("PACKETCAPTURE_IATA", "SEA")
    monkeypatch.setenv("PACKETCAPTURE_DATA_DIR", str(tmp_path))
    cap = PacketCapture(enable_mqtt=True)
    cap.device_public_key = "ff" * 32
    cap.neighbors_run_now = True
    ran = []
    cap.run_neighbors_cycle = lambda: ran.append(1)
    errors = []
    monkeypatch.setattr(cap.logger, "error", lambda m, **k: errors.append(m))

    _run(_drive_manual_cycle(cap))

    assert ran == []
    assert any("no enabled broker has neighbors" in m for m in errors)


def test_manual_trigger_survives_cycle_exception(
    monkeypatch: pytest.MonkeyPatch, tmp_path
):
    cap = _cycle_capture(monkeypatch, tmp_path, {})
    cap.neighbors_run_now = True
    cap.neighbors_exit_after_run = True

    async def boom():
        raise RuntimeError("radio unplugged")

    cap.run_neighbors_cycle = boom
    errors = []
    monkeypatch.setattr(cap.logger, "error", lambda m, **k: errors.append(m))

    _run(_drive_manual_cycle(cap))   # must not propagate

    assert any("manual cycle failed" in m for m in errors)
    # Still honours --neighbors-exit so a scripted test run terminates.
    assert cap.should_exit is True


# --------------------------------------------------------------------------
# Failure modes found on real hardware
# --------------------------------------------------------------------------

def test_discover_bounded_when_send_never_returns():
    """A stalled link must not hang the cycle (and, for --neighbors-now, startup).

    The BLE/serial write inside send() can block far longer than the library's
    own response timeout; observed as a >3 minute stall on real hardware.
    """
    class HangingMeshCore:
        def __init__(self):
            class Commands:
                async def send_node_discover_req(s, *a, **k):
                    # A never-resolving future, not sleep(): the autouse fixture
                    # patches asyncio.sleep module-wide, which would make a
                    # sleep-based fake return instantly.
                    await asyncio.Event().wait()

            self.commands = Commands()
            self.unsubscribed = []

        def subscribe(self, et, handler):
            return "sub"

        def unsubscribe(self, sub):
            self.unsubscribed.append(sub)

    mc = HangingMeshCore()
    cfg = nb.NeighborsConfig(command_timeout=0.05)
    logger = _FakeLogger()

    async def scenario():
        # Real sleep so wait_for can actually fire.
        return await nb.discover_neighbors(mc, cfg, None, logger)

    result = asyncio.run(scenario())

    assert result is None
    assert any("did not complete within" in m for m in logger.messages)
    # Must still unsubscribe on the timeout path.
    assert mc.unsubscribed == ["sub"]


def test_discover_aborts_when_session_reset_midwindow():
    """A reconnect clears every subscription, so the handler stops firing.

    Publishing the (now empty) collection would assert the mesh has no
    neighbours when in fact we simply stopped listening.
    """
    mc = _DiscoverMeshCore([_resp("aa" * 32, 5.0)])
    logger = _FakeLogger()

    result = _run(
        nb.discover_neighbors(
            mc, nb.NeighborsConfig(), None, logger, still_valid=lambda: False
        )
    )

    assert result is None
    assert any("session was reset" in m for m in logger.messages)


def test_discover_proceeds_while_session_intact():
    mc = _DiscoverMeshCore([_resp("aa" * 32, 5.0)])
    entries = _run(
        nb.discover_neighbors(
            mc, nb.NeighborsConfig(), None, _FakeLogger(), still_valid=lambda: True
        )
    )
    assert [e.pubkey for e in entries] == ["aa" * 32]


def test_cycle_discards_result_when_session_reset_during_scopes(
    monkeypatch: pytest.MonkeyPatch, tmp_path
):
    """Scopes gathered against a dead session must not be published."""
    cap = _cycle_capture(monkeypatch, tmp_path, {"aa" * 32: "DEN"})
    published = []
    cap.safe_publish = lambda *a, **k: published.append(1) or {"attempted": 1, "succeeded": 1}

    original_collect = nb.collect_scopes

    async def collect_then_reconnect(*a, **k):
        await original_collect(*a, **k)
        cap.meshcore = _CycleMeshCore({})   # simulate reconnect swapping the object

    monkeypatch.setattr(pc_mod, "collect_scopes", collect_then_reconnect)

    assert _run(cap.run_neighbors_cycle()) is False
    assert published == []


def test_command_timeout_is_configurable(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("PACKETCAPTURE_NEIGHBORS_COMMAND_TIMEOUT", "7.5")
    cap = PacketCapture(enable_mqtt=False)
    assert cap.neighbors_config.command_timeout == 7.5


def test_every_neighbors_config_field_is_reachable_from_toml():
    """Guard against re-introducing dead config (as neighbors_retry_limit was).

    Every NeighborsConfig field must survive the TOML -> env -> PacketCapture
    round trip, or it is a knob documented in config.toml.example that silently
    does nothing.
    """
    import dataclasses
    from meshcore_packet_capture import config_loader as cl

    toml_name = {"max_neighbors": "neighbors_max"}
    capture = {}
    for field in dataclasses.fields(nb.NeighborsConfig):
        key = toml_name.get(field.name, f"neighbors_{field.name}")
        capture[key] = "DEN" if field.name == "self_scopes" else 13

    env = cl.flatten_config_to_env_dict({"capture": capture})
    missing = [k for k in capture if not any(
        e.startswith("PACKETCAPTURE_NEIGHBORS_") and env[e] in ("13", "DEN")
        and e.endswith(k.replace("neighbors_", "").upper()) for e in env)]
    assert not missing, f"not settable from config: {missing}"


# --------------------------------------------------------------------------
# Device-command serialisation (concurrent BLE writes drop the link)
# --------------------------------------------------------------------------

def test_collect_scopes_holds_lock_per_request_not_whole_pass():
    """The lock must be released between neighbours.

    A scope pass can span minutes; holding the lock throughout would stall the
    app's status publishes and health checks for its whole duration.
    """
    entries = [_entry("a", 1.0, 100.0), _entry("b", 1.0, 90.0)]
    mc = _FakeMeshCore({e.pubkey: "S" for e in entries})
    lock = asyncio.Lock()
    held = []

    original = mc.commands.req_regions_sync

    async def watching(pubkey, timeout=0, min_timeout=0):
        held.append(lock.locked())
        return await original(pubkey, timeout=timeout, min_timeout=min_timeout)

    mc.commands.req_regions_sync = watching

    async def scenario():
        await nb.collect_scopes(
            mc, entries, nb.NeighborsConfig(scope_gap=0.0), _FakeLogger(),
            command_lock=lock,
        )
        return lock.locked()

    still_locked = asyncio.run(scenario())
    assert held == [True, True]      # held during each request
    assert still_locked is False     # released afterwards


def test_discover_holds_lock_for_the_send():
    mc = _DiscoverMeshCore([])
    lock = asyncio.Lock()
    seen = []
    original = mc.commands.send_node_discover_req

    async def watching(*a, **k):
        seen.append(lock.locked())
        return await original(*a, **k)

    mc.commands.send_node_discover_req = watching
    _run(nb.discover_neighbors(mc, nb.NeighborsConfig(), None, _FakeLogger(),
                               command_lock=lock))
    assert seen == [True]
    assert lock.locked() is False


def test_neighbors_functions_work_without_a_lock():
    """command_lock is optional; omitting it must not break anything."""
    entry = _entry("a", 1.0, 100.0)
    mc = _FakeMeshCore({entry.pubkey: "DEN"})
    _run(nb.collect_scopes(mc, [entry], nb.NeighborsConfig(scope_gap=0.0), _FakeLogger()))
    assert entry.status == nb.STATUS_RESPONDED


# --------------------------------------------------------------------------
# Device lock: neighbors-side usage
# --------------------------------------------------------------------------

def test_scope_request_is_bounded_while_holding_the_lock(monkeypatch: pytest.MonkeyPatch):
    """An unbounded scope request would wedge the shared lock (and the watchdog)."""
    entry = _entry("a", 1.0, 100.0)
    lock = pc_mod.TaskReentrantLock()

    class Stalling:
        calls = []

        async def req_regions_sync(self, pubkey, timeout=0, min_timeout=0):
            self.calls.append(pubkey)
            await asyncio.Event().wait()          # never returns

    class MC:
        def __init__(self):
            self.commands = Stalling()
            self._contacts = {}

        @property
        def contacts(self):
            return self._contacts

    mc = MC()
    # Shrink the MSG_SENT allowance so the real budget is exercised quickly.
    monkeypatch.setattr(nb, "LIBRARY_MSG_SENT_TIMEOUT", 0.05)
    cfg = nb.NeighborsConfig(scope_gap=0.0, scope_min_timeout=0.05, command_timeout=1.0)
    logger = _FakeLogger()

    async def scenario():
        await asyncio.wait_for(
            nb.collect_scopes(mc, [entry], cfg, logger, command_lock=lock), timeout=60.0
        )
        return lock.locked()

    still_locked = asyncio.run(scenario())
    assert entry.status == nb.STATUS_SEND_FAILED
    assert still_locked is False
    assert any("may be stalled" in m for m in logger.messages)


def test_command_timeout_zero_is_floored():
    """0 reads as 'no cap' beside scope_timeout, but wait_for(0) fails instantly."""
    assert nb.NeighborsConfig(command_timeout=0).command_timeout == nb.MIN_COMMAND_TIMEOUT
    assert nb.NeighborsConfig(command_timeout=-5).command_timeout == nb.MIN_COMMAND_TIMEOUT


def test_manual_cycle_is_bounded_by_its_budget(monkeypatch: pytest.MonkeyPatch, tmp_path):
    """--neighbors-now runs inline before the main loop; an unbounded stall
    there hangs startup outright (observed on hardware before this bound)."""
    cap = _cycle_capture(monkeypatch, tmp_path, {})
    cap.neighbors_run_now = True
    cap.neighbors_exit_after_run = True
    # Every term feeds the budget, so shrink the floors too or this test would
    # have to wait out the real ~18s minimum.
    monkeypatch.setattr(nb, "MIN_DISCOVER_WINDOW", 0.01)
    monkeypatch.setattr(nb, "MIN_CYCLE_TIMEOUT", 0.01)
    monkeypatch.setattr(nb, "MIN_COMMAND_TIMEOUT", 0.01)
    monkeypatch.setattr(nb, "LIBRARY_MSG_SENT_TIMEOUT", 0.01)
    cap.neighbors_config = nb.NeighborsConfig(
        discover_window=0, command_timeout=0, cycle_timeout=0,
        scope_min_timeout=0.01, scope_gap=0,
    )

    async def hangs():
        await asyncio.Event().wait()

    cap.run_neighbors_cycle = hangs
    errors = []
    monkeypatch.setattr(cap.logger, "error", lambda m, **k: errors.append(m))

    _run(asyncio.wait_for(cap.run_manual_neighbors_cycle(), timeout=90))

    assert any("was abandoned" in m for m in errors)
    assert cap.should_exit is True     # --neighbors-exit still honoured


def test_cycle_truncates_to_max_neighbors(monkeypatch: pytest.MonkeyPatch, tmp_path):
    """Without the cap a large mesh would be queried without bound."""
    scopes = {f"{i:02x}" * 32: "DEN" for i in range(6)}
    cap = _cycle_capture(monkeypatch, tmp_path, scopes)
    cap.neighbors_config = nb.NeighborsConfig(
        discover_window=0, scope_gap=0, max_neighbors=2
    )
    published = []
    cap.safe_publish = lambda topic, payload, retain=False, **kw: (
        published.append(json.loads(payload)) or {"attempted": 1, "succeeded": 1}
    )
    _run(cap.run_neighbors_cycle())
    assert len(published[0]["neighbors"]) == 2


def test_collect_scopes_paces_requests_with_the_gap():
    """scope_gap is the anti-collision mechanism from firmware commit aba571ed."""
    entries = [_entry("a", 1.0, 100.0), _entry("b", 1.0, 90.0), _entry("c", 1.0, 80.0)]
    mc = _FakeMeshCore({e.pubkey: "S" for e in entries})
    slept = []

    async def record(seconds):
        slept.append(seconds)

    async def scenario():
        import meshcore_packet_capture.neighbors as mod
        real = mod.asyncio.sleep
        mod.asyncio.sleep = record
        try:
            await nb.collect_scopes(
                mc, entries, nb.NeighborsConfig(scope_gap=2.0), _FakeLogger()
            )
        finally:
            mod.asyncio.sleep = real

    asyncio.run(scenario())
    # One gap between each pair, none before the first.
    assert slept == [2.0, 2.0]


def test_neighbors_config_env_wiring_reaches_the_instance(monkeypatch: pytest.MonkeyPatch):
    """TOML->env is not enough; __init__ must actually read each key."""
    for key, val in [
        ("NEIGHBORS_DISCOVER_WINDOW", "31"), ("NEIGHBORS_COMMAND_TIMEOUT", "32"),
        ("NEIGHBORS_SCOPE_TIMEOUT", "33"), ("NEIGHBORS_SCOPE_MIN_TIMEOUT", "34"),
        ("NEIGHBORS_SCOPE_GAP", "35"), ("NEIGHBORS_CYCLE_TIMEOUT", "36"),
        ("NEIGHBORS_MAX", "37"),
    ]:
        monkeypatch.setenv(f"PACKETCAPTURE_{key}", val)
    cfg = PacketCapture(enable_mqtt=False).neighbors_config
    assert cfg.discover_window == 31
    assert cfg.command_timeout == 32
    assert cfg.scope_timeout == 33
    assert cfg.scope_min_timeout == 34
    assert cfg.scope_gap == 35
    assert cfg.cycle_timeout == 36
    assert cfg.max_neighbors == 37


def test_cycle_passes_the_device_lock_to_every_stage(monkeypatch: pytest.MonkeyPatch, tmp_path):
    """The lock wiring is the whole hardware-driven fix; assert it is threaded."""
    cap = _cycle_capture(monkeypatch, tmp_path, {"aa" * 32: "DEN"})
    seen = {}

    async def fake_discover(mc, cfg, pk, logger, **kw):
        seen["discover"] = kw.get("command_lock")
        return [_entry("a", 1.0, 100.0)]

    async def fake_collect(mc, entries, cfg, logger, **kw):
        seen["collect"] = kw.get("command_lock")

    async def fake_self_scopes(mc, cfg, logger, command_lock=None):
        seen["self_scopes"] = command_lock
        return ""

    monkeypatch.setattr(pc_mod, "discover_neighbors", fake_discover)
    monkeypatch.setattr(pc_mod, "collect_scopes", fake_collect)
    monkeypatch.setattr(pc_mod, "fetch_self_scopes", fake_self_scopes)
    cap.safe_publish = lambda *a, **k: {"attempted": 1, "succeeded": 1}

    _run(cap.run_neighbors_cycle())

    assert seen["discover"] is cap.device_command_lock
    assert seen["collect"] is cap.device_command_lock
    assert seen["self_scopes"] is cap.device_command_lock


async def _drive_manual_cycle(cap):
    """Invoke the real production path, then the real scheduler launch."""
    await cap.run_manual_neighbors_cycle()
    if (not cap.should_exit and cap.enable_mqtt
            and cap.neighbors_broker_nums(warn_unroutable=True)):
        cap.neighbors_task = asyncio.create_task(cap.neighbors_scheduler())


def test_truncated_flag_set_by_payload_budget():
    entries = [
        nb.NeighborEntry(pubkey=f"{i:02x}" * 32, snr=0.0, heard_at=float(i), scopes="X" * 40)
        for i in range(40)
    ]
    message, dropped = nb.build_neighbors_message(
        "o", "id", "", entries, timestamp="T", now=100.0, budget=1024
    )
    assert dropped > 0
    assert message["truncated"] is True
    assert message["queried_neighbors"] == 40
    assert len(message["neighbors"]) == 40 - dropped


def test_truncated_flag_set_by_max_neighbors_cap():
    """total_neighbors reports the pre-cap count, so consumers can see the cap."""
    entries = [nb.NeighborEntry(pubkey="11" * 32, snr=1.0, heard_at=1.0)]
    message, dropped = nb.build_neighbors_message(
        "o", "id", "", entries, timestamp="T", now=1.0, total_neighbors=9
    )
    assert dropped == 0
    assert message["total_neighbors"] == 9
    assert message["queried_neighbors"] == 1
    assert message["truncated"] is True
