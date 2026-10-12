#!/usr/bin/env python3
"""Zero-hop neighbor discovery and scope collection for the MQTT neighbors topic.

Port of the observer firmware's WITH_MQTT_NEIGHBORS feature (see
examples/simple_repeater/MyMesh.cpp). Two stages per cycle:

1. A zero-hop node-discover request; repeaters answer with their pubkey and the
   SNR we heard them at. Responses are collected for a fixed window.
2. One anon-regions request per discovered neighbor, yielding that neighbor's
   scope names.

Both requests are issued through meshcore_py (``send_node_discover_req`` and
``req_regions_sync``); nothing here re-encodes packets. Stage 2 requires
meshcore >= 2.3.8, where ``send_anon_req`` will send to a destination that is
not already a known contact. Earlier releases refused such a request
client-side, and this module used to work around that by injecting a synthetic
contact into the library's cache for the duration of each query.

Stage 2 must reach the neighbour by a *direct* route. The repeater gates the
REGIONS request behind isRouteDirect() and silently drops anything that arrives
flooded, so a query routed any other way is indistinguishable from a dead
neighbour at this layer -- the send still reports MSG_SENT and the reply simply
never comes. ``send_anon_req`` only arranges a direct route for a destination it
finds in the library's contact cache, so this module loads that cache and pins
each neighbour to a zero-hop path for the duration of its query (see
``_load_contacts`` and ``_direct_route``).

Stage 2 is deliberately paced. The firmware originally fired every request at
once and the responses collided, so it moved to one request in flight at a time
(firmware commit aba571ed). ``req_regions_sync`` already gives us that — it
awaits the response under a lock — so this module supplies the rest of that
strategy: sort by usefulness *before* querying, let the device's own airtime
estimate set each timeout, and leave a settle gap between requests.
"""

from __future__ import annotations

import asyncio
import json
import random
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional

from meshcore import EventType

# ADV_TYPE_REPEATER (enums.AdvertFlags.ADV_TYPE_REPEATER). The firmware discovers
# repeaters only; the filter is a bitmask over advert types.
ADV_TYPE_REPEATER = 0x02
DISCOVER_FILTER_REPEATER = 1 << ADV_TYPE_REPEATER

# Matches MQTTBridge::NEIGHBORS_JSON_BUFFER_SIZE. Entries past this budget are
# dropped from the tail so the payload stays within the firmware's contract.
NEIGHBORS_JSON_BUDGET = 10240

@asynccontextmanager
async def _maybe_lock(lock):
    """Hold ``lock`` if one was supplied, otherwise do nothing.

    Device commands must not overlap: a command is a write plus a wait for its
    reply, and meshcore_py serialises neither, so concurrent commands awaiting
    the same event type can take each other's response. The caller owns the lock
    so neighbors requests serialise against the app's other device traffic
    (status publishes, stats, health checks), not just against each other.
    """
    if lock is None:
        yield
    else:
        async with lock:
            yield


STATUS_RESPONDED = "responded"
STATUS_TIMEOUT = "timeout"
STATUS_SEND_FAILED = "send_failed"

# Firmware interval band (MQTTPrefsStorage.h).
MIN_INTERVAL_HOURS = 12
MAX_INTERVAL_HOURS = 336
DEFAULT_INTERVAL_HOURS = 24

# Floors that keep a misconfiguration from producing an empty snapshot forever.
# Repeaters answer a discover request after a randomised delay, so a very short
# window collects nothing at all.
MIN_DISCOVER_WINDOW = 5.0
MIN_CYCLE_TIMEOUT = 10.0
MIN_COMMAND_TIMEOUT = 1.0

# meshcore_py's CommandHandlerBase.DEFAULT_TIMEOUT: how long req_regions_sync
# waits for MSG_SENT before it even begins waiting for the response.
LIBRARY_MSG_SENT_TIMEOUT = 15.0


def clamp_interval_hours(hours: int) -> int:
    """Clamp to the firmware's 12-336h band, falling back to the 24h default."""
    if hours <= 0:
        return DEFAULT_INTERVAL_HOURS
    return max(MIN_INTERVAL_HOURS, min(MAX_INTERVAL_HOURS, hours))


@dataclass
class NeighborsConfig:
    """Tuning for one neighbors cycle. Defaults mirror the firmware."""

    interval_hours: int = DEFAULT_INTERVAL_HOURS
    discover_window: float = 60.0     # stage 1 collection window
    command_timeout: float = 20.0     # cap on the discover request itself
    scope_timeout: float = 0.0        # 0 = let the device suggest it
    scope_min_timeout: float = 8.0    # floor under the suggested timeout
    scope_gap: float = 2.0            # settle delay between scope requests
    cycle_timeout: float = 600.0      # overall budget for the scope pass
    max_neighbors: int = 32
    self_scopes: str = ""             # explicit override; "" = ask the device

    def __post_init__(self):
        # Values that would silently produce a permanently empty snapshot get a
        # floor rather than being honoured: a 0s discover window collects nothing,
        # and max_neighbors = 0 queries nobody.
        self.interval_hours = clamp_interval_hours(self.interval_hours)
        if self.discover_window < MIN_DISCOVER_WINDOW:
            self.discover_window = MIN_DISCOVER_WINDOW
        if self.max_neighbors < 1:
            self.max_neighbors = 1
        if self.cycle_timeout < MIN_CYCLE_TIMEOUT:
            self.cycle_timeout = MIN_CYCLE_TIMEOUT
        if self.scope_gap < 0:
            self.scope_gap = 0.0
        # wait_for(timeout=0) raises immediately, so 0 here would break every
        # cycle forever -- and it reads as "no cap" by analogy with scope_timeout.
        if self.command_timeout < MIN_COMMAND_TIMEOUT:
            self.command_timeout = MIN_COMMAND_TIMEOUT

    @property
    def scope_request_budget(self) -> float:
        """Hard ceiling on one scope request, covering the lock it holds.

        req_regions_sync waits for MSG_SENT (the library default, 15s) and then
        for the response, so the budget has to exceed both or healthy requests
        would be cut off.
        """
        wait = self.scope_timeout if self.scope_timeout > 0 else self.scope_min_timeout
        return LIBRARY_MSG_SENT_TIMEOUT + max(wait, self.scope_min_timeout) + self.command_timeout

    @property
    def interval_seconds(self) -> float:
        return self.interval_hours * 3600.0


@dataclass
class NeighborEntry:
    """One discovered neighbor. Snapshotted so later table changes can't alter it."""

    pubkey: str
    snr: float
    heard_at: float                   # monotonic-ish wall clock of the response
    scopes: str = ""
    status: str = STATUS_TIMEOUT

    def heard_secs_ago(self, now: Optional[float] = None) -> int:
        now = time.time() if now is None else now
        return max(0, int(now - self.heard_at))


def sort_key(entry: NeighborEntry, now: Optional[float] = None) -> tuple:
    """Firmware ordering: most recently heard, then stronger SNR, then pubkey.

    Mirrors neighborPublishEntryComesBefore() and the pre-query sort added in
    firmware commit aba571ed, so query order and publish order agree — a
    truncated cycle still covers the most useful neighbors.

    Recency is compared as the published heard_secs_ago, ascending -- the exact
    value the firmware's comparator uses. Sorting on the raw float clock instead
    would quantise differently from the field we publish, so the output could be
    non-monotonic in heard_secs_ago, and SNR would never break a tie: the most
    recent response would always win outright. That matters because this order
    decides which entries survive the payload budget.
    """
    return (entry.heard_secs_ago(now), -entry.snr, entry.pubkey)


def sort_entries(entries: list[NeighborEntry],
                 now: Optional[float] = None) -> list[NeighborEntry]:
    # One `now` for the whole sort, and the same one the payload uses, so the
    # published heard_secs_ago values are ordered exactly as sorted.
    now = time.time() if now is None else now
    return sorted(entries, key=lambda e: sort_key(e, now))


async def discover_neighbors(
    meshcore,
    cfg: NeighborsConfig,
    self_pubkey: Optional[str],
    logger,
    *,
    debug: bool = False,
    still_valid=None,
    command_lock=None,
) -> Optional[list[NeighborEntry]]:
    """Stage 1: zero-hop node-discover, collecting responses for the window.

    Returns the discovered entries (possibly empty), or None if the request
    could not be sent or the session was invalidated mid-window.

    ``still_valid`` is an optional predicate that must keep returning True for
    the collected data to mean anything. A reconnect part-way through the window
    tears down every event subscription (the app clears them wholesale), so our
    response handler silently stops firing -- without this check the cycle would
    happily publish "0 neighbours" as though the mesh were empty.
    """
    collected: dict[str, NeighborEntry] = {}
    self_key = (self_pubkey or "").lower()
    # EventDispatcher spawns async callbacks as background tasks, so an event
    # already dequeued can still reach the handler after unsubscribe() returns.
    # This latch keeps a straggler from mutating entries we have already returned.
    closed = False

    # Generate the tag ourselves rather than letting the library pick one, so it is
    # known *before* the subscription goes live. Otherwise a response arriving
    # between subscribe and send-completion would be accepted with no tag check --
    # which is how a stale round, or another client's round, could leak in.
    # DISCOVER_RESPONSE reports the tag as little-endian hex.
    tag = random.randint(1, 0xFFFFFFFF)
    expected_tag = tag.to_bytes(4, "little").hex()

    async def on_discover_response(event):
        if closed:
            return
        payload = getattr(event, "payload", None) or {}
        pubkey = str(payload.get("pubkey", "")).lower()
        # Full 32-byte pubkeys only; the firmware rejects short prefixes too.
        if len(pubkey) != 64:
            return
        if self_key and pubkey == self_key:
            return
        if payload.get("node_type") != ADV_TYPE_REPEATER:
            return
        if str(payload.get("tag", "")).lower() != expected_tag:
            return

        snr = float(payload.get("SNR", 0) or 0)
        existing = collected.get(pubkey)
        if existing is None:
            collected[pubkey] = NeighborEntry(pubkey=pubkey, snr=snr, heard_at=time.time())
        else:
            # Same neighbor heard again (repeaters delay responses randomly).
            # putNeighbour() refreshes the timestamp on every response, so do
            # that unconditionally; keep the strongest SNR seen.
            existing.heard_at = time.time()
            existing.snr = max(existing.snr, snr)

    # Subscribe per-run rather than at startup: cleanup_event_subscriptions()
    # drops every subscription on reconnect, and this handler is only wanted for
    # the duration of the window.
    subscription = meshcore.subscribe(EventType.DISCOVER_RESPONSE, on_discover_response)
    try:
        # Bounded: on a stalled link the underlying BLE/serial write can block far
        # longer than the library's own response timeout, and an unbounded wait
        # here stalls the whole cycle (and, for a one-shot run, startup).
        try:
            async with _maybe_lock(command_lock):
                result = await asyncio.wait_for(
                    meshcore.commands.send_node_discover_req(
                        DISCOVER_FILTER_REPEATER,
                        prefix_only=False,   # we need the full 32-byte pubkey
                        tag=tag,
                    ),
                    timeout=cfg.command_timeout,
                )
        except asyncio.TimeoutError:
            logger.warning(
                f"Neighbors: node-discover request did not complete within "
                f"{cfg.command_timeout:.0f}s, abandoning this cycle"
            )
            return None

        if result is None or result.type == EventType.ERROR:
            reason = ""
            if result is not None:
                reason = (getattr(result, "payload", None) or {}).get("reason", "")
            # Logged at debug: the caller owns the user-facing message, because on a
            # build that lacks the command this fails every cycle forever.
            logger.debug(
                f"Neighbors: node-discover request failed{f' ({reason})' if reason else ''}"
            )
            return None

        if debug:
            logger.debug(
                f"Neighbors: node-discover sent (tag={expected_tag}), "
                f"collecting for {cfg.discover_window:.0f}s"
            )
        await asyncio.sleep(cfg.discover_window)

        if still_valid is not None and not still_valid():
            logger.warning(
                "Neighbors: device session was reset during the discovery window "
                "(event subscriptions are torn down on reconnect), abandoning this cycle"
            )
            return None
    finally:
        closed = True
        try:
            meshcore.unsubscribe(subscription)
        except Exception as exc:
            logger.debug(f"Neighbors: error unsubscribing discover handler: {exc}")

    return sort_entries(list(collected.values()))


def _event_error_reason(result) -> Optional[str]:
    """The failure reason if ``result`` is an Event(ERROR), else None.

    Several meshcore commands report failure by *returning* Event(ERROR) rather
    than raising -- get_contacts and change_contact_path both do. Discarding the
    return value turns a refused device write into a silent no-op, which is how
    an empty contact cache and an unrestored route both went unnoticed.
    """
    if result is None or getattr(result, "type", None) != EventType.ERROR:
        return None
    return (getattr(result, "payload", None) or {}).get("reason", "") or "no reason given"


async def _restore_contact_path(change, contact, path, mode, cfg, pubkey, logger) -> None:
    """Put a pinned contact's route back, surviving the cancellation that may
    have made the restore necessary.

    This runs from a ``finally``, so it can be entered with the task already
    cancelled -- where a bare ``await`` aborts before the device is told
    anything, stranding the contact on a zero-hop path indefinitely. The write is
    therefore shielded from that cancellation, and still bounded so it cannot
    hang the cycle. The caller holds the device lock across this, so the window
    is not observable by other traffic.
    """
    write = asyncio.ensure_future(change(contact, path, mode))
    pending_cancel = None
    try:
        async with asyncio.timeout(cfg.command_timeout):
            result = await asyncio.shield(write)
    except asyncio.CancelledError as exc:
        # The shield kept the write alive; give it the same bounded window to
        # land before propagating, rather than abandon a half-applied pin.
        pending_cancel = exc
        try:
            async with asyncio.timeout(cfg.command_timeout):
                result = await write
        except Exception:
            result = None
    except Exception as exc:
        write.cancel()
        logger.warning(
            f"Neighbors: could not restore the routing path for {pubkey[:12]} ({exc}); "
            "it stays pinned to zero-hop until its next path discovery"
        )
        return

    reason = _event_error_reason(result)
    if reason is not None:
        # Not debug: the device is on a route it may not actually have, and the
        # library's cached contact now disagrees with it.
        logger.warning(
            f"Neighbors: device refused the path restore for {pubkey[:12]} ({reason}); "
            "it stays pinned to zero-hop until its next path discovery"
        )
    elif result is None:
        logger.warning(
            f"Neighbors: path restore for {pubkey[:12]} did not complete; "
            "it stays pinned to zero-hop until its next path discovery"
        )

    if pending_cancel is not None:
        raise pending_cancel


async def _load_contacts(meshcore, cfg: NeighborsConfig, logger, command_lock=None) -> None:
    """Populate the library's contact cache before the scope pass.

    Required, not cosmetic. ``send_anon_req`` consults this cache to decide how
    to route: a destination it finds there is sent direct, one it does not is
    left to the firmware, which floods it -- and a flooded REGIONS request is
    dropped unanswered by the repeater. Skipping this is why every neighbor
    reported ``timeout`` regardless of how it was configured.

    ``MeshCore.ensure_contacts()`` is deliberately not used. It calls
    ``get_contacts()`` with the library's 5s default, which is generous on an
    idle link and far too short here: the fetch is answered as a stream of
    NEXT_CONTACT events through the same dispatcher the capture path is filling
    with RF_DATA, so under live traffic it times out. ``get_contacts`` reports
    that by *returning* Event(ERROR) rather than raising, and ``ensure_contacts``
    passes the result back as True regardless -- so the cache silently stays
    empty and every scope query floods. Calling the command directly lets us set
    the timeout and actually inspect the outcome.

    Best effort: a failure costs us the scopes but not the cycle, which still
    publishes the neighbour list -- the more valuable half of the payload.
    """
    commands = getattr(meshcore, "commands", None)
    fetch = getattr(commands, "get_contacts", None)
    if not callable(fetch):
        return

    try:
        # Under the lock: this is a multi-frame exchange, and an interleaved
        # command would take NEXT_CONTACT events that belong to it.
        async with _maybe_lock(command_lock):
            # wait_for can swallow cancellation at command completion on Python 3.11.
            async with asyncio.timeout(cfg.command_timeout * 2):
                result = await fetch(timeout=cfg.command_timeout)
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        logger.warning(f"Neighbors: could not load the contact cache ({exc}); "
                       "scope queries will be routed flooded and go unanswered")
        return

    if result is not None and getattr(result, "type", None) == EventType.ERROR:
        reason = (getattr(result, "payload", None) or {}).get("reason", "")
        logger.warning(
            f"Neighbors: contact fetch failed{f' ({reason})' if reason else ''}; "
            "scope queries will be routed flooded and go unanswered"
        )
        return

    loaded = len(getattr(meshcore, "contacts", None) or {})
    if not loaded:
        logger.warning(
            "Neighbors: contact cache is empty after a successful fetch; "
            "scope queries will be routed flooded and go unanswered"
        )
    elif logger is not None:
        logger.debug(f"Neighbors: {loaded} contact(s) loaded for scope routing")


@asynccontextmanager
async def _direct_route(meshcore, cfg: NeighborsConfig, pubkey: str, logger, *, debug: bool = False):
    """Pin ``pubkey``'s contact to a zero-hop path for the duration of one query.

    Pin both multi-hop and pathless contacts here. The SDK's pathless pin/reset
    has no ``finally``, so cancellation can leave that contact pinned. An already
    zero-hop contact needs no write.

    The original path is restored explicitly rather than through ``reset_path``,
    which clears ``out_path`` outright: that would cost the contact its route and
    force a fresh path discovery purely as a side effect of reading its scopes.
    """
    getter = getattr(meshcore, "get_contact_by_key_prefix", None)
    contact = getter(pubkey[:12].lower()) if callable(getter) else None
    commands = getattr(meshcore, "commands", None)
    change = getattr(commands, "change_contact_path", None)

    if contact is None or not callable(change) or contact.get("out_path_len", -1) == 0:
        yield
        return

    # Captured before the change: update_contact() reflects the new path back
    # onto this same dict, so reading them afterwards would return the pin.
    original_path = contact.get("out_path", "")
    original_mode = contact.get("out_path_hash_mode", 0)
    original_length = contact.get("out_path_len", -1)

    restore = change
    if original_length == -1:
        async def restore(contact, path, mode):
            # change_contact_path("") encodes zero-hop, not the -1 flood sentinel.
            contact["out_path"] = path
            contact["out_path_len"] = original_length
            contact["out_path_hash_mode"] = mode
            return await commands.update_contact(contact)

    # Restore after every attempted pin: SDK errors can mean lost acknowledgements,
    # and even a device refusal leaves the cached contact mutated.
    try:
        try:
            async with asyncio.timeout(cfg.command_timeout):
                result = await change(contact, "")
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.debug(f"Neighbors: pin of {pubkey[:12]} to zero-hop did not complete: {exc}")
        else:
            reason = _event_error_reason(result)
            if reason is not None:
                logger.debug(
                    f"Neighbors: zero-hop pin for {pubkey[:12]} was not confirmed ({reason})"
                )
            elif debug:
                logger.debug(
                    f"Neighbors: pinned {pubkey[:12]} to zero-hop for its scope query "
                    f"(was {original_path or '(none)'})"
                )
        yield
    finally:
        await _restore_contact_path(
            restore, contact, original_path, original_mode, cfg, pubkey, logger
        )


async def collect_scopes(
    meshcore,
    entries: list[NeighborEntry],
    cfg: NeighborsConfig,
    logger,
    *,
    debug: bool = False,
    command_lock=None,
) -> None:
    """Stage 2: one anon-regions request per neighbor, paced, updating in place.

    Entries must already be sorted (see sort_entries) so that if the cycle
    budget runs out the most useful neighbors have been covered. Anything not
    reached keeps its initial ``timeout`` status, matching the firmware's
    fallback.

    The probe is zero-hop, matching the firmware, and this function is what
    makes it so: it loads the contact cache up front and pins each neighbor to a
    zero-hop path around its own query. Neither step is optional -- a request
    that reaches the repeater any other way is dropped by its isRouteDirect()
    gate without a reply. See ``_load_contacts`` and ``_direct_route``.
    """
    if not entries:
        return

    # Before the loop: one device round-trip for the whole pass, not one per
    # neighbor. _direct_route needs a populated cache to find anything.
    await _load_contacts(meshcore, cfg, logger, command_lock=command_lock)

    deadline = time.time() + cfg.cycle_timeout
    # 0 means "let the device decide": req_regions_sync derives the wait from the
    # suggested_timeout the radio returns, which is its own airtime estimate.
    timeout = cfg.scope_timeout if cfg.scope_timeout > 0 else 0

    for index, entry in enumerate(entries):
        if time.time() >= deadline:
            dropped = len(entries) - index
            logger.warning(
                f"Neighbors: cycle budget ({cfg.cycle_timeout:.0f}s) reached, "
                f"{dropped} of {len(entries)} neighbor(s) left unqueried (reported as timeout)"
            )
            break

        # Settle gap between requests, standing in for the firmware's
        # wait-for-TX-completion gating.
        if index > 0 and cfg.scope_gap > 0:
            await asyncio.sleep(cfg.scope_gap)

        try:
            # Locked per request, not for the whole pass: a pass can span
            # minutes and must not block the app's other device traffic.
            async with _maybe_lock(command_lock):
                # Inside the lock: while a neighbor is pinned to zero-hop its
                # contact is temporarily wrong for everything else, so no other
                # device traffic may observe that window.
                async with _direct_route(meshcore, cfg, entry.pubkey, logger, debug=debug):
                    # Bounded: this holds the shared device-command lock, and an
                    # unbounded stall here would block the connection watchdog
                    # (and everything else) for as long as the write hangs.
                    async with asyncio.timeout(cfg.scope_request_budget):
                        scopes = await meshcore.commands.req_regions_sync(
                            entry.pubkey,
                            timeout=timeout,
                            min_timeout=cfg.scope_min_timeout,
                        )
        except asyncio.CancelledError:
            raise
        except asyncio.TimeoutError:
            entry.status = STATUS_SEND_FAILED
            logger.warning(
                f"Neighbors: scope request to {entry.pubkey[:12]} exceeded "
                f"{cfg.scope_request_budget:.0f}s; the device link may be stalled"
            )
            continue
        except Exception as exc:
            entry.status = STATUS_SEND_FAILED
            logger.debug(f"Neighbors: scope request to {entry.pubkey[:12]} failed: {exc}")
            continue

        if scopes is None:
            # req_regions_sync collapses every failure to None: a real timeout,
            # but also a device-level send rejection. We report timeout, which is
            # the firmware's own fallback for anything that isn't a clean send
            # failure or response.
            entry.status = STATUS_TIMEOUT
            if debug:
                logger.debug(f"Neighbors: no scope response from {entry.pubkey[:12]}")
            continue

        entry.scopes = str(scopes).strip()
        entry.status = STATUS_RESPONDED
        if debug:
            logger.debug(
                f"Neighbors: {entry.pubkey[:12]} scopes="
                f"{entry.scopes if entry.scopes else '(none)'}"
            )


async def fetch_self_scopes(meshcore, cfg: NeighborsConfig, logger, command_lock=None) -> str:
    """This node's own scope names for the message's ``self`` object.

    A companion radio has no region_map, so the closest analogue to the
    firmware's exportNamesTo(REGION_DENY_FLOOD) is the default flood scope name.
    ``neighbors_self_scopes`` overrides it outright.
    """
    if cfg.self_scopes:
        return cfg.self_scopes

    # A reconnect can null out the device handle mid-cycle (a cycle spans minutes).
    commands = getattr(meshcore, "commands", None)
    getter = getattr(commands, "get_default_flood_scope", None)
    if not callable(getter):
        return ""

    try:
        async with _maybe_lock(command_lock):
            result = await asyncio.wait_for(getter(), timeout=cfg.command_timeout)
    except Exception as exc:
        logger.debug(f"Neighbors: could not read default flood scope: {exc}")
        return ""

    if result is None or result.type == EventType.ERROR:
        return ""
    return str((getattr(result, "payload", None) or {}).get("scope_name", "") or "").strip()


def build_neighbors_message(
    origin: str,
    origin_id: str,
    self_scopes: str,
    entries: list[NeighborEntry],
    *,
    timestamp: Optional[str] = None,
    now: Optional[float] = None,
    budget: int = NEIGHBORS_JSON_BUDGET,
    total_neighbors: Optional[int] = None,
) -> tuple[dict[str, Any], int]:
    """Build the neighbors payload, dropping the tail past ``budget`` bytes.

    Matches MQTTPayloadBuilder::buildNeighborsMessage. Returns the message and
    the number of entries dropped.
    """
    now = time.time() if now is None else now
    # total_neighbors is how many were discovered before any max_neighbors cap;
    # queried_neighbors is how many we actually asked. Firmware key order
    # (MQTTPayloadBuilder.cpp): these sit between origin_id and self.
    queried = len(entries)
    total = queried if total_neighbors is None else total_neighbors
    message: dict[str, Any] = {
        "timestamp": timestamp or datetime.now(timezone.utc).isoformat(),
        "origin": origin,
        "origin_id": origin_id,
        "total_neighbors": total,
        "queried_neighbors": queried,
        # Set below once we know whether the payload budget dropped a tail.
        "truncated": total > queried,
        "self": {"scopes": self_scopes or ""},
        "neighbors": [],
    }

    neighbors = message["neighbors"]
    dropped = 0
    for position, entry in enumerate(sort_entries(entries, now)):
        neighbors.append(
            {
                "pubkey": entry.pubkey.upper(),
                "snr": entry.snr,
                "heard_secs_ago": entry.heard_secs_ago(now),
                "scopes": entry.scopes or "",
                "status": entry.status,
            }
        )
        # Entries are ordered most- to least-useful, so once one overflows, drop
        # it and everything after it.
        if len(json.dumps(message)) >= budget:
            neighbors.pop()
            dropped = len(entries) - position
            break

    # Truncated covers both causes: the max_neighbors cap and the payload budget.
    message["truncated"] = bool(dropped) or total > queried
    return message, dropped
