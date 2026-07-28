"""Serialisation of device commands.

Nothing in the app guarantees callers are sequential -- schedulers, health
checks, JWT signing and user commands all issue independently -- so device
commands are funnelled through a single lock. It is task-reentrant because the
JWT path legitimately nests.

meshcore_py >= 2.3.8 serialises the BLE write itself, which is what stops two
overlapping writes from dropping the link ("BLE write failed: 19", reproduced on
hardware). This lock covers what that cannot: a command is a write *plus* a wait
for its reply, which the library does not serialise, and multi-frame sequences
like on-device JWT signing have to be held as a unit.
"""
from __future__ import annotations

import asyncio

import pytest

from meshcore_packet_capture import packet_capture as pc_mod
from meshcore_packet_capture.packet_capture import PacketCapture


@pytest.fixture
def capture(monkeypatch: pytest.MonkeyPatch) -> PacketCapture:
    monkeypatch.setenv("PACKETCAPTURE_IATA", "SEA")
    return PacketCapture(enable_mqtt=False)



def test_retryable_device_command_serialises(capture: PacketCapture):
    """Concurrent commands can take each other's reply; the wrapper must serialise."""
    capture.connected = True
    import types as _types
    capture.meshcore = _types.SimpleNamespace(is_connected=True)
    overlap = {"cur": 0, "max": 0}

    async def slow_command():
        overlap["cur"] += 1
        overlap["max"] = max(overlap["max"], overlap["cur"])
        await asyncio.sleep(0.01)
        overlap["cur"] -= 1
        return type("E", (), {"type": "ok", "payload": {}})()

    async def scenario():
        await asyncio.gather(*(
            capture.retryable_device_command(slow_command, f"cmd{i}", timeout=5, max_retries=1)
            for i in range(6)
        ))

    asyncio.run(scenario())
    assert overlap["max"] == 1, f"{overlap['max']} device commands overlapped"


def test_reentrant_lock_allows_same_task_to_nest():
    """JWT signing holds the lock, then its fallback re-enters via
    retryable_device_command. A plain asyncio.Lock deadlocks there."""
    lock = pc_mod.TaskReentrantLock()

    async def scenario():
        async with lock:
            async with lock:          # would hang on a plain Lock
                assert lock.locked()
            assert lock.locked()      # still held at depth 1
        return lock.locked()

    assert asyncio.run(asyncio.wait_for(scenario(), timeout=2.0)) is False


def test_reentrant_lock_still_excludes_other_tasks():
    """Re-entry is per task; concurrent tasks must still serialise."""
    lock = pc_mod.TaskReentrantLock()
    overlap = {"cur": 0, "max": 0}

    async def worker():
        async with lock:
            overlap["cur"] += 1
            overlap["max"] = max(overlap["max"], overlap["cur"])
            await asyncio.sleep(0)
            overlap["cur"] -= 1

    async def scenario():
        await asyncio.gather(*(worker() for _ in range(6)))

    asyncio.run(scenario())
    assert overlap["max"] == 1


def test_reentrant_lock_releases_on_exception():
    lock = pc_mod.TaskReentrantLock()

    async def scenario():
        try:
            async with lock:
                raise RuntimeError("boom")
        except RuntimeError:
            pass
        return lock.locked()

    assert asyncio.run(scenario()) is False


def test_retryable_device_command_gives_up_rather_than_queueing_forever(
    capture: PacketCapture,
):
    """A stalled holder must not block the connection watchdog indefinitely.

    The watchdog is the one thing that can recover a stalled link, and its own
    timeout cannot fire while it is still queued for the lock.
    """
    capture.connected = True
    import types as _types
    capture.meshcore = _types.SimpleNamespace(is_connected=True)
    capture.device_lock_wait_margin = 0.05

    async def scenario():
        await capture.device_command_lock.acquire()   # simulate a stalled holder

        async def never():
            return None

        try:
            return await asyncio.wait_for(
                capture.retryable_device_command(never, "health", timeout=0.05, max_retries=1),
                timeout=3.0,
            )
        finally:
            capture.device_command_lock.release()

    assert asyncio.run(scenario()) is None
