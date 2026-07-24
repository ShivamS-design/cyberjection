"""Tests for cyberjection.distributed.coordinator.DistributedClusterCoordinator.

Requires the `redis` package's async client surface -- see
`test_rate_limiter.py`'s module docstring for how this resolves both in a
real deployment (genuine `redis.asyncio` against a live server) and in
the offline sandbox this suite was hard-tested in (a functional in-memory
double implementing real Pub/Sub queueing semantics).
"""

from __future__ import annotations

import asyncio

import pytest

from cyberjection.distributed.coordinator import ABORT_CHANNEL, DistributedClusterCoordinator
from cyberjection.evaluators.base import Verdict


@pytest.mark.asyncio
class TestBroadcastAbort:
    async def test_broadcast_reaches_a_subscribed_listener(self) -> None:
        coord = DistributedClusterCoordinator("redis://test-coord-1/0")
        cancel_event = asyncio.Event()
        listener = asyncio.create_task(coord.listen_for_aborts(cancel_event))
        await asyncio.sleep(0.02)  # let the listener actually subscribe first

        await coord.broadcast_abort("tc-1", "manual abort")

        data = await asyncio.wait_for(listener, timeout=1.0)
        assert cancel_event.is_set()
        assert data == {"test_case_id": "tc-1", "reason": "manual abort"}

    async def test_broadcast_before_any_subscriber_is_a_silent_noop(self) -> None:
        # Redis Pub/Sub has no delivery guarantee to subscribers that
        # join after a message was published -- publishing to an empty
        # channel must not raise or hang.
        coord = DistributedClusterCoordinator("redis://test-coord-2/0")
        await coord.broadcast_abort("tc-2", "nobody listening yet")

    async def test_listener_uses_the_module_default_channel(self) -> None:
        coord = DistributedClusterCoordinator("redis://test-coord-3/0")
        assert coord.abort_channel == ABORT_CHANNEL

    async def test_custom_channel_name_is_isolated_from_default(self) -> None:
        coord_a = DistributedClusterCoordinator("redis://test-coord-4/0", abort_channel="campaign:alpha:abort")
        coord_b = DistributedClusterCoordinator("redis://test-coord-4/0")  # default channel, same redis
        cancel_event = asyncio.Event()
        listener = asyncio.create_task(coord_b.listen_for_aborts(cancel_event))
        await asyncio.sleep(0.02)

        await coord_a.broadcast_abort("tc-3", "wrong channel")

        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(listener, timeout=0.2)
        assert not cancel_event.is_set()
        listener.cancel()

    async def test_pubsub_connection_is_cleaned_up_after_listening(self) -> None:
        # Regression test: an earlier draft broke out of the listen loop
        # without unsubscribing/closing the pubsub connection, leaking a
        # subscriber entry in the fake (and, against real Redis, a
        # server-side subscription) per listener.
        coord = DistributedClusterCoordinator("redis://test-coord-5/0")
        cancel_event = asyncio.Event()
        listener = asyncio.create_task(coord.listen_for_aborts(cancel_event))
        await asyncio.sleep(0.02)
        await coord.broadcast_abort("tc-4", "cleanup check")
        await asyncio.wait_for(listener, timeout=1.0)

        remaining = coord.redis._server.subscribers.get(coord.abort_channel, [])
        assert remaining == []


@pytest.mark.asyncio
class TestBroadcastIfFailing:
    async def test_fail_verdict_triggers_broadcast(self) -> None:
        coord = DistributedClusterCoordinator("redis://test-coord-6/0")
        sent = await coord.broadcast_if_failing("tc-5", Verdict.FAIL)
        assert sent is True

    async def test_pass_verdict_does_not_broadcast(self) -> None:
        coord = DistributedClusterCoordinator("redis://test-coord-7/0")
        sent = await coord.broadcast_if_failing("tc-6", Verdict.PASS)
        assert sent is False

    async def test_uncertain_verdict_does_not_broadcast(self) -> None:
        coord = DistributedClusterCoordinator("redis://test-coord-8/0")
        sent = await coord.broadcast_if_failing("tc-7", Verdict.UNCERTAIN)
        assert sent is False

    async def test_string_fail_value_also_triggers_broadcast(self) -> None:
        coord = DistributedClusterCoordinator("redis://test-coord-9/0")
        sent = await coord.broadcast_if_failing("tc-8", "fail")
        assert sent is True

    async def test_default_reason_mentions_verdict_fail(self) -> None:
        coord = DistributedClusterCoordinator("redis://test-coord-10/0")
        cancel_event = asyncio.Event()
        listener = asyncio.create_task(coord.listen_for_aborts(cancel_event))
        await asyncio.sleep(0.02)

        await coord.broadcast_if_failing("tc-9", Verdict.FAIL)

        data = await asyncio.wait_for(listener, timeout=1.0)
        assert "FAIL" in data["reason"]
