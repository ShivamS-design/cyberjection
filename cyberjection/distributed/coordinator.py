"""Cluster state coordination via Redis Pub/Sub.

Once evaluation work is spread across worker nodes, an early-termination
signal decided on one node (e.g. a Tier 1 evaluator's instant `Verdict.FAIL`
on a strategy configured to stop-on-first-failure) has to reach every other
node currently working on the same campaign or test case, not just the
node that made the decision. Redis Pub/Sub is used here rather than the
Celery broker's own queue: an abort is a broadcast ("every listener acts
on this"), while Celery's queue semantics are point-to-point ("exactly one
worker consumes this task").
"""

from __future__ import annotations

import json
from typing import Any, Optional

try:
    import redis.asyncio as aioredis
except ImportError:  # pragma: no cover - exercised only when redis truly absent
    aioredis = None  # type: ignore[assignment]

ABORT_CHANNEL = "cyberjection:events:abort"


class DistributedClusterCoordinator:
    """Publishes and listens for cluster-wide abort signals over Redis
    Pub/Sub, and centralizes the one channel name every node agrees on."""

    def __init__(self, redis_url: str, abort_channel: str = ABORT_CHANNEL) -> None:
        if aioredis is None:  # pragma: no cover - exercised only when redis truly absent
            raise ImportError(
                "The 'redis' package is required for DistributedClusterCoordinator. "
                "Install it with `pip install redis` (see pyproject.toml)."
            )
        self.redis_url = redis_url
        self.redis = aioredis.from_url(redis_url, decode_responses=True)
        self.abort_channel = abort_channel

    async def broadcast_abort(self, test_case_id: str, reason: str) -> None:
        """Publishes an abort signal for `test_case_id` to every subscriber."""

        payload = json.dumps({"test_case_id": test_case_id, "reason": reason})
        await self.redis.publish(self.abort_channel, payload)

    async def broadcast_if_failing(self, test_case_id: str, verdict: Any, *, reason: Optional[str] = None) -> bool:
        """Broadcasts an abort only when `verdict` is a FAIL, per the Phase 7
        spec's own framing ("broadcasting early-termination signals, e.g.
        `Verdict.FAIL` triggers, cluster-wide instantly"). Returns whether a
        broadcast was actually sent, so callers can log/assert on it.

        `verdict` is compared against `cyberjection.evaluators.base.Verdict.FAIL`
        by value (`verdict == Verdict.FAIL` after coercion) rather than typed
        as `Verdict` directly, so this coordinator -- otherwise entirely
        independent of the evaluators package -- doesn't force every caller
        that only wants raw abort broadcasting to also depend on it.
        """

        from cyberjection.evaluators.base import Verdict

        is_fail = verdict == Verdict.FAIL or (isinstance(verdict, str) and verdict.upper() == Verdict.FAIL.value)
        if not is_fail:
            return False
        await self.broadcast_abort(test_case_id, reason or "evaluator verdict FAIL")
        return True

    async def listen_for_aborts(self, cancel_event: Any) -> None:
        """Blocks, listening on the abort channel, until one abort message
        arrives, then sets `cancel_event` and returns.

        `cancel_event` is duck-typed to `asyncio.Event` (needs only
        `.set()`) so tests can pass a lightweight stand-in instead of a
        real `asyncio.Event`. The pubsub connection is always
        unsubscribed and closed before returning -- including when the
        loop exits without ever seeing a message (e.g. the connection is
        closed out from under it) -- so a caller that starts and stops
        many short-lived listeners (as tests do) doesn't leak a Redis
        connection per listener.
        """

        pubsub = self.redis.pubsub()
        try:
            await pubsub.subscribe(self.abort_channel)
            async for message in pubsub.listen():
                if message["type"] == "message":
                    data = json.loads(message["data"])
                    cancel_event.set()
                    return data
        finally:
            await pubsub.unsubscribe(self.abort_channel)
            await pubsub.close()
        return None

    async def close(self) -> None:
        await self.redis.close()
