"""Celery task definitions worker nodes actually execute.

Each task wraps a single evaluation turn (or, for multi-turn strategies,
a single Crescendo/TAP step) behind Celery's retry machinery: a transient
failure (network blip, provider 5xx, momentary rate-limit rejection) gets
retried with exponential backoff; a failure that survives every retry is
routed to the dead-letter queue instead of vanishing into a Celery
FAILURE result nobody's watching.
"""

from __future__ import annotations

import asyncio
import os
from typing import Any, Dict, Optional

from celery.exceptions import MaxRetriesExceededError
from celery.utils.log import get_task_logger

from cyberjection.distributed.celery_app import celery_app
from cyberjection.distributed.rate_limiter import DistributedRateLimiter
from cyberjection.distributed.retry import compute_backoff_delay, push_to_dead_letter_queue

logger = get_task_logger(__name__)

DEFAULT_REDIS_URL = os.environ.get("CYBERJECTION_CELERY_BROKER_URL", "redis://localhost:6379/0")
MAX_RETRIES = 3

# Constructing a `DistributedRateLimiter` opens a Redis connection and
# loads the Lua script onto the server, so building a fresh one on every
# single task invocation (as an earlier draft of this task did) leaks a
# connection per task and re-uploads the same script every time. Worker
# processes are long-lived, so a limiter is cached per (redis_url,
# provider_id) and reused across every task that process executes.
_limiter_cache: Dict[Any, DistributedRateLimiter] = {}


def _get_rate_limiter(redis_url: str, provider_id: str, max_rpm: int, max_tpm: int) -> DistributedRateLimiter:
    key = (redis_url, provider_id, max_rpm, max_tpm)
    limiter = _limiter_cache.get(key)
    if limiter is None:
        limiter = DistributedRateLimiter(redis_url, provider_id, max_rpm=max_rpm, max_tpm=max_tpm)
        _limiter_cache[key] = limiter
    return limiter


async def _execute_eval_turn(
    target_id: str,
    payload: str,
    provider_url: str,
    *,
    max_rpm: int,
    max_tpm: int,
    task_id: str,
) -> Dict[str, Any]:
    """The actual async work: acquire a rate-limit token, then run the
    turn. Kept as a standalone coroutine (rather than nested inside the
    task function) so it can be awaited directly from an async test
    without going through Celery's synchronous task-call machinery at
    all.

    The `provider_url` argument threads through to wherever this gets
    wired into `cyberjection.providers.litellm_provider.LiteLLMTarget`
    in a later phase; this phase's task body stops short of making a
    real provider call (there's no live campaign/target context to call
    it with from a bare Celery task signature), matching the Phase 7
    spec's own "mock API execution bridge" scope.

    Disconnects the limiter's Redis connection in a `finally` block
    before returning -- see that block's own comment for why.
    """

    limiter = _get_rate_limiter(DEFAULT_REDIS_URL, target_id, max_rpm, max_tpm)
    try:
        await limiter.acquire(request_cost=1)

        await asyncio.sleep(0)  # yields control; stand-in for the real provider call
        return {
            "task_id": task_id,
            "target_id": target_id,
            "provider_url": provider_url,
            "status": "COMPLETED",
            "score": 0.0,
        }
    finally:
        # `execute_eval_turn_task` below runs this coroutine inside its
        # own fresh `asyncio.run(...)` call on every single invocation --
        # a brand new event loop each time. `limiter`, however, is cached
        # at module scope in `_limiter_cache` and deliberately *reused*
        # across those separate invocations (see that cache's own
        # docstring: re-uploading the Lua script and opening a fresh
        # connection per task would leak a connection per task). Real
        # `redis.asyncio.Redis`'s connection pool is a genuine asyncio
        # object -- its sockets/locks are bound to whichever event loop
        # was running when they were first created. Reusing that same
        # pool from a *different* event loop on the next task raises
        # errors like "Future ... got Future attached to a different
        # loop" or "RuntimeError: Event loop is closed" (this never
        # surfaced against the project's offline Redis test double, which
        # has no real loop-bound sockets to begin with -- it only showed
        # up once this suite ran against genuine Redis in CI).
        #
        # Disconnecting here, before this coroutine's own `asyncio.run()`
        # call returns and tears down this event loop, lets the
        # connection pool reconnect lazily -- against whichever loop is
        # current -- the next time this same cached `limiter` is used.
        # The cached `DistributedRateLimiter` instance (and its
        # already-loaded Lua script SHA, which is server-side state, not
        # connection state) is left untouched, so `_limiter_cache`'s
        # reuse-the-same-instance contract (see
        # `TestRateLimiterCaching` in the test suite) still holds.
        await limiter.close()


@celery_app.task(bind=True, max_retries=MAX_RETRIES, default_retry_delay=5)
def execute_eval_turn_task(
    self: Any,
    target_id: str,
    payload: str,
    provider_url: str,
    max_rpm: int = 60,
    max_tpm: int = 90_000,
) -> Dict[str, Any]:
    """Distributed task executing a single evaluation turn against
    `target_id`, rate-limited cluster-wide, retried with backoff on
    transient failure, and dead-lettered once retries are exhausted."""

    logger.info("task %s started for target %s", self.request.id, target_id)

    try:
        return asyncio.run(
            _execute_eval_turn(
                target_id,
                payload,
                provider_url,
                max_rpm=max_rpm,
                max_tpm=max_tpm,
                task_id=self.request.id,
            )
        )
    except Exception as exc:  # noqa: BLE001 - deliberately broad: any failure here is a retry candidate
        # Checked *before* calling `self.retry()`, rather than relying on
        # catching `MaxRetriesExceededError` out of that call: real
        # Celery's `Task.retry()`, once `self.request.retries` has reached
        # `self.max_retries`, does NOT raise `MaxRetriesExceededError` when
        # an `exc` was passed in (which this call site always does) --
        # it re-raises that original `exc` itself instead (per Celery's
        # own `retry()` source: `if exc: raise_with_context(exc)`, and
        # `MaxRetriesExceededError` is only raised when `exc` is `None`).
        # This project's offline Celery test double originally modeled
        # `self.retry()` as unconditionally raising
        # `MaxRetriesExceededError` once exhausted -- which is why this
        # `except MaxRetriesExceededError:` around `self.retry()` passed
        # every offline test but silently never fired once this ran
        # against genuine Celery in CI: the raw `exc` (e.g. the original
        # `ConnectionError`) propagated straight out instead, skipping the
        # dead-letter hand-off entirely. Deciding exhaustion ourselves,
        # up front, makes the dead-letter path -- and the
        # `MaxRetriesExceededError` this task promises its callers --
        # reliable regardless of which `exc` the retry was called with.
        if self.request.retries >= self.max_retries:
            logger.error(
                "task %s exhausted %s retries for target %s; routing to dead-letter queue",
                self.request.id,
                self.max_retries,
                target_id,
            )
            asyncio.run(_dead_letter(self, target_id, payload, provider_url, exc))
            raise MaxRetriesExceededError(str(exc)) from exc

        countdown = compute_backoff_delay(self.request.retries)
        logger.warning(
            "task %s failed for target %s (attempt %s): %s; retrying in %.2fs",
            self.request.id,
            target_id,
            self.request.retries,
            exc,
            countdown,
        )
        raise self.retry(exc=exc, countdown=countdown)


async def _dead_letter(self: Any, target_id: str, payload: str, provider_url: str, exc: BaseException) -> None:
    # Runs in its own `asyncio.run(...)` call (see `execute_eval_turn_task`),
    # separate from -- and after -- the `asyncio.run(...)` call that ran
    # `_execute_eval_turn` for this same task attempt. See
    # `_execute_eval_turn`'s `finally` block for why the limiter's Redis
    # connection must be disconnected before this coroutine's own event
    # loop closes.
    limiter = _get_rate_limiter(DEFAULT_REDIS_URL, target_id, 60, 90_000)
    try:
        await push_to_dead_letter_queue(
            limiter.redis,
            task_name="execute_eval_turn_task",
            task_id=self.request.id,
            args=[target_id, payload, provider_url],
            kwargs={},
            error=exc,
            retries=self.request.retries,
        )
    finally:
        await limiter.close()
