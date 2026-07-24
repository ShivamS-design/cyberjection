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
    """

    limiter = _get_rate_limiter(DEFAULT_REDIS_URL, target_id, max_rpm, max_tpm)
    await limiter.acquire(request_cost=1)

    await asyncio.sleep(0)  # yields control; stand-in for the real provider call
    return {
        "task_id": task_id,
        "target_id": target_id,
        "provider_url": provider_url,
        "status": "COMPLETED",
        "score": 0.0,
    }


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
        countdown = compute_backoff_delay(self.request.retries)
        logger.warning(
            "task %s failed for target %s (attempt %s): %s; retrying in %.2fs",
            self.request.id,
            target_id,
            self.request.retries,
            exc,
            countdown,
        )
        try:
            raise self.retry(exc=exc, countdown=countdown)
        except MaxRetriesExceededError:
            logger.error(
                "task %s exhausted %s retries for target %s; routing to dead-letter queue",
                self.request.id,
                self.max_retries,
                target_id,
            )
            asyncio.run(_dead_letter(self, target_id, payload, provider_url, exc))
            raise


async def _dead_letter(self: Any, target_id: str, payload: str, provider_url: str, exc: BaseException) -> None:
    limiter = _get_rate_limiter(DEFAULT_REDIS_URL, target_id, 60, 90_000)
    await push_to_dead_letter_queue(
        limiter.redis,
        task_name="execute_eval_turn_task",
        task_id=self.request.id,
        args=[target_id, payload, provider_url],
        kwargs={},
        error=exc,
        retries=self.request.retries,
    )
