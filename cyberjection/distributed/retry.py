"""Retry backoff math and dead-letter-queue handling for distributed tasks.

Kept separate from `tasks.py` for the same reason
`cyberjection.persistence.resumability`'s reconciliation logic is kept
separate from `CampaignRepository`: `compute_backoff_delay` is a pure
function of plain numbers, so it can be hard-tested directly -- including
adversarial retry counts and injected randomness for determinism --
without needing Celery or Redis to be importable at all.
"""

from __future__ import annotations

import json
import random
import time
from typing import Any, Callable, Dict, Optional

DEAD_LETTER_QUEUE_KEY = "cyberjection:dlq"


def compute_backoff_delay(
    retry_count: int,
    *,
    base: float = 1.0,
    jitter_max: float = 1.0,
    cap: Optional[float] = None,
    rng: Optional[Callable[[], float]] = None,
) -> float:
    """Exponential backoff with jitter: `T_wait = base * 2^retry + jitter`.

    `retry_count` is 0 for the first retry (the task's initial attempt
    doesn't call this at all). `jitter_max` bounds a uniform random
    addition in `[0, jitter_max)` -- pure exponential backoff with no
    jitter causes every worker that failed at the same moment (e.g. a
    provider-wide outage) to retry in lockstep, re-creating the exact
    thundering-herd the backoff was meant to avoid; jitter staggers them.
    `cap`, if given, ceilings the total so a task that's failed many times
    doesn't end up waiting for a wall-clock eternity before its next
    attempt. `rng` defaults to `random.random` and exists so tests can
    inject a deterministic generator instead of patching the `random`
    module globally.
    """

    if retry_count < 0:
        raise ValueError(f"retry_count must be >= 0, got {retry_count}")
    if base <= 0:
        raise ValueError(f"base must be positive, got {base}")
    if jitter_max < 0:
        raise ValueError(f"jitter_max must be >= 0, got {jitter_max}")

    delay = base * (2**retry_count)
    jitter = (rng or random.random)() * jitter_max
    total = delay + jitter
    if cap is not None:
        total = min(total, cap)
    return total


def build_dead_letter_payload(
    *,
    task_name: str,
    task_id: str,
    args: Any,
    kwargs: Any,
    error: BaseException,
    retries: int,
) -> Dict[str, Any]:
    """Builds the JSON-serializable record pushed to the dead-letter queue.

    A separate builder function (rather than inlining the dict literal at
    the push call site) so the exact shape of a DLQ entry is one thing
    that can be unit-tested without touching Redis, and so a consumer
    reading the DLQ back out has one documented schema to parse against.
    """

    return {
        "task_name": task_name,
        "task_id": task_id,
        "args": list(args) if args is not None else [],
        "kwargs": dict(kwargs) if kwargs is not None else {},
        "error_type": type(error).__name__,
        "error_message": str(error),
        "retries_exhausted": retries,
        "failed_at": time.time(),
    }


async def push_to_dead_letter_queue(
    redis_client: Any,
    *,
    task_name: str,
    task_id: str,
    args: Any = None,
    kwargs: Any = None,
    error: BaseException,
    retries: int,
    queue_key: str = DEAD_LETTER_QUEUE_KEY,
) -> None:
    """Serializes a failed task's context and pushes it onto the DLQ list.

    Uses a plain Redis list (`RPUSH`) rather than a Stream or a second
    Celery queue: a DLQ's job is "durable record an operator can inspect
    and optionally replay," not "actively dispatch work," so the simplest
    durable structure that supports append + full scan is enough, and it
    keeps this module's Redis command surface identical to what the rate
    limiter and coordinator already use (no new Redis data-structure
    dependency to test against offline).
    """

    payload = build_dead_letter_payload(
        task_name=task_name,
        task_id=task_id,
        args=args,
        kwargs=kwargs,
        error=error,
        retries=retries,
    )
    await redis_client.rpush(queue_key, json.dumps(payload))
