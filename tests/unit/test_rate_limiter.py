"""Tests for cyberjection.distributed.rate_limiter.

Two layers are tested separately:

- `TestEvaluateDualBucket` exercises `evaluate_dual_bucket`, the pure
  Python function documented as a line-for-line mirror of the
  `DUAL_TOKEN_BUCKET_LUA` script. It needs no Redis client, no event loop,
  and no external service, so it runs identically everywhere.
- `TestDistributedRateLimiterAcquire` exercises the real
  `DistributedRateLimiter` against a real `redis.asyncio` client. In a
  deployment with the `redis` package installed and a reachable Redis
  server (see the spec's own `docker run redis:alpine` prerequisite),
  this runs against genuine Redis, executing the real Lua script
  server-side. In the offline sandbox this suite was developed and
  hard-tested in, `redis.asyncio` resolves to a functional in-memory
  double (see its module docstring) that dispatches `EVALSHA` for this
  exact script to `evaluate_dual_bucket` under an `asyncio.Lock`,
  reproducing Redis's single-threaded atomicity guarantee -- which is
  precisely what `test_concurrent_acquire_never_exceeds_capacity` below
  is designed to catch a regression of, either way.
"""

from __future__ import annotations

import asyncio

import pytest

from cyberjection.distributed.rate_limiter import (
    DistributedRateLimiter,
    evaluate_dual_bucket,
)
from cyberjection.utils.exceptions import RateLimitCapacityExceededError


class TestEvaluateDualBucket:
    def test_empty_bucket_starts_full(self) -> None:
        decision = evaluate_dual_bucket(
            rpm_tokens=None,
            rpm_last_update=None,
            max_rpm=10,
            rpm_refill_rate=10 / 60.0,
            rpm_cost=1,
            tpm_tokens=None,
            tpm_last_update=None,
            max_tpm=1000,
            tpm_refill_rate=1000 / 60.0,
            tpm_cost=1,
            now=1000.0,
        )
        assert decision.allowed is True
        assert decision.rpm_tokens_remaining == 9
        assert decision.tpm_tokens_remaining == 999

    def test_exact_boundary_request_succeeds(self) -> None:
        decision = evaluate_dual_bucket(
            rpm_tokens=5,
            rpm_last_update=1000.0,
            max_rpm=10,
            rpm_refill_rate=0.0,
            rpm_cost=5,
            tpm_tokens=100,
            tpm_last_update=1000.0,
            max_tpm=1000,
            tpm_refill_rate=0.0,
            tpm_cost=100,
            now=1000.0,
        )
        assert decision.allowed is True
        assert decision.rpm_tokens_remaining == 0
        assert decision.tpm_tokens_remaining == 0

    def test_one_over_boundary_rejected(self) -> None:
        decision = evaluate_dual_bucket(
            rpm_tokens=5,
            rpm_last_update=1000.0,
            max_rpm=10,
            rpm_refill_rate=1.0,
            rpm_cost=6,
            tpm_tokens=1000,
            tpm_last_update=1000.0,
            max_tpm=1000,
            tpm_refill_rate=1.0,
            tpm_cost=1,
            now=1000.0,
        )
        assert decision.allowed is False
        assert decision.wait_seconds == 1  # need 1 more RPM token at 1/sec refill

    def test_refill_capped_at_max_even_after_long_idle(self) -> None:
        # bucket was last touched a full day ago -- refill must saturate at
        # max_rpm, not keep accumulating past capacity.
        decision = evaluate_dual_bucket(
            rpm_tokens=0,
            rpm_last_update=1000.0,
            max_rpm=10,
            rpm_refill_rate=10 / 60.0,
            rpm_cost=10,
            tpm_tokens=0,
            tpm_last_update=1000.0,
            max_tpm=1000,
            tpm_refill_rate=1000 / 60.0,
            tpm_cost=1,
            now=1000.0 + 86_400,
        )
        assert decision.allowed is True
        assert decision.rpm_tokens_remaining == 0  # 10 available, 10 consumed

    def test_zero_elapsed_time_grants_no_refill(self) -> None:
        decision = evaluate_dual_bucket(
            rpm_tokens=0,
            rpm_last_update=1000.0,
            max_rpm=10,
            rpm_refill_rate=1.0,
            rpm_cost=1,
            tpm_tokens=1000,
            tpm_last_update=1000.0,
            max_tpm=1000,
            tpm_refill_rate=1.0,
            tpm_cost=1,
            now=1000.0,
        )
        assert decision.allowed is False

    def test_rpm_ok_but_tpm_short_rejects_the_whole_request(self) -> None:
        # This is the behavior the earlier, RPM-only draft was missing
        # entirely: a request with plenty of RPM budget left must still be
        # rejected if it would blow the TPM budget.
        decision = evaluate_dual_bucket(
            rpm_tokens=10,
            rpm_last_update=1000.0,
            max_rpm=10,
            rpm_refill_rate=1.0,
            rpm_cost=1,
            tpm_tokens=50,
            tpm_last_update=1000.0,
            max_tpm=1000,
            tpm_refill_rate=10.0,
            tpm_cost=500,
            now=1000.0,
        )
        assert decision.allowed is False
        assert decision.wait_seconds == 45  # (500 - 50) / 10, ceil'd

    def test_neither_bucket_is_debited_when_request_is_rejected(self) -> None:
        # Guards against a partial-admission bug: if only one bucket were
        # checked-and-debited before discovering the other is short, state
        # would end up decremented for a request that overall failed.
        decision = evaluate_dual_bucket(
            rpm_tokens=10,
            rpm_last_update=1000.0,
            max_rpm=10,
            rpm_refill_rate=1.0,
            rpm_cost=1,
            tpm_tokens=0,
            tpm_last_update=1000.0,
            max_tpm=1000,
            tpm_refill_rate=1.0,
            tpm_cost=500,
            now=1000.0,
        )
        assert decision.allowed is False
        assert decision.rpm_tokens_remaining is None
        assert decision.tpm_tokens_remaining is None


@pytest.mark.asyncio
class TestDistributedRateLimiterAcquire:
    async def test_acquire_within_capacity_succeeds_immediately(self) -> None:
        limiter = DistributedRateLimiter("redis://test-rl-1/0", "openai", max_rpm=5, max_tpm=10_000)
        for _ in range(5):
            await asyncio.wait_for(limiter.acquire(), timeout=1.0)

    async def test_acquire_beyond_capacity_blocks(self) -> None:
        limiter = DistributedRateLimiter("redis://test-rl-2/0", "openai", max_rpm=2, max_tpm=10_000)
        await limiter.acquire()
        await limiter.acquire()
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(limiter.acquire(), timeout=0.3)

    async def test_request_cost_larger_than_capacity_raises_immediately(self) -> None:
        # Prior to this fix, a request for more tokens than the bucket
        # could ever hold would loop forever inside acquire()'s while-True,
        # since current_tokens can never exceed max_tokens. It must fail
        # fast instead.
        limiter = DistributedRateLimiter("redis://test-rl-3/0", "openai", max_rpm=5, max_tpm=10_000)
        with pytest.raises(RateLimitCapacityExceededError):
            await asyncio.wait_for(limiter.acquire(request_cost=6), timeout=1.0)

    async def test_token_cost_larger_than_tpm_capacity_raises_immediately(self) -> None:
        limiter = DistributedRateLimiter("redis://test-rl-4/0", "openai", max_rpm=100, max_tpm=500)
        with pytest.raises(RateLimitCapacityExceededError):
            await asyncio.wait_for(limiter.acquire(token_cost=501), timeout=1.0)

    async def test_tpm_bucket_is_actually_enforced(self) -> None:
        # The earlier draft accepted max_tpm in __init__ but never checked
        # it anywhere -- this is the regression test for that fix.
        limiter = DistributedRateLimiter("redis://test-rl-5/0", "openai", max_rpm=1000, max_tpm=100)
        await limiter.acquire(request_cost=1, token_cost=60)
        with pytest.raises(asyncio.TimeoutError):
            # 60 already spent of a 100 cap; asking for another 60 must
            # block even though the RPM bucket has ample room.
            await asyncio.wait_for(limiter.acquire(request_cost=1, token_cost=60), timeout=0.3)

    async def test_two_limiter_instances_share_state_via_same_redis_url(self) -> None:
        # Distinct worker processes each construct their own
        # DistributedRateLimiter, but must contend over the *same*
        # provider-scoped bucket -- this is the whole point of moving the
        # bucket into Redis instead of keeping it in-process.
        limiter_a = DistributedRateLimiter("redis://test-rl-6/0", "shared-provider", max_rpm=3, max_tpm=10_000)
        limiter_b = DistributedRateLimiter("redis://test-rl-6/0", "shared-provider", max_rpm=3, max_tpm=10_000)
        await limiter_a.acquire()
        await limiter_a.acquire()
        await limiter_b.acquire()  # 3rd unit, drawn from the same shared bucket
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(limiter_b.acquire(), timeout=0.3)

    async def test_concurrent_acquire_never_exceeds_capacity(self) -> None:
        """The concurrency/atomicity claim itself: 50 coroutines race to
        acquire from a bucket with capacity 10. If the check-then-debit
        sequence were not atomic, more than 10 could observe "capacity
        available" before any of them writes back the debited value,
        letting more than 10 succeed. Exactly 10 must succeed within the
        short window before any refill meaningfully progresses; the rest
        must still be waiting.
        """

        limiter = DistributedRateLimiter("redis://test-rl-7/0", "anthropic", max_rpm=10, max_tpm=1_000_000)
        completed = 0
        lock = asyncio.Lock()

        async def worker() -> None:
            nonlocal completed
            try:
                await asyncio.wait_for(limiter.acquire(request_cost=1), timeout=0.05)
                async with lock:
                    completed += 1
            except asyncio.TimeoutError:
                pass

        await asyncio.gather(*(worker() for _ in range(50)))
        assert completed == 10

    async def test_construction_rejects_non_positive_limits(self) -> None:
        with pytest.raises(ValueError):
            DistributedRateLimiter("redis://test-rl-8/0", "openai", max_rpm=0)
        with pytest.raises(ValueError):
            DistributedRateLimiter("redis://test-rl-9/0", "openai", max_tpm=0)
