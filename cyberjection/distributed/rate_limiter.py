"""Cluster-wide adaptive rate limiting for target providers.

`cyberjection.providers.litellm_provider._TokenBucketLimiter` already
paces requests within a single process. Once evaluation work is spread
across a pool of Celery worker processes (Phase 7's whole point), an
in-process bucket is no longer enough: five worker processes each
independently pacing "6 requests/second" against the same provider still
adds up to 30 requests/second hitting that provider's real limit. This
module moves the bucket's state into Redis so every worker process
consults and updates the *same* counter, enforcing the limit for the
provider as a whole rather than per-process.

Two limits are enforced together, atomically: requests-per-minute (RPM)
and tokens-per-minute (TPM), since providers commonly cap both
independently (e.g. OpenAI's tiered rate limits). An earlier draft of
this module accepted a `max_tpm` constructor argument but never actually
used it anywhere -- `acquire()` only ever checked the RPM bucket, so a
caller could blow straight through a provider's TPM cap without the
limiter ever noticing. This version tracks both buckets for real, and
checks + debits them in a single atomic operation so a request is never
partially admitted (RPM debited but TPM insufficient, or vice versa).
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from typing import Optional

try:
    import redis.asyncio as aioredis
except ImportError:  # pragma: no cover - exercised only when redis truly absent
    aioredis = None  # type: ignore[assignment]

from cyberjection.utils.exceptions import RateLimitCapacityExceededError

# Atomic dual-bucket (RPM + TPM) token evaluation, executed server-side via
# `EVALSHA` so the read-refill-compare-debit sequence for *both* buckets
# happens as one uninterruptible step from Redis's point of view -- no
# other worker's script invocation can interleave between the check and
# the debit, which is what makes this safe under concurrent access from
# many worker processes without a distributed lock.
#
# KEYS[1] = rpm bucket hash key      KEYS[2] = tpm bucket hash key
# ARGV[1] = max_rpm_tokens           ARGV[2] = rpm_refill_rate (tokens/sec)
# ARGV[3] = rpm_cost                 ARGV[4] = max_tpm_tokens
# ARGV[5] = tpm_refill_rate          ARGV[6] = tpm_cost
# ARGV[7] = now (unix seconds, float)
#
# Returns {1, 0} if both buckets had enough capacity and were debited, or
# {0, wait_seconds} if either bucket was short -- wait_seconds is how long
# the caller should sleep before retrying, computed from whichever bucket
# needs the longer refill.
#
# CYBERJECTION_DUAL_TOKEN_BUCKET_V1 -- marker comment used by the offline
# test double (see cyberjection.distributed._offline note in
# docs/TESTING.md) to recognize this exact script body without a real Lua
# interpreter. Do not remove.
DUAL_TOKEN_BUCKET_LUA = """
-- CYBERJECTION_DUAL_TOKEN_BUCKET_V1
local function refill(key, max_tokens, refill_rate, now)
    local data = redis.call("HMGET", key, "tokens", "last_update")
    local tokens = tonumber(data[1])
    local last_update = tonumber(data[2])
    if tokens == nil then
        return max_tokens
    end
    local delta = math.max(0, now - last_update)
    return math.min(max_tokens, tokens + delta * refill_rate)
end

local rpm_key, tpm_key = KEYS[1], KEYS[2]
local max_rpm, rpm_rate, rpm_cost = tonumber(ARGV[1]), tonumber(ARGV[2]), tonumber(ARGV[3])
local max_tpm, tpm_rate, tpm_cost = tonumber(ARGV[4]), tonumber(ARGV[5]), tonumber(ARGV[6])
local now = tonumber(ARGV[7])

local rpm_tokens = refill(rpm_key, max_rpm, rpm_rate, now)
local tpm_tokens = refill(tpm_key, max_tpm, tpm_rate, now)

if rpm_tokens >= rpm_cost and tpm_tokens >= tpm_cost then
    rpm_tokens = rpm_tokens - rpm_cost
    tpm_tokens = tpm_tokens - tpm_cost
    redis.call("HMSET", rpm_key, "tokens", rpm_tokens, "last_update", now)
    redis.call("HMSET", tpm_key, "tokens", tpm_tokens, "last_update", now)
    return {1, 0}
else
    local rpm_wait = 0
    local tpm_wait = 0
    if rpm_tokens < rpm_cost then
        rpm_wait = (rpm_cost - rpm_tokens) / rpm_rate
    end
    if tpm_tokens < tpm_cost then
        tpm_wait = (tpm_cost - tpm_tokens) / tpm_rate
    end
    local wait = rpm_wait
    if tpm_wait > wait then
        wait = tpm_wait
    end
    return {0, math.ceil(wait)}
end
"""


@dataclass(frozen=True)
class BucketDecision:
    """Result of evaluating both buckets for one `acquire()` attempt."""

    allowed: bool
    wait_seconds: float
    rpm_tokens_remaining: Optional[float] = None
    tpm_tokens_remaining: Optional[float] = None


def evaluate_dual_bucket(
    *,
    rpm_tokens: Optional[float],
    rpm_last_update: Optional[float],
    max_rpm: float,
    rpm_refill_rate: float,
    rpm_cost: float,
    tpm_tokens: Optional[float],
    tpm_last_update: Optional[float],
    max_tpm: float,
    tpm_refill_rate: float,
    tpm_cost: float,
    now: float,
) -> BucketDecision:
    """Pure-Python mirror of `DUAL_TOKEN_BUCKET_LUA`.

    This is not a fallback implementation invoked at runtime -- in
    production the Lua script above runs server-side inside Redis, which
    is what actually gives the check-and-debit its atomicity across
    concurrent workers. This function exists so that exact algorithm can
    be hard-tested with plain Python values (including deliberately
    adversarial edge cases: zero elapsed time, requests larger than
    capacity, exact-boundary requests, saturated buckets) without a Redis
    server or a Lua interpreter, neither of which is available in every
    environment this code is developed and tested in. It is kept in
    lock-step, line-for-line, with the Lua text above; the offline test
    double in the test suite calls this same function when it detects the
    `CYBERJECTION_DUAL_TOKEN_BUCKET_V1` script via `EVALSHA`, so the same
    code path that's unit-tested here is also what offline integration
    tests exercise.
    """

    def refill(tokens: Optional[float], last_update: Optional[float], max_tokens: float, rate: float) -> float:
        if tokens is None:
            return max_tokens
        delta = max(0.0, now - (last_update or now))
        return min(max_tokens, tokens + delta * rate)

    rpm_available = refill(rpm_tokens, rpm_last_update, max_rpm, rpm_refill_rate)
    tpm_available = refill(tpm_tokens, tpm_last_update, max_tpm, tpm_refill_rate)

    if rpm_available >= rpm_cost and tpm_available >= tpm_cost:
        return BucketDecision(
            allowed=True,
            wait_seconds=0.0,
            rpm_tokens_remaining=rpm_available - rpm_cost,
            tpm_tokens_remaining=tpm_available - tpm_cost,
        )

    rpm_wait = max(0.0, (rpm_cost - rpm_available) / rpm_refill_rate) if rpm_available < rpm_cost else 0.0
    tpm_wait = max(0.0, (tpm_cost - tpm_available) / tpm_refill_rate) if tpm_available < tpm_cost else 0.0
    import math

    return BucketDecision(allowed=False, wait_seconds=math.ceil(max(rpm_wait, tpm_wait)))


class DistributedRateLimiter:
    """Atomic Redis-backed RPM + TPM limiter shared across worker processes.

    One instance is scoped to a single `provider_id` (e.g. a target's
    provider name); every worker process constructing a limiter for the
    same `provider_id` against the same Redis instance reads and writes
    the same bucket state, so the configured RPM/TPM ceiling applies to
    the provider as a whole rather than per worker.
    """

    def __init__(
        self,
        redis_url: str,
        provider_id: str,
        max_rpm: int = 60,
        max_tpm: int = 90_000,
    ) -> None:
        if aioredis is None:  # pragma: no cover - exercised only when redis truly absent
            raise ImportError(
                "The 'redis' package is required for DistributedRateLimiter. "
                "Install it with `pip install redis` (see pyproject.toml)."
            )
        if max_rpm <= 0 or max_tpm <= 0:
            raise ValueError("max_rpm and max_tpm must both be positive")

        self.redis = aioredis.from_url(redis_url, decode_responses=True)
        self.provider_id = provider_id
        self.max_rpm = max_rpm
        self.max_tpm = max_tpm
        self.rpm_refill_rate = max_rpm / 60.0
        self.tpm_refill_rate = max_tpm / 60.0
        self.rpm_key = f"cyberjection:rate_limit:{provider_id}:rpm"
        self.tpm_key = f"cyberjection:rate_limit:{provider_id}:tpm"
        self._script_sha: Optional[str] = None

    async def acquire(self, request_cost: int = 1, token_cost: int = 0) -> None:
        """Blocks until `request_cost` RPM units and `token_cost` TPM units
        are both available, then debits both atomically.

        `token_cost` defaults to 0 (skip TPM enforcement) because the
        exact token cost of an LLM call is often only known *after* the
        response arrives (prompt tokens are knowable up front, but
        completion tokens are not). Callers that know an estimate (e.g.
        a configured `max_tokens` request parameter) should pass it as a
        conservative pre-flight check; reconciling the estimate against
        the real post-response usage is a coordination concern for
        whatever later phase wires this limiter into the provider
        adapters, and isn't solved by the limiter itself.
        """

        if request_cost > self.max_rpm:
            raise RateLimitCapacityExceededError(
                f"requested {request_cost} RPM units but bucket capacity is only "
                f"{self.max_rpm}; this request can never be admitted",
                target_id=self.provider_id,
            )
        if token_cost > self.max_tpm:
            raise RateLimitCapacityExceededError(
                f"requested {token_cost} TPM units but bucket capacity is only "
                f"{self.max_tpm}; this request can never be admitted",
                target_id=self.provider_id,
            )

        if self._script_sha is None:
            self._script_sha = await self.redis.script_load(DUAL_TOKEN_BUCKET_LUA)
            expected = hashlib.sha1(DUAL_TOKEN_BUCKET_LUA.encode("utf-8")).hexdigest()
            # redis-py's script_load already returns the server's own
            # SHA1 of the script body; this assertion just documents (and
            # would catch, if it ever regressed) that the client-side
            # constant above matches what the server actually hashed.
            assert self._script_sha == expected, "script SHA mismatch: DUAL_TOKEN_BUCKET_LUA text changed?"

        while True:
            now = time.time()
            result = await self.redis.evalsha(
                self._script_sha,
                2,
                self.rpm_key,
                self.tpm_key,
                self.max_rpm,
                self.rpm_refill_rate,
                request_cost,
                self.max_tpm,
                self.tpm_refill_rate,
                token_cost,
                now,
            )
            allowed, detail = result[0], result[1]
            if int(allowed) == 1:
                return
            await self._sleep(max(0.1, float(detail)))

    async def _sleep(self, seconds: float) -> None:
        import asyncio

        await asyncio.sleep(seconds)

    async def close(self) -> None:
        await self.redis.close()
