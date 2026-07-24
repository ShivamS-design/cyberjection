"""LiteLLM-backed universal target adapter.

Wraps `litellm.acompletion` so Cyberjection can talk to 100+ model
providers (OpenAI, Anthropic, Bedrock, Ollama, vLLM, Azure, Gemini, ...)
through one consistent async interface, with target-scoped rate limiting,
retry/backoff on transient failures, and normalized error + usage
reporting.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field

from cyberjection.config.schema import TargetConfig
from cyberjection.providers.base import BaseTarget
from cyberjection.utils.exceptions import (
    ProviderConnectionError,
    ProviderRateLimitError,
    ProviderTimeoutError,
)

# Recognized substrings used to classify provider SDK exceptions without
# taking a hard dependency on every provider's specific exception classes.
_RATE_LIMIT_MARKERS = ("rate limit", "429", "ratelimiterror")
_TIMEOUT_MARKERS = ("timeout", "timed out")


class _TokenBucketLimiter:
    """Async token-bucket limiter enforcing a steady requests/second pace.

    `asyncio.Semaphore` alone only caps *concurrency* (how many calls are
    in flight at once) - it does not cap *rate*. For fast/local targets
    (e.g. mocked responses, or low-latency Ollama endpoints) many
    concurrent coroutines can each acquire and release the semaphore
    within the same instant, producing bursts far above the configured
    `requests_per_second`. This bucket paces admission independently of
    concurrency so `RateLimitConfig.requests_per_second` is actually
    enforced, per Task 1.3 of the Phase 1 spec.
    """

    def __init__(self, rate_per_second: float, capacity: int) -> None:
        self.rate_per_second = max(rate_per_second, 0.001)
        self.capacity = max(capacity, 1)
        self._tokens = float(self.capacity)
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        while True:
            async with self._lock:
                now = time.monotonic()
                elapsed = now - self._last_refill
                self._last_refill = now
                self._tokens = min(self.capacity, self._tokens + elapsed * self.rate_per_second)
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                wait_seconds = (1.0 - self._tokens) / self.rate_per_second
            await asyncio.sleep(wait_seconds)


class UsageMetrics(BaseModel):
    """Token and latency telemetry for a single target call."""

    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    latency_ms: float = 0.0


class TargetResponse(BaseModel):
    """Normalized response returned by any `BaseTarget` implementation."""

    content: str
    raw_response: Dict[str, Any] = Field(default_factory=dict)
    metrics: UsageMetrics
    model_used: str


def _classify_exception(exc: Exception, *, target_id: str) -> Exception:
    """Map a raw litellm/provider SDK exception onto a Cyberjection type."""

    message = str(exc).lower()
    exc_type = type(exc).__name__.lower()

    if any(marker in message or marker in exc_type for marker in _RATE_LIMIT_MARKERS):
        return ProviderRateLimitError(f"Rate limited by provider: {exc}", target_id=target_id)
    if any(marker in message or marker in exc_type for marker in _TIMEOUT_MARKERS):
        return ProviderTimeoutError(f"Target call timed out: {exc}", target_id=target_id)
    return ProviderConnectionError(f"Target provider call failed: {exc}", target_id=target_id)


class LiteLLMTarget(BaseTarget):
    """Universal LiteLLM adapter for target model communication."""

    def __init__(
        self,
        config: TargetConfig,
        *,
        max_retries: int = 3,
        backoff_base_seconds: float = 0.5,
    ) -> None:
        self.config = config
        self.max_retries = max_retries
        self.backoff_base_seconds = backoff_base_seconds
        self._semaphore = asyncio.Semaphore(config.rate_limit.burst)
        self._rate_limiter = _TokenBucketLimiter(
            rate_per_second=config.rate_limit.requests_per_second,
            capacity=config.rate_limit.burst,
        )

    async def generate(
        self,
        prompt: str,
        system_prompt_override: Optional[str] = None,
    ) -> TargetResponse:
        """Send a prompt to the configured target and return a `TargetResponse`.

        Applies target-scoped rate limiting (token bucket paced to
        `requests_per_second`, capped at `burst` concurrent slots via a
        semaphore) and retries transient rate-limit / connection failures
        with exponential backoff before giving up.
        """

        system_prompt = system_prompt_override or self.config.system_prompt
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        await self._rate_limiter.acquire()
        async with self._semaphore:
            return await self._call_with_retry(messages)

    async def generate_conversation(self, messages: list[dict[str, str]]) -> TargetResponse:
        """Send a full multi-turn message history to the configured target
        as-is, rather than building a single system+user pair the way
        :meth:`generate` does.

        Added for Phase 5's stateful multi-turn attack engines
        (`CrescendoEngine`, `TAPEngine`), which own and grow their own
        conversation history turn by turn and need to replay the whole
        thing to the target on every call. Applies the exact same
        target-scoped rate limiting and retry/backoff as :meth:`generate`,
        so multi-turn attack traffic is governed by the same
        `requests_per_second` / `burst` / retry policy as single-turn
        traffic against the same target -- there is no separate, weaker
        code path for multi-turn calls.
        """

        await self._rate_limiter.acquire()
        async with self._semaphore:
            return await self._call_with_retry(messages)

    async def _call_with_retry(self, messages: list[dict[str, str]]) -> TargetResponse:
        from litellm import acompletion  # imported lazily so Phase 1 tests can mock it cheaply

        for attempt in range(self.max_retries + 1):
            start_time = time.perf_counter()
            try:
                api_key_str = (
                    self.config.api_key.get_secret_value() if self.config.api_key else None
                )
                response = await acompletion(
                    model=f"{self.config.provider.value}/{self.config.model}",
                    messages=messages,
                    temperature=self.config.temperature,
                    max_tokens=self.config.max_tokens,
                    api_key=api_key_str,
                    api_base=self.config.api_base,
                    extra_headers=self.config.custom_headers,
                )
            except Exception as exc:  # noqa: BLE001 - normalized below
                classified = _classify_exception(exc, target_id=self.config.id)
                # Connection errors are treated as non-transient and fail fast.
                # Rate-limit / timeout errors are retried with exponential backoff.
                if isinstance(classified, ProviderConnectionError) or attempt == self.max_retries:
                    raise classified
                await asyncio.sleep(self.backoff_base_seconds * (2**attempt))
                continue

            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return self._to_target_response(response, elapsed_ms)

        # Unreachable: the loop above always either returns or raises.
        raise ProviderConnectionError("Exhausted retries with no response.", target_id=self.config.id)

    def _to_target_response(self, response: Any, elapsed_ms: float) -> TargetResponse:
        content = response.choices[0].message.content or ""
        usage = getattr(response, "usage", None)
        metrics = UsageMetrics(
            prompt_tokens=getattr(usage, "prompt_tokens", 0) or 0,
            completion_tokens=getattr(usage, "completion_tokens", 0) or 0,
            total_tokens=getattr(usage, "total_tokens", 0) or 0,
            latency_ms=elapsed_ms,
        )
        raw_response: Dict[str, Any]
        if hasattr(response, "model_dump"):
            raw_response = response.model_dump()
        elif hasattr(response, "to_dict"):
            raw_response = response.to_dict()
        else:
            raw_response = {}

        return TargetResponse(
            content=content,
            raw_response=raw_response,
            metrics=metrics,
            model_used=getattr(response, "model", self.config.model),
        )
