"""Tests for cyberjection.providers.litellm_provider: mocked LiteLLM adapter.

Includes regression tests for two issues caught during concurrency review
(see cyberjection/providers/litellm_provider.py for the fix):

1. `RateLimitConfig.requests_per_second` was defined in the schema but never
   enforced -- only `burst` (concurrency) was. Fixed with `_TokenBucketLimiter`.
2. Explicit verification that cancellation (asyncio.CancelledError)
   propagates correctly rather than being misclassified as a provider error,
   and that the semaphore is always released -- on success, on failure, and
   on cancellation.
"""

from __future__ import annotations

import asyncio
import time
from types import SimpleNamespace
from typing import Any, Dict, List

import pytest

from cyberjection.config.schema import ProviderType, RateLimitConfig, TargetConfig
from cyberjection.providers.litellm_provider import LiteLLMTarget, TargetResponse
from cyberjection.utils.exceptions import (
    ProviderConnectionError,
    ProviderRateLimitError,
    ProviderTimeoutError,
)


def _fake_response(content: str = "Hello, I cannot help with that.", model: str = "gpt-4o-mini") -> SimpleNamespace:
    message = SimpleNamespace(content=content)
    choice = SimpleNamespace(message=message)
    usage = SimpleNamespace(prompt_tokens=12, completion_tokens=8, total_tokens=20)
    response = SimpleNamespace(
        choices=[choice],
        usage=usage,
        model=model,
        model_dump=lambda: {"model": model, "choices": [{"message": {"content": content}}]},
    )
    return response


def _target_config(**overrides: Any) -> TargetConfig:
    defaults: Dict[str, Any] = dict(
        id="support-agent",
        provider=ProviderType.OPENAI,
        model="gpt-4o-mini",
        api_key="sk-test",
        rate_limit=RateLimitConfig(requests_per_second=1000, burst=5),
    )
    defaults.update(overrides)
    return TargetConfig(**defaults)


@pytest.mark.asyncio
class TestLiteLLMTargetGenerate:
    async def test_successful_generate_returns_normalized_response(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def fake_acompletion(**kwargs: Any) -> SimpleNamespace:
            return _fake_response("Sure, here is the answer.")

        monkeypatch.setattr("litellm.acompletion", fake_acompletion)

        target = LiteLLMTarget(_target_config())
        response = await target.generate("What is 2+2?")

        assert isinstance(response, TargetResponse)
        assert response.content == "Sure, here is the answer."
        assert response.metrics.prompt_tokens == 12
        assert response.metrics.completion_tokens == 8
        assert response.metrics.total_tokens == 20
        assert response.metrics.latency_ms >= 0
        assert response.model_used == "gpt-4o-mini"

    async def test_system_prompt_included_when_configured(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: Dict[str, Any] = {}

        async def fake_acompletion(**kwargs: Any) -> SimpleNamespace:
            captured.update(kwargs)
            return _fake_response()

        monkeypatch.setattr("litellm.acompletion", fake_acompletion)

        target = LiteLLMTarget(_target_config(system_prompt="You are a helpful assistant."))
        await target.generate("Hi")

        messages: List[Dict[str, str]] = captured["messages"]
        assert messages[0] == {"role": "system", "content": "You are a helpful assistant."}
        assert messages[1] == {"role": "user", "content": "Hi"}

    async def test_system_prompt_override_takes_precedence(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: Dict[str, Any] = {}

        async def fake_acompletion(**kwargs: Any) -> SimpleNamespace:
            captured.update(kwargs)
            return _fake_response()

        monkeypatch.setattr("litellm.acompletion", fake_acompletion)

        target = LiteLLMTarget(_target_config(system_prompt="Default"))
        await target.generate("Hi", system_prompt_override="Overridden")

        assert captured["messages"][0]["content"] == "Overridden"

    async def test_model_string_combines_provider_and_model(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: Dict[str, Any] = {}

        async def fake_acompletion(**kwargs: Any) -> SimpleNamespace:
            captured.update(kwargs)
            return _fake_response()

        monkeypatch.setattr("litellm.acompletion", fake_acompletion)

        target = LiteLLMTarget(_target_config(provider=ProviderType.ANTHROPIC, model="claude-3-5-sonnet"))
        await target.generate("Hi")

        assert captured["model"] == "anthropic/claude-3-5-sonnet"

    async def test_connection_error_raises_immediately_without_retry(self, monkeypatch: pytest.MonkeyPatch) -> None:
        call_count = 0

        async def fake_acompletion(**kwargs: Any) -> SimpleNamespace:
            nonlocal call_count
            call_count += 1
            raise RuntimeError("connection refused")

        monkeypatch.setattr("litellm.acompletion", fake_acompletion)

        target = LiteLLMTarget(_target_config(), backoff_base_seconds=0.001)
        with pytest.raises(ProviderConnectionError):
            await target.generate("Hi")
        assert call_count == 1

    async def test_rate_limit_error_retries_then_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        call_count = 0

        async def fake_acompletion(**kwargs: Any) -> SimpleNamespace:
            nonlocal call_count
            call_count += 1
            raise RuntimeError("429 rate limit exceeded")

        monkeypatch.setattr("litellm.acompletion", fake_acompletion)

        target = LiteLLMTarget(_target_config(), max_retries=2, backoff_base_seconds=0.001)
        with pytest.raises(ProviderRateLimitError):
            await target.generate("Hi")
        assert call_count == 3  # initial attempt + 2 retries

    async def test_rate_limit_error_succeeds_after_transient_failure(self, monkeypatch: pytest.MonkeyPatch) -> None:
        call_count = 0

        async def fake_acompletion(**kwargs: Any) -> SimpleNamespace:
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise RuntimeError("429 rate limit exceeded")
            return _fake_response("Recovered")

        monkeypatch.setattr("litellm.acompletion", fake_acompletion)

        target = LiteLLMTarget(_target_config(), max_retries=3, backoff_base_seconds=0.001)
        response = await target.generate("Hi")
        assert response.content == "Recovered"
        assert call_count == 2

    async def test_timeout_error_classified_correctly(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def fake_acompletion(**kwargs: Any) -> SimpleNamespace:
            raise TimeoutError("request timed out")

        monkeypatch.setattr("litellm.acompletion", fake_acompletion)

        target = LiteLLMTarget(_target_config(), max_retries=0, backoff_base_seconds=0.001)
        with pytest.raises(ProviderTimeoutError):
            await target.generate("Hi")

    async def test_semaphore_limits_concurrent_calls(self, monkeypatch: pytest.MonkeyPatch) -> None:
        in_flight = 0
        max_in_flight = 0

        async def fake_acompletion(**kwargs: Any) -> SimpleNamespace:
            nonlocal in_flight, max_in_flight
            in_flight += 1
            max_in_flight = max(max_in_flight, in_flight)
            await asyncio.sleep(0.01)
            in_flight -= 1
            return _fake_response()

        monkeypatch.setattr("litellm.acompletion", fake_acompletion)

        target = LiteLLMTarget(_target_config(rate_limit=RateLimitConfig(requests_per_second=1000, burst=2)))
        await asyncio.gather(*(target.generate(f"prompt {i}") for i in range(6)))

        assert max_in_flight <= 2

    async def test_semaphore_released_after_mixed_success_and_failure(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Semaphore permits must return to full capacity whether a call
        succeeds or raises -- `async with` guarantees release, but this
        verifies it empirically across a batch of failures, not just one."""

        call_n = 0

        async def flaky(**kwargs: Any) -> SimpleNamespace:
            nonlocal call_n
            call_n += 1
            if call_n % 2 == 0:
                raise RuntimeError("connection refused")
            return _fake_response()

        monkeypatch.setattr("litellm.acompletion", flaky)

        target = LiteLLMTarget(
            _target_config(rate_limit=RateLimitConfig(requests_per_second=1000, burst=4)), max_retries=0
        )
        results = await asyncio.gather(
            *(target.generate(f"p{i}") for i in range(10)), return_exceptions=True
        )

        successes = [r for r in results if isinstance(r, TargetResponse)]
        failures = [r for r in results if isinstance(r, BaseException)]
        assert len(successes) + len(failures) == 10
        assert all(isinstance(f, ProviderConnectionError) for f in failures)
        assert target._semaphore._value == 4

    async def test_cancellation_propagates_and_releases_semaphore(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """`except Exception` in `_call_with_retry` must NOT swallow
        `asyncio.CancelledError` (a BaseException subclass since Python
        3.8) -- otherwise cancelling a caller would surface as a misleading
        ProviderConnectionError instead of propagating cancellation."""

        started = asyncio.Event()

        async def hang(**kwargs: Any) -> SimpleNamespace:
            started.set()
            await asyncio.sleep(10)
            return _fake_response()

        monkeypatch.setattr("litellm.acompletion", hang)

        target = LiteLLMTarget(_target_config())
        task = asyncio.create_task(target.generate("hi"))
        await started.wait()
        task.cancel()

        with pytest.raises(asyncio.CancelledError):
            await task

        assert target._semaphore._value == target.config.rate_limit.burst


@pytest.mark.asyncio
class TestTokenBucketRateLimiting:
    """Regression coverage for the requests_per_second enforcement gap
    found during concurrency review: previously only `burst` (concurrency)
    was enforced via the semaphore, so fast/local targets could blow well
    past the configured requests-per-second pace."""

    async def test_rate_limiter_paces_requests_beyond_burst(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def instant(**kwargs: Any) -> SimpleNamespace:
            return _fake_response()

        monkeypatch.setattr("litellm.acompletion", instant)

        target = LiteLLMTarget(_target_config(rate_limit=RateLimitConfig(requests_per_second=10, burst=5)))
        start = time.monotonic()
        await asyncio.gather(*(target.generate(f"p{i}") for i in range(20)))
        elapsed = time.monotonic() - start

        # 20 requests, burst of 5 free, remaining 15 paced at 10/s => >= ~1.2s (20% slack for jitter)
        expected_min = (20 - 5) / 10 * 0.8
        assert elapsed >= expected_min

    async def test_burst_allows_immediate_initial_requests(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def instant(**kwargs: Any) -> SimpleNamespace:
            return _fake_response()

        monkeypatch.setattr("litellm.acompletion", instant)

        target = LiteLLMTarget(_target_config(rate_limit=RateLimitConfig(requests_per_second=1, burst=5)))
        start = time.monotonic()
        await asyncio.gather(*(target.generate(f"p{i}") for i in range(5)))
        elapsed = time.monotonic() - start

        assert elapsed < 0.5


class TestResponseEdgeCases:
    """Defensive handling of provider responses that don't match the
    happy-path shape (missing usage, null content)."""

    @pytest.mark.asyncio
    async def test_missing_usage_defaults_to_zero(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def no_usage(**kwargs: Any) -> SimpleNamespace:
            message = SimpleNamespace(content="ok")
            choice = SimpleNamespace(message=message)
            return SimpleNamespace(choices=[choice], usage=None, model="m", model_dump=lambda: {})

        monkeypatch.setattr("litellm.acompletion", no_usage)

        target = LiteLLMTarget(_target_config())
        response = await target.generate("hi")
        assert response.metrics.prompt_tokens == 0
        assert response.metrics.completion_tokens == 0
        assert response.metrics.total_tokens == 0

    @pytest.mark.asyncio
    async def test_none_content_becomes_empty_string(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def none_content(**kwargs: Any) -> SimpleNamespace:
            return _fake_response(content=None)  # type: ignore[arg-type]

        monkeypatch.setattr("litellm.acompletion", none_content)

        target = LiteLLMTarget(_target_config())
        response = await target.generate("hi")
        assert response.content == ""
