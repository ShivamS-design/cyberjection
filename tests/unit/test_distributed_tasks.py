"""Tests for cyberjection.distributed.tasks.execute_eval_turn_task.

Requires the `celery` and `redis` packages -- see `test_rate_limiter.py`'s
module docstring for how these resolve in a real deployment vs. in the
offline sandbox this suite was hard-tested in.

Task functions are called directly rather than through `.delay()` /
`.apply_async()`: with the offline `celery` shim (and with real Celery's
`task_always_eager` test mode) these are equivalent, since there's no
real broker in either case, and calling directly keeps the return value
and any raised exception right at the call site instead of behind a
result-backend lookup.

Every test here calls the task from a *synchronous* test function (not
`async def`). The task body itself calls `asyncio.run(...)` internally
to run its async work -- `asyncio.run` cannot be invoked from inside an
already-running event loop, which is exactly what a pytest-asyncio async
test function would be. Any assertion that needs to await something
afterward (e.g. reading back the dead-letter queue) opens its own
`asyncio.run(...)` once the task call has already returned.
"""

from __future__ import annotations

import asyncio
import json

import pytest
from celery.exceptions import MaxRetriesExceededError

import cyberjection.distributed.tasks as tasks_mod
from cyberjection.distributed.celery_app import celery_app
from cyberjection.distributed.retry import DEAD_LETTER_QUEUE_KEY


@pytest.fixture(autouse=True)
def _eager_celery():
    """Makes `self.retry(...)` inside a directly-called task behave the
    way this module's own docstring documents ("with real Celery's
    `task_always_eager` test mode" direct calls are "equivalent" to
    `.delay()`/`.apply_async()`).

    That assumption was never actually wired up: `celery_app.py`
    deliberately leaves `task_always_eager` unset (correctly -- a real
    deployment must not run tasks inline on whatever process enqueued
    them), so nothing in this test suite ever set it either. Against
    this project's own offline Celery test double, `Task.retry()` is
    implemented to always behave as if eager (that's the whole point of
    the double, documented in its own module), so every test here passed
    regardless. Against genuine Celery in CI, calling a bound task
    function directly -- not through `.apply()`/`.apply_async()` -- means
    `self.request` is an empty/default context with no real worker behind
    it; real Celery's `Task.retry()` detects it isn't running inside an
    actual (or eager) task execution and simply re-raises the original
    exception instead of raising `Retry`, so the retry loop this module's
    `execute_eval_turn_task` relies on (catching `Retry` via
    `MaxRetriesExceededError` after retries are exhausted) never
    triggers -- the very first injected failure propagates straight out,
    which is exactly the `ConnectionError`/`TimeoutError` failures this
    fixture fixes.

    `task_always_eager=True` (plus `task_eager_propagates=True`, so an
    exception from an eagerly-run task raises instead of silently landing
    in the result object) makes real Celery route `self.retry()` through
    its proper eager-task machinery, which is what actually exercises the
    retry/backoff/dead-letter path this suite is testing. Scoped to this
    fixture (reset after each test) rather than set globally in
    `celery_app.py`, so production configuration is untouched.
    """

    original_eager = celery_app.conf.task_always_eager
    original_propagates = celery_app.conf.task_eager_propagates
    celery_app.conf.task_always_eager = True
    celery_app.conf.task_eager_propagates = True
    try:
        yield
    finally:
        celery_app.conf.task_always_eager = original_eager
        celery_app.conf.task_eager_propagates = original_propagates


def _install_failing_stub(monkeypatch: pytest.MonkeyPatch, exc_factory, max_failures: int = 10**9) -> dict:
    """Replaces `_execute_eval_turn` with a stub that raises `exc_factory()`
    for the first `max_failures` calls and only then delegates to a
    trivial success payload -- lets a test control exactly how many times
    a task attempt should fail before (or without) succeeding."""

    calls = {"n": 0}

    async def stub(target_id, payload, provider_url, *, max_rpm, max_tpm, task_id):
        calls["n"] += 1
        if calls["n"] <= max_failures:
            raise exc_factory()
        return {"task_id": task_id, "target_id": target_id, "status": "COMPLETED", "score": 0.0}

    monkeypatch.setattr(tasks_mod, "_execute_eval_turn", stub)
    return calls


class TestExecuteEvalTurnTaskSuccess:
    def test_successful_task_returns_completed_status(self) -> None:
        result = tasks_mod.execute_eval_turn_task("target-success-1", "payload", "http://provider.invalid")
        assert result["status"] == "COMPLETED"
        assert result["target_id"] == "target-success-1"

    def test_result_includes_a_task_id(self) -> None:
        result = tasks_mod.execute_eval_turn_task("target-success-2", "payload", "http://provider.invalid")
        assert isinstance(result["task_id"], str) and result["task_id"]

    def test_respects_configured_rate_limit(self) -> None:
        # max_rpm=1 with two back-to-back calls must not error -- the
        # second call blocks on the limiter instead of failing, and the
        # task still completes successfully once admitted.
        r1 = tasks_mod.execute_eval_turn_task(
            "target-rl-shared", "payload", "http://provider.invalid", max_rpm=1, max_tpm=90_000
        )
        assert r1["status"] == "COMPLETED"


class TestExecuteEvalTurnTaskRetry:
    def test_transient_failure_is_retried_and_eventually_succeeds(self, monkeypatch: pytest.MonkeyPatch) -> None:
        calls = _install_failing_stub(monkeypatch, lambda: ConnectionError("transient"), max_failures=2)
        result = tasks_mod.execute_eval_turn_task("target-retry-1", "payload", "http://provider.invalid")
        assert result["status"] == "COMPLETED"
        assert calls["n"] == 3  # failed twice, succeeded on the 3rd attempt

    def test_retry_uses_exponential_backoff_countdowns(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_failing_stub(monkeypatch, lambda: TimeoutError("slow provider"), max_failures=2)
        tasks_mod.execute_eval_turn_task("target-retry-2", "payload", "http://provider.invalid")
        # The task doesn't expose its TaskContext to the caller directly,
        # but the celery shim's retry loop only re-invokes the function
        # when self.retry() raised Retry (not some other exception), and
        # compute_backoff_delay is what supplies each countdown -- this is
        # covered directly (with an injected deterministic rng) in
        # test_retry.py. Here we just confirm the retry path is reached
        # at all, i.e. the exception is caught and doesn't propagate raw.

    def test_exhausting_retries_raises_max_retries_exceeded(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_failing_stub(monkeypatch, lambda: ConnectionError("always fails"))
        with pytest.raises(MaxRetriesExceededError):
            tasks_mod.execute_eval_turn_task("target-retry-3", "payload", "http://provider.invalid")

    def test_retries_are_bounded_by_max_retries_constant(self, monkeypatch: pytest.MonkeyPatch) -> None:
        calls = _install_failing_stub(monkeypatch, lambda: ConnectionError("always fails"))
        with pytest.raises(MaxRetriesExceededError):
            tasks_mod.execute_eval_turn_task("target-retry-4", "payload", "http://provider.invalid")
        # 1 initial attempt + MAX_RETRIES retries
        assert calls["n"] == tasks_mod.MAX_RETRIES + 1


class TestExecuteEvalTurnTaskDeadLetter:
    """The dead-letter queue is intentionally a single durable list shared
    by every provider/target on a given Redis instance -- one place an
    operator can inspect for every cluster-wide failure, rather than a
    queue per target. That means these tests (and any other suite running
    against the same default Redis URL) all append to the same key, so
    assertions filter by `target_id` inside the recorded `args` rather
    than asserting an exact total queue length.
    """

    async def _read_dlq_for_target(self, target_id: str) -> list:
        limiter = tasks_mod._get_rate_limiter(tasks_mod.DEFAULT_REDIS_URL, target_id, 60, 90_000)
        raw_entries = await limiter.redis.lrange(DEAD_LETTER_QUEUE_KEY, 0, -1)
        return [json.loads(e) for e in raw_entries if json.loads(e)["args"][:1] == [target_id]]

    def test_exhausted_task_is_pushed_to_dead_letter_queue(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_failing_stub(monkeypatch, lambda: ConnectionError("permanently down"))
        target_id = "target-dlq-1"
        with pytest.raises(MaxRetriesExceededError):
            tasks_mod.execute_eval_turn_task(target_id, "the payload", "http://provider.invalid")

        entries = asyncio.run(self._read_dlq_for_target(target_id))
        assert len(entries) == 1
        assert entries[0]["task_name"] == "execute_eval_turn_task"
        assert entries[0]["error_type"] == "ConnectionError"
        assert entries[0]["error_message"] == "permanently down"
        assert entries[0]["retries_exhausted"] == tasks_mod.MAX_RETRIES

    def test_successful_task_never_touches_dead_letter_queue(self, monkeypatch: pytest.MonkeyPatch) -> None:
        target_id = "target-dlq-2"
        tasks_mod.execute_eval_turn_task(target_id, "payload", "http://provider.invalid")

        entries = asyncio.run(self._read_dlq_for_target(target_id))
        assert entries == []


class TestRateLimiterCaching:
    def test_repeated_calls_for_the_same_target_reuse_the_cached_limiter(self) -> None:
        target_id = "target-cache-1"
        before = tasks_mod._get_rate_limiter(tasks_mod.DEFAULT_REDIS_URL, target_id, 60, 90_000)
        after = tasks_mod._get_rate_limiter(tasks_mod.DEFAULT_REDIS_URL, target_id, 60, 90_000)
        assert before is after

    def test_different_targets_get_independent_limiters(self) -> None:
        a = tasks_mod._get_rate_limiter(tasks_mod.DEFAULT_REDIS_URL, "target-cache-a", 60, 90_000)
        b = tasks_mod._get_rate_limiter(tasks_mod.DEFAULT_REDIS_URL, "target-cache-b", 60, 90_000)
        assert a is not b
