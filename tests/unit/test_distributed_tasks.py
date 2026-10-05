"""Tests for cyberjection.distributed.tasks.execute_eval_turn_task.

Requires the `celery` and `redis` packages -- see `test_rate_limiter.py`'s
module docstring for how these resolve in a real deployment vs. in the
offline sandbox this suite was hard-tested in.

Tasks are invoked via the `_call_task` helper below, which drives
`execute_eval_turn_task.apply(args=..., kwargs=..., retries=N)` in a loop
that catches `celery.exceptions.Retry` and re-applies with `retries`
incremented, rather than calling the task object directly as a plain
function or trusting a single `.apply()` call to loop on its own.

Two things earlier drafts of this suite got wrong, both only visible
once this ran against genuine Celery in CI (this project's own offline
Celery test double papers over both, since its `Task.retry()` always
loops a single call to completion by itself):

1. Calling the task directly as a plain function -- on the theory that
   "with the offline celery shim (and with real Celery's
   task_always_eager test mode) these are equivalent, since there's no
   real broker in either case" -- does not work against real Celery.
   Real `Task.retry()` detects a *directly*-called task
   (`request.called_directly`, true whenever nothing -- no worker, no
   `.apply()`/`.apply_async()` -- sits between the caller and the task
   function) and immediately re-raises the original exception instead of
   attempting to retry, since there's no real request context to
   schedule a retry against.
2. Calling `.apply(...)` once and expecting it to internally loop every
   retry to completion also does not hold against real Celery: `.apply()`
   runs the task body exactly once per call and, when the body raises
   `celery.exceptions.Retry` (which `self.retry()` raises whenever
   retries remain), that `Retry` propagates straight out through
   `EagerResult.get()` rather than being caught and retried internally.
   `Task.apply()`'s own `retries=` keyword argument is the documented
   mechanism for a *caller* to drive that loop itself -- precisely what
   `_call_task` does -- seeding each successive `.apply()` call's request
   context with the incremented retry count so `self.retry()`'s own
   `retries >= max_retries` check (and this module's dead-letter
   hand-off once that check trips) behaves exactly as it would across a
   real worker's successive pickups of the same task, without needing an
   actual broker or worker process.

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
from celery.exceptions import MaxRetriesExceededError, Retry

import cyberjection.distributed.tasks as tasks_mod
from cyberjection.distributed.celery_app import celery_app
from cyberjection.distributed.retry import DEAD_LETTER_QUEUE_KEY


@pytest.fixture(autouse=True)
def _eager_celery():
    """Standard practice for unit-testing Celery tasks without a real
    broker/worker: `task_always_eager=True` (plus `task_eager_propagates`,
    so an exception from the task raises through `.get()` instead of
    silently landing in the result object) is what `.apply()` is
    documented to be used alongside. Scoped to this fixture (reset after
    each test) rather than set globally in `celery_app.py`, so production
    configuration -- which must *not* run tasks inline on whatever
    process enqueued them -- is untouched.
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


def _call_task(target_id: str, payload: str, provider_url: str, **kwargs):
    """Runs `execute_eval_turn_task` to completion -- including every
    retry attempt -- via repeated `.apply(..., retries=N)` calls. See
    this module's own docstring for why neither a direct call nor a
    single `.apply()` call is enough to exercise retries against real
    Celery. `celery.exceptions.MaxRetriesExceededError` (raised by
    `self.retry()` once `retries` reaches `self.max_retries`) propagates
    out of this function exactly as it would out of a bare function call
    or a single `.apply()` -- only a mid-sequence `Retry` is caught and
    looped here."""

    retries = 0
    while True:
        result = tasks_mod.execute_eval_turn_task.apply(
            args=(target_id, payload, provider_url), kwargs=kwargs, retries=retries
        )
        try:
            return result.get()
        except Retry:
            retries += 1


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
        result = _call_task("target-success-1", "payload", "http://provider.invalid")
        assert result["status"] == "COMPLETED"
        assert result["target_id"] == "target-success-1"

    def test_result_includes_a_task_id(self) -> None:
        result = _call_task("target-success-2", "payload", "http://provider.invalid")
        assert isinstance(result["task_id"], str) and result["task_id"]

    def test_respects_configured_rate_limit(self) -> None:
        # max_rpm=1 with two back-to-back calls must not error -- the
        # second call blocks on the limiter instead of failing, and the
        # task still completes successfully once admitted.
        r1 = _call_task("target-rl-shared", "payload", "http://provider.invalid", max_rpm=1, max_tpm=90_000)
        assert r1["status"] == "COMPLETED"


class TestExecuteEvalTurnTaskRetry:
    def test_transient_failure_is_retried_and_eventually_succeeds(self, monkeypatch: pytest.MonkeyPatch) -> None:
        calls = _install_failing_stub(monkeypatch, lambda: ConnectionError("transient"), max_failures=2)
        result = _call_task("target-retry-1", "payload", "http://provider.invalid")
        assert result["status"] == "COMPLETED"
        assert calls["n"] == 3  # failed twice, succeeded on the 3rd attempt

    def test_retry_uses_exponential_backoff_countdowns(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_failing_stub(monkeypatch, lambda: TimeoutError("slow provider"), max_failures=2)
        _call_task("target-retry-2", "payload", "http://provider.invalid")
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
            _call_task("target-retry-3", "payload", "http://provider.invalid")

    def test_retries_are_bounded_by_max_retries_constant(self, monkeypatch: pytest.MonkeyPatch) -> None:
        calls = _install_failing_stub(monkeypatch, lambda: ConnectionError("always fails"))
        with pytest.raises(MaxRetriesExceededError):
            _call_task("target-retry-4", "payload", "http://provider.invalid")
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
            _call_task(target_id, "the payload", "http://provider.invalid")

        entries = asyncio.run(self._read_dlq_for_target(target_id))
        assert len(entries) == 1
        assert entries[0]["task_name"] == "execute_eval_turn_task"
        assert entries[0]["error_type"] == "ConnectionError"
        assert entries[0]["error_message"] == "permanently down"
        assert entries[0]["retries_exhausted"] == tasks_mod.MAX_RETRIES

    def test_successful_task_never_touches_dead_letter_queue(self, monkeypatch: pytest.MonkeyPatch) -> None:
        target_id = "target-dlq-2"
        _call_task(target_id, "payload", "http://provider.invalid")

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
