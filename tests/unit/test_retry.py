"""Tests for cyberjection.distributed.retry: the pure exponential-backoff
formula and the dead-letter-queue payload builder. Neither needs Redis,
Celery, or any I/O, so these run identically in every environment.
"""

from __future__ import annotations

import json

import pytest

from cyberjection.distributed.retry import (
    build_dead_letter_payload,
    compute_backoff_delay,
)


class TestComputeBackoffDelay:
    def test_grows_exponentially_with_retry_count(self) -> None:
        # With jitter pinned to 0, delay is exactly base * 2**retry_count.
        assert compute_backoff_delay(0, base=1.0, jitter_max=0.0) == 1.0
        assert compute_backoff_delay(1, base=1.0, jitter_max=0.0) == 2.0
        assert compute_backoff_delay(2, base=1.0, jitter_max=0.0) == 4.0
        assert compute_backoff_delay(3, base=1.0, jitter_max=0.0) == 8.0

    def test_jitter_is_added_on_top_of_the_exponential_term(self) -> None:
        delay = compute_backoff_delay(2, base=1.0, jitter_max=1.0, rng=lambda: 0.5)
        assert delay == 4.5

    def test_cap_limits_the_total(self) -> None:
        delay = compute_backoff_delay(10, base=1.0, jitter_max=0.0, cap=30.0)
        assert delay == 30.0

    def test_default_rng_produces_values_in_expected_range(self) -> None:
        for _ in range(50):
            delay = compute_backoff_delay(0, base=1.0, jitter_max=1.0)
            assert 1.0 <= delay < 2.0

    def test_negative_retry_count_rejected(self) -> None:
        with pytest.raises(ValueError):
            compute_backoff_delay(-1)

    def test_non_positive_base_rejected(self) -> None:
        with pytest.raises(ValueError):
            compute_backoff_delay(0, base=0.0)

    def test_negative_jitter_max_rejected(self) -> None:
        with pytest.raises(ValueError):
            compute_backoff_delay(0, jitter_max=-1.0)

    def test_successive_retries_are_deterministically_increasing_without_jitter(self) -> None:
        delays = [compute_backoff_delay(n, base=0.5, jitter_max=0.0) for n in range(5)]
        assert delays == sorted(delays)
        assert delays == [0.5, 1.0, 2.0, 4.0, 8.0]


class TestBuildDeadLetterPayload:
    def test_payload_is_json_serializable(self) -> None:
        payload = build_dead_letter_payload(
            task_name="execute_eval_turn_task",
            task_id="abc-123",
            args=["target-1", "payload text", "http://example.invalid"],
            kwargs={},
            error=ConnectionError("boom"),
            retries=3,
        )
        # Must not raise -- every value in the payload has to be a plain
        # JSON-compatible type since this is what gets pushed onto the
        # Redis DLQ list as a string.
        serialized = json.dumps(payload)
        round_tripped = json.loads(serialized)
        assert round_tripped["task_name"] == "execute_eval_turn_task"
        assert round_tripped["error_type"] == "ConnectionError"
        assert round_tripped["error_message"] == "boom"
        assert round_tripped["retries_exhausted"] == 3

    def test_none_args_and_kwargs_default_to_empty(self) -> None:
        payload = build_dead_letter_payload(
            task_name="t",
            task_id="id",
            args=None,
            kwargs=None,
            error=ValueError("x"),
            retries=0,
        )
        assert payload["args"] == []
        assert payload["kwargs"] == {}

    def test_includes_a_failed_at_timestamp(self) -> None:
        payload = build_dead_letter_payload(
            task_name="t", task_id="id", args=[], kwargs={}, error=ValueError("x"), retries=1
        )
        assert isinstance(payload["failed_at"], float)
        assert payload["failed_at"] > 0
