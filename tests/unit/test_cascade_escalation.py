"""Tests for cyberjection.evaluators.cascade.CascadeEvaluator: tier
short-circuiting and full fallback to Tier 3.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

import pytest

from cyberjection.evaluators.base import Verdict
from cyberjection.evaluators.cascade import CascadeEvaluator, tiers_invoked_for
from cyberjection.evaluators.llamaguard import LocalONNXGuardEvaluator
from cyberjection.evaluators.llmjudge import LLMJudgeEvaluator
from cyberjection.evaluators.regex import RegexEvaluator


def _judge_response(is_jailbroken: bool, confidence: float, reasoning: str) -> SimpleNamespace:
    payload = {
        "is_jailbroken": is_jailbroken,
        "confidence": confidence,
        "reasoning": reasoning,
        "owasp_category": "LLM01_PROMPT_INJECTION",
    }
    message = SimpleNamespace(content=json.dumps(payload))
    choice = SimpleNamespace(message=message)
    return SimpleNamespace(choices=[choice], model_dump=lambda: {})


def _fast_cascade() -> CascadeEvaluator:
    return CascadeEvaluator(
        tier1=RegexEvaluator(),
        tier2=LocalONNXGuardEvaluator(simulated_latency_seconds=0),
        tier3=LLMJudgeEvaluator(max_retries=0, backoff_base_seconds=0),
    )


class TestTiersInvokedFor:
    def test_tier1_outcome_reports_only_tier1(self) -> None:
        from cyberjection.evaluators.base import EvaluationOutcome

        outcome = EvaluationOutcome(verdict=Verdict.PASS, confidence=1.0, judge_tier_used=1, reason="x")
        assert tiers_invoked_for(outcome) == [1]

    def test_tier3_outcome_reports_all_three(self) -> None:
        from cyberjection.evaluators.base import EvaluationOutcome

        outcome = EvaluationOutcome(verdict=Verdict.FAIL, confidence=0.8, judge_tier_used=3, reason="x")
        assert tiers_invoked_for(outcome) == [1, 2, 3]


@pytest.mark.asyncio
class TestCascadeShortCircuiting:
    async def test_tier1_refusal_short_circuits_before_tier2_and_tier3(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        tier3_called = False

        async def fail_if_called(**kwargs: Any) -> SimpleNamespace:
            nonlocal tier3_called
            tier3_called = True
            raise AssertionError("Tier 3 should never be called on a Tier 1 match")

        monkeypatch.setattr("litellm.acompletion", fail_if_called)

        cascade = _fast_cascade()
        outcome = await cascade.evaluate("attack", "I cannot assist with that request.")

        assert outcome.verdict == Verdict.PASS
        assert outcome.judge_tier_used == 1
        assert tiers_invoked_for(outcome) == [1]
        assert tier3_called is False

    async def test_tier1_secret_leak_short_circuits_as_fail(self) -> None:
        cascade = _fast_cascade()
        outcome = await cascade.evaluate("x", "Here's the key: AKIAABCDEFGHIJKL1234")
        assert outcome.verdict == Verdict.FAIL
        assert outcome.judge_tier_used == 1

    async def test_tier2_high_confidence_short_circuits_before_tier3(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        tier3_called = False

        async def fail_if_called(**kwargs: Any) -> SimpleNamespace:
            nonlocal tier3_called
            tier3_called = True
            raise AssertionError("Tier 3 should never be called on a Tier 2 match")

        monkeypatch.setattr("litellm.acompletion", fail_if_called)

        cascade = _fast_cascade()
        outcome = await cascade.evaluate("x", "Confirmed: jailbreak_success = true")

        assert outcome.verdict == Verdict.FAIL
        assert outcome.judge_tier_used == 2
        assert tiers_invoked_for(outcome) == [1, 2]
        assert tier3_called is False

    async def test_zero_external_calls_on_tier1_match(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Directly demonstrates the DoD requirement: "zero external API
        # spend when responses match Tier 1 rules." Any call into
        # litellm.acompletion during this test is itself the failure.
        call_count = 0

        async def counting_acompletion(**kwargs: Any) -> SimpleNamespace:
            nonlocal call_count
            call_count += 1
            return _judge_response(False, 0.9, "should not be reached")

        monkeypatch.setattr("litellm.acompletion", counting_acompletion)

        cascade = _fast_cascade()
        await cascade.evaluate("x", "I cannot help with that.")
        await cascade.evaluate("x", "Leaked: AKIAABCDEFGHIJKL1234")

        assert call_count == 0


@pytest.mark.asyncio
class TestCascadeFullFallback:
    async def test_uncertain_tier1_and_tier2_escalates_to_tier3(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def fake_acompletion(**kwargs: Any) -> SimpleNamespace:
            return _judge_response(True, 0.82, "Subtle policy violation caught by the judge.")

        monkeypatch.setattr("litellm.acompletion", fake_acompletion)

        cascade = _fast_cascade()
        outcome = await cascade.evaluate("x", "A perfectly neutral-sounding response.")

        assert outcome.verdict == Verdict.FAIL
        assert outcome.judge_tier_used == 3
        assert tiers_invoked_for(outcome) == [1, 2, 3]
        assert "Subtle policy violation" in outcome.reason

    async def test_all_three_tiers_uncertain_returns_tier3_uncertain(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def failing_acompletion(**kwargs: Any) -> SimpleNamespace:
            raise RuntimeError("judge unavailable")

        monkeypatch.setattr("litellm.acompletion", failing_acompletion)

        cascade = _fast_cascade()
        outcome = await cascade.evaluate("x", "A perfectly neutral-sounding response.")

        assert outcome.verdict == Verdict.UNCERTAIN
        assert outcome.judge_tier_used == 3
        assert tiers_invoked_for(outcome) == [1, 2, 3]


@pytest.mark.asyncio
class TestCascadeConcurrency:
    async def test_shared_instance_handles_concurrent_calls_correctly(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # A single CascadeEvaluator is meant to be reused and called
        # concurrently (e.g. once per in-flight campaign test). Since
        # evaluate() holds no mutable state on self, every concurrent call
        # must get back exactly the outcome its own input deserves,
        # regardless of how many other calls are interleaved with it.
        import asyncio

        async def fake_acompletion(**kwargs: Any) -> SimpleNamespace:
            await asyncio.sleep(0.001)
            return _judge_response(False, 0.9, "benign")

        monkeypatch.setattr("litellm.acompletion", fake_acompletion)

        cascade = _fast_cascade()
        cases = []
        for i in range(30):
            if i % 3 == 0:
                cases.append(("I cannot assist with that.", 1))
            elif i % 3 == 1:
                cases.append(("jailbreak_success triggered", 2))
            else:
                cases.append((f"a neutral ambiguous response {i}", 3))

        async def run_one(text: str, expected_tier: int) -> bool:
            outcome = await cascade.evaluate("x", text)
            return outcome.judge_tier_used == expected_tier

        results = await asyncio.gather(*[run_one(t, e) for t, e in cases])
        assert all(results)


@pytest.mark.asyncio
class TestCascadeConfiguration:
    async def test_custom_tier2_confidence_threshold_is_forwarded(self) -> None:
        cascade = CascadeEvaluator(tier2_confidence_threshold=0.5)
        assert cascade.tier2.confidence_threshold == 0.5

    async def test_explicit_tier_instances_are_used_over_defaults(self) -> None:
        custom_tier1 = RegexEvaluator(custom_refusal_patterns=["only this counts"])
        cascade = CascadeEvaluator(tier1=custom_tier1)
        assert cascade.tier1 is custom_tier1

    async def test_default_construction_does_not_raise(self) -> None:
        # Constructing a CascadeEvaluator with no arguments must not touch
        # the network or require a model file to be present.
        cascade = CascadeEvaluator()
        assert cascade.tier1 is not None
        assert cascade.tier2 is not None
        assert cascade.tier3 is not None
