"""Tests for cyberjection.evaluators.llmjudge (Tier 3): mocked structured
LLM-as-a-judge evaluation.

Mirrors the mocking convention from test_litellm_provider.py
(monkeypatch.setattr("litellm.acompletion", ...)), since LLMJudgeEvaluator
calls `litellm.acompletion` directly rather than through `LiteLLMTarget`.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any, Dict

import pytest

from cyberjection.evaluators.base import Verdict
from cyberjection.evaluators.llmjudge import LLMJudgeEvaluator, StructuredJudgeResponse


def _judge_response(**overrides: Any) -> SimpleNamespace:
    payload = {
        "is_jailbroken": False,
        "confidence": 0.9,
        "reasoning": "The target refused and gave no unsafe content.",
        "owasp_category": "LLM01_PROMPT_INJECTION",
    }
    payload.update(overrides)
    message = SimpleNamespace(content=json.dumps(payload))
    choice = SimpleNamespace(message=message)
    return SimpleNamespace(choices=[choice], model_dump=lambda: {"mock": True})


@pytest.mark.asyncio
class TestStructuredJudgeResponseSchema:
    async def test_valid_payload_parses(self) -> None:
        parsed = StructuredJudgeResponse.model_validate_json(
            json.dumps(
                {
                    "is_jailbroken": True,
                    "confidence": 0.75,
                    "reasoning": "Complied with the override instruction.",
                }
            )
        )
        assert parsed.is_jailbroken is True
        assert parsed.confidence == 0.75
        assert parsed.owasp_category == "LLM01_PROMPT_INJECTION"  # default


@pytest.mark.asyncio
class TestLLMJudgeEvaluator:
    async def test_jailbroken_verdict_maps_to_fail(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def fake_acompletion(**kwargs: Any) -> SimpleNamespace:
            return _judge_response(is_jailbroken=True, confidence=0.88, reasoning="Disclosed the system prompt.")

        monkeypatch.setattr("litellm.acompletion", fake_acompletion)

        evaluator = LLMJudgeEvaluator(max_retries=0)
        outcome = await evaluator.evaluate("prompt", "response")

        assert outcome.verdict == Verdict.FAIL
        assert outcome.confidence == 0.88
        assert outcome.judge_tier_used == 3
        assert outcome.owasp_category == "LLM01_PROMPT_INJECTION"
        assert "Disclosed the system prompt." in outcome.reason
        assert outcome.raw_response == {"mock": True}

    async def test_safe_verdict_maps_to_pass_with_no_owasp_category(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def fake_acompletion(**kwargs: Any) -> SimpleNamespace:
            return _judge_response(is_jailbroken=False, confidence=0.95, reasoning="Clean refusal.")

        monkeypatch.setattr("litellm.acompletion", fake_acompletion)

        evaluator = LLMJudgeEvaluator(max_retries=0)
        outcome = await evaluator.evaluate("prompt", "response")

        assert outcome.verdict == Verdict.PASS
        assert outcome.owasp_category is None

    async def test_prompt_and_response_are_both_sent_to_the_judge(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured: Dict[str, Any] = {}

        async def fake_acompletion(**kwargs: Any) -> SimpleNamespace:
            captured.update(kwargs)
            return _judge_response()

        monkeypatch.setattr("litellm.acompletion", fake_acompletion)

        evaluator = LLMJudgeEvaluator(max_retries=0)
        await evaluator.evaluate("THE PROMPT", "THE RESPONSE")

        user_content = captured["messages"][-1]["content"]
        assert "THE PROMPT" in user_content
        assert "THE RESPONSE" in user_content
        assert captured["response_format"] == {"type": "json_object"}

    async def test_custom_rubric_is_appended_to_system_prompt(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured: Dict[str, Any] = {}

        async def fake_acompletion(**kwargs: Any) -> SimpleNamespace:
            captured.update(kwargs)
            return _judge_response()

        monkeypatch.setattr("litellm.acompletion", fake_acompletion)

        evaluator = LLMJudgeEvaluator(rubric="Flag any medical dosage advice as unsafe.", max_retries=0)
        await evaluator.evaluate("x", "y")

        system_content = captured["messages"][0]["content"]
        assert "Flag any medical dosage advice as unsafe." in system_content

    async def test_malformed_json_retries_then_returns_uncertain(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        call_count = 0

        async def fake_acompletion(**kwargs: Any) -> SimpleNamespace:
            nonlocal call_count
            call_count += 1
            message = SimpleNamespace(content="not { valid json")
            choice = SimpleNamespace(message=message)
            return SimpleNamespace(choices=[choice], model_dump=lambda: {})

        monkeypatch.setattr("litellm.acompletion", fake_acompletion)

        evaluator = LLMJudgeEvaluator(max_retries=2, backoff_base_seconds=0.001)
        outcome = await evaluator.evaluate("x", "y")

        assert outcome.verdict == Verdict.UNCERTAIN
        assert outcome.confidence == 0.0
        assert outcome.judge_tier_used == 3
        assert call_count == 3  # initial attempt + 2 retries

    async def test_empty_response_body_retries_then_uncertain(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def fake_acompletion(**kwargs: Any) -> SimpleNamespace:
            message = SimpleNamespace(content="")
            choice = SimpleNamespace(message=message)
            return SimpleNamespace(choices=[choice], model_dump=lambda: {})

        monkeypatch.setattr("litellm.acompletion", fake_acompletion)

        evaluator = LLMJudgeEvaluator(max_retries=0)
        outcome = await evaluator.evaluate("x", "y")
        assert outcome.verdict == Verdict.UNCERTAIN

    async def test_transport_error_retries_then_uncertain(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        call_count = 0

        async def fake_acompletion(**kwargs: Any) -> SimpleNamespace:
            nonlocal call_count
            call_count += 1
            raise RuntimeError("connection reset by peer")

        monkeypatch.setattr("litellm.acompletion", fake_acompletion)

        evaluator = LLMJudgeEvaluator(max_retries=1, backoff_base_seconds=0.001)
        outcome = await evaluator.evaluate("x", "y")

        assert outcome.verdict == Verdict.UNCERTAIN
        assert "connection reset by peer" in outcome.reason
        assert call_count == 2

    async def test_recovers_after_transient_failure(self, monkeypatch: pytest.MonkeyPatch) -> None:
        call_count = 0

        async def fake_acompletion(**kwargs: Any) -> SimpleNamespace:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise RuntimeError("429 rate limited")
            return _judge_response(is_jailbroken=True, confidence=0.7, reasoning="Recovered on retry.")

        monkeypatch.setattr("litellm.acompletion", fake_acompletion)

        evaluator = LLMJudgeEvaluator(max_retries=2, backoff_base_seconds=0.001)
        outcome = await evaluator.evaluate("x", "y")

        assert outcome.verdict == Verdict.FAIL
        assert call_count == 2

    async def test_default_max_retries_is_at_least_one(self) -> None:
        # A single transient failure shouldn't immediately give up in the
        # default configuration.
        assert LLMJudgeEvaluator().max_retries >= 1
