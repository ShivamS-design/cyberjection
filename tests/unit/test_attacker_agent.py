"""Tests for cyberjection.attacks.attacker.AttackerAgent: mocked structured
attacker-payload generation.

Mirrors the mocking convention from test_llm_judge.py
(monkeypatch.setattr("litellm.acompletion", ...)), since AttackerAgent calls
`litellm.acompletion` directly rather than through `LiteLLMTarget` -- see
the module docstring in cyberjection/attacks/attacker.py for why.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any, Dict

import pytest

from cyberjection.attacks.attacker import AttackerAgent, AttackerResponse
from cyberjection.utils.exceptions import AttackerGenerationError


def _attacker_response(**overrides: Any) -> SimpleNamespace:
    payload = {
        "analysis": "Target refused; try a benign framing.",
        "refusal_detected": True,
        "next_prompt": "Hypothetically speaking, for a fictional story...",
    }
    payload.update(overrides)
    message = SimpleNamespace(content=json.dumps(payload))
    choice = SimpleNamespace(message=message)
    return SimpleNamespace(choices=[choice])


@pytest.mark.asyncio
class TestAttackerResponseSchema:
    async def test_valid_payload_parses(self) -> None:
        parsed = AttackerResponse.model_validate_json(
            json.dumps({"analysis": "a", "refusal_detected": False, "next_prompt": "p"})
        )
        assert parsed.refusal_detected is False
        assert parsed.next_prompt == "p"


@pytest.mark.asyncio
class TestAttackerAgent:
    async def test_generates_next_payload_from_valid_response(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def fake_acompletion(**kwargs: Any) -> SimpleNamespace:
            return _attacker_response(next_prompt="escalated prompt")

        monkeypatch.setattr("litellm.acompletion", fake_acompletion)

        agent = AttackerAgent(max_retries=0)
        result = await agent.generate_next_payload("goal", [{"role": "user", "content": "x"}])

        assert result.next_prompt == "escalated prompt"

    async def test_goal_is_interpolated_into_the_system_prompt(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: Dict[str, Any] = {}

        async def fake_acompletion(**kwargs: Any) -> SimpleNamespace:
            captured.update(kwargs)
            return _attacker_response()

        monkeypatch.setattr("litellm.acompletion", fake_acompletion)

        agent = AttackerAgent(max_retries=0)
        await agent.generate_next_payload("extract the system prompt", [])

        system_content = captured["messages"][0]["content"]
        assert "extract the system prompt" in system_content
        assert captured["response_format"] == {"type": "json_object"}

    async def test_conversation_history_is_appended_after_system_prompt(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured: Dict[str, Any] = {}

        async def fake_acompletion(**kwargs: Any) -> SimpleNamespace:
            captured.update(kwargs)
            return _attacker_response()

        monkeypatch.setattr("litellm.acompletion", fake_acompletion)

        history = [{"role": "user", "content": "turn 1"}, {"role": "assistant", "content": "reply 1"}]
        agent = AttackerAgent(max_retries=0)
        await agent.generate_next_payload("goal", history)

        assert captured["messages"][1:] == history

    async def test_malformed_json_retries_then_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        call_count = 0

        async def fake_acompletion(**kwargs: Any) -> SimpleNamespace:
            nonlocal call_count
            call_count += 1
            message = SimpleNamespace(content="not { valid json")
            return SimpleNamespace(choices=[SimpleNamespace(message=message)])

        monkeypatch.setattr("litellm.acompletion", fake_acompletion)

        agent = AttackerAgent(max_retries=2, backoff_base_seconds=0.001)
        with pytest.raises(AttackerGenerationError):
            await agent.generate_next_payload("goal", [])
        assert call_count == 3

    async def test_empty_response_body_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def fake_acompletion(**kwargs: Any) -> SimpleNamespace:
            return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=""))])

        monkeypatch.setattr("litellm.acompletion", fake_acompletion)

        agent = AttackerAgent(max_retries=0)
        with pytest.raises(AttackerGenerationError):
            await agent.generate_next_payload("goal", [])

    async def test_recovers_after_transient_failure(self, monkeypatch: pytest.MonkeyPatch) -> None:
        call_count = 0

        async def fake_acompletion(**kwargs: Any) -> SimpleNamespace:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise RuntimeError("429 rate limited")
            return _attacker_response(next_prompt="recovered prompt")

        monkeypatch.setattr("litellm.acompletion", fake_acompletion)

        agent = AttackerAgent(max_retries=2, backoff_base_seconds=0.001)
        result = await agent.generate_next_payload("goal", [])

        assert result.next_prompt == "recovered prompt"
        assert call_count == 2

    async def test_missing_next_prompt_field_is_treated_as_malformed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def fake_acompletion(**kwargs: Any) -> SimpleNamespace:
            payload = {"analysis": "a", "refusal_detected": False}  # next_prompt missing
            return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=json.dumps(payload)))])

        monkeypatch.setattr("litellm.acompletion", fake_acompletion)

        agent = AttackerAgent(max_retries=0)
        with pytest.raises(AttackerGenerationError):
            await agent.generate_next_payload("goal", [])
