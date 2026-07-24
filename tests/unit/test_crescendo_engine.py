"""Tests for cyberjection.attacks.crescendo.CrescendoEngine.

Uses lightweight duck-typed test doubles for the target, evaluator, and
attacker rather than real `LiteLLMTarget` / `CascadeEvaluator` /
`AttackerAgent` instances -- CrescendoEngine only calls
`target.generate_conversation(...)`, `evaluator.evaluate(...)`, and
`attacker.generate_next_payload(...)`, so a fake with just those three
methods is a faithful, fast substitute.

Includes a direct regression test for the double-yield bug found in the
Phase 5 spec's own Crescendo code: a turn that triggers a backtrack yielded
the same `AttackNode` twice (once inside the backtrack branch, once via an
unconditional yield right after it).
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, Dict, List

import pytest

from cyberjection.attacks.attacker import AttackerResponse
from cyberjection.attacks.crescendo import CrescendoEngine
from cyberjection.attacks.state import TurnStatus
from cyberjection.evaluators.base import EvaluationOutcome, Verdict
from cyberjection.utils.exceptions import AttackerGenerationError


def _outcome(verdict: Verdict, confidence: float) -> EvaluationOutcome:
    return EvaluationOutcome(verdict=verdict, confidence=confidence, judge_tier_used=1, reason="x")


class FakeTarget:
    def __init__(self, responses: List[str], target_id: str = "target-a") -> None:
        self.config = SimpleNamespace(id=target_id)
        self._responses = list(responses)
        self.calls: List[List[Dict[str, str]]] = []

    async def generate_conversation(self, messages: List[Dict[str, str]]) -> SimpleNamespace:
        self.calls.append([dict(m) for m in messages])
        return SimpleNamespace(content=self._responses.pop(0))


class FakeEvaluator:
    def __init__(self, outcomes: List[EvaluationOutcome]) -> None:
        self._outcomes = list(outcomes)
        self.calls: List[Any] = []

    async def evaluate(self, prompt_sent: str, response_text: str) -> EvaluationOutcome:
        self.calls.append((prompt_sent, response_text))
        return self._outcomes.pop(0)


class FakeAttacker:
    def __init__(self, next_prompts: List[str]) -> None:
        self._next_prompts = list(next_prompts)
        self.calls: List[Any] = []

    async def generate_next_payload(self, goal: str, history: List[Dict[str, str]]) -> AttackerResponse:
        self.calls.append((goal, [dict(m) for m in history]))
        if not self._next_prompts:
            raise AttackerGenerationError("test double ran out of scripted prompts")
        return AttackerResponse(analysis="a", refusal_detected=True, next_prompt=self._next_prompts.pop(0))


@pytest.mark.asyncio
class TestCrescendoSingleYieldPerTurn:
    async def test_backtracked_turn_yields_exactly_one_node(self) -> None:
        # Turn 1: PASS/high-confidence -> a refusal, well below the success
        # threshold -> triggers a backtrack. This is exactly the scenario
        # the original spec code double-yielded on.
        target = FakeTarget(responses=["refusal response", "compliant response"])
        evaluator = FakeEvaluator([_outcome(Verdict.PASS, 0.95), _outcome(Verdict.FAIL, 0.9)])
        attacker = FakeAttacker(next_prompts=["turn 2 prompt"])
        engine = CrescendoEngine(evaluator=evaluator, attacker=attacker, max_turns=2, max_backtracks=5)

        nodes = [node async for node in engine.run(target, "goal", "turn 1 prompt")]

        assert len(nodes) == 2
        assert nodes[0].status == TurnStatus.BACKTRACK
        assert nodes[1].status == TurnStatus.SUCCESS

    async def test_progressing_turn_also_yields_exactly_one_node(self) -> None:
        target = FakeTarget(responses=["mild response"])
        evaluator = FakeEvaluator([_outcome(Verdict.UNCERTAIN, 0.5)])
        attacker = FakeAttacker(next_prompts=[])
        engine = CrescendoEngine(evaluator=evaluator, attacker=attacker, max_turns=1)

        nodes = [node async for node in engine.run(target, "goal", "seed")]

        assert len(nodes) == 1
        assert nodes[0].status == TurnStatus.PROGRESSING


@pytest.mark.asyncio
class TestCrescendoBacktrackRollback:
    async def test_backtrack_removes_the_refused_turn_from_history_sent_to_target(self) -> None:
        target = FakeTarget(responses=["refusal", "second try response"])
        evaluator = FakeEvaluator([_outcome(Verdict.PASS, 0.9), _outcome(Verdict.UNCERTAIN, 0.5)])
        attacker = FakeAttacker(next_prompts=["retry prompt"])
        engine = CrescendoEngine(evaluator=evaluator, attacker=attacker, max_turns=2, max_backtracks=5)

        _ = [node async for node in engine.run(target, "goal", "first prompt")]

        # Turn 2's outgoing message list should NOT contain turn 1's
        # (rolled-back) prompt/response -- only turn 2's own user message.
        second_call_messages = target.calls[1]
        assert second_call_messages == [{"role": "user", "content": "retry prompt"}]

    async def test_refusal_with_exhausted_backtrack_budget_is_not_rolled_back(self) -> None:
        target = FakeTarget(responses=["refusal 1", "refusal 2"])
        evaluator = FakeEvaluator([_outcome(Verdict.PASS, 0.9), _outcome(Verdict.PASS, 0.9)])
        attacker = FakeAttacker(next_prompts=["second prompt"])
        engine = CrescendoEngine(evaluator=evaluator, attacker=attacker, max_turns=2, max_backtracks=0)

        nodes = [node async for node in engine.run(target, "goal", "first prompt")]

        assert nodes[0].status == TurnStatus.REFUSED  # not BACKTRACK: no budget left
        # Turn 1's exchange should still be present in what's sent for turn 2.
        second_call_messages = target.calls[1]
        assert {"role": "user", "content": "first prompt"} in second_call_messages


@pytest.mark.asyncio
class TestCrescendoSuccessShortCircuits:
    async def test_success_stops_the_generator_before_max_turns(self) -> None:
        target = FakeTarget(responses=["fully compliant response"])
        evaluator = FakeEvaluator([_outcome(Verdict.FAIL, 0.95)])
        attacker = FakeAttacker(next_prompts=["never used"])
        engine = CrescendoEngine(evaluator=evaluator, attacker=attacker, max_turns=10)

        nodes = [node async for node in engine.run(target, "goal", "seed")]

        assert len(nodes) == 1
        assert nodes[0].status == TurnStatus.SUCCESS
        assert attacker.calls == []  # never asked for a follow-up


@pytest.mark.asyncio
class TestCrescendoAttackerFailure:
    async def test_attacker_failure_ends_the_generator_without_raising(self) -> None:
        target = FakeTarget(responses=["response 1"])
        evaluator = FakeEvaluator([_outcome(Verdict.UNCERTAIN, 0.5)])
        attacker = FakeAttacker(next_prompts=[])  # will raise on first call
        engine = CrescendoEngine(evaluator=evaluator, attacker=attacker, max_turns=5)

        nodes = [node async for node in engine.run(target, "goal", "seed")]

        assert len(nodes) == 1  # turn 1 still yielded before the failed follow-up generation


@pytest.mark.asyncio
class TestCrescendoLastTurnSkipsAttackerCall:
    async def test_no_attacker_call_is_made_after_the_final_turn(self) -> None:
        target = FakeTarget(responses=["response"])
        evaluator = FakeEvaluator([_outcome(Verdict.UNCERTAIN, 0.5)])
        attacker = FakeAttacker(next_prompts=["would blow up if called"])
        engine = CrescendoEngine(evaluator=evaluator, attacker=attacker, max_turns=1)

        _ = [node async for node in engine.run(target, "goal", "seed")]

        assert attacker.calls == []
