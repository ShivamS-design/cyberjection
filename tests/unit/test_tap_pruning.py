"""Tests for cyberjection.attacks.tap.TAPEngine: tree expansion and
evaluator-guided pruning.

Includes a direct regression test for the Phase 5 spec's own loop-nesting
bug: `active_branches = next_generation_branches` and the final `return`
sat at the wrong indent level in the source pseudocode, which -- taken
literally -- would terminate the search after a single depth level
regardless of `max_depth`. `TAPEngine.execute_tree_search` expands every
surviving branch at every depth level before moving on.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, Dict, List

import pytest

from cyberjection.attacks.attacker import AttackerResponse
from cyberjection.attacks.state import TurnStatus
from cyberjection.attacks.tap import TAPEngine
from cyberjection.evaluators.base import EvaluationOutcome, Verdict


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


class ScriptedAttacker:
    """Returns (or raises) the next scripted outcome on each call, in
    order. An item that's an `Exception` instance is raised instead of
    returned, so tests can script individual branch-candidate failures."""

    def __init__(self, outcomes: List[Any]) -> None:
        self._outcomes = list(outcomes)
        self.calls = 0

    async def generate_next_payload(self, goal: str, history: List[Dict[str, str]]) -> AttackerResponse:
        self.calls += 1
        outcome = self._outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return AttackerResponse(analysis="a", refusal_detected=False, next_prompt=outcome)


@pytest.mark.asyncio
class TestTAPPruning:
    async def test_below_threshold_branch_is_pruned_and_not_expanded_further(self) -> None:
        target = FakeTarget(responses=["weak response"])
        # UNCERTAIN/0.5 -> score 2.5 (see state.score_from_evaluation), below
        # the pruning threshold of 3.0.
        evaluator = FakeEvaluator([_outcome(Verdict.UNCERTAIN, 0.5)])
        attacker = ScriptedAttacker(["candidate prompt"])
        engine = TAPEngine(
            evaluator=evaluator, attacker=attacker,
            branching_factor=1, max_depth=3, pruning_threshold=3.0, success_threshold=8.0,
        )

        path = await engine.execute_tree_search(target, "goal", "seed")

        # Pruned at depth 1: no depth-2 target call should ever have happened.
        assert len(target.calls) == 1
        assert len(path) == 2  # root + the one pruned node
        assert path[-1].score == 2.5

    async def test_above_threshold_branch_survives_and_is_expanded_next_depth(self) -> None:
        target = FakeTarget(responses=["mild compliance", "full compliance"])
        # Depth 1: FAIL/0.5 -> score 5.0, above pruning_threshold, below success.
        # Depth 2: FAIL/0.9 -> score 9.0, above success_threshold.
        evaluator = FakeEvaluator([_outcome(Verdict.FAIL, 0.5), _outcome(Verdict.FAIL, 0.9)])
        attacker = ScriptedAttacker(["depth 1 prompt", "depth 2 prompt"])
        engine = TAPEngine(
            evaluator=evaluator, attacker=attacker,
            branching_factor=1, max_depth=3, pruning_threshold=3.0, success_threshold=8.0,
        )

        path = await engine.execute_tree_search(target, "goal", "seed")

        assert len(target.calls) == 2  # both depths were actually explored
        assert len(path) == 3  # root -> depth1 node -> depth2 success node
        assert path[-1].status == TurnStatus.SUCCESS
        assert path[-1].score == 9.0

    async def test_returns_best_partial_path_when_nothing_succeeds(self) -> None:
        target = FakeTarget(responses=["mild compliance", "refusal"])
        # Depth 1 survives (score 5.0); depth 2 is a refusal that's pruned
        # (score 1.0, below the 3.0 threshold) -- so the search ends with
        # no success anywhere in the tree.
        evaluator = FakeEvaluator([_outcome(Verdict.FAIL, 0.5), _outcome(Verdict.PASS, 0.9)])
        attacker = ScriptedAttacker(["depth 1 prompt", "depth 2 prompt"])
        engine = TAPEngine(
            evaluator=evaluator, attacker=attacker,
            branching_factor=1, max_depth=3, pruning_threshold=3.0, success_threshold=8.0,
        )

        path = await engine.execute_tree_search(target, "goal", "seed")

        assert all(node.status != TurnStatus.SUCCESS for node in path)
        assert path[-1].score == 5.0  # the best-scoring node explored, not the refusal


@pytest.mark.asyncio
class TestTAPMultiDepthTraversal:
    async def test_search_runs_for_the_full_max_depth_when_nothing_prunes_or_succeeds(self) -> None:
        # Regression test for the spec's loop-nesting bug: a search that
        # neither prunes (threshold 0.0, everything survives) nor succeeds
        # (threshold 100.0, unreachable) must still explore all max_depth
        # levels rather than stopping after the first.
        target = FakeTarget(responses=["r1", "r2", "r3", "r4"])
        evaluator = FakeEvaluator([_outcome(Verdict.UNCERTAIN, 0.5)] * 4)
        attacker = ScriptedAttacker(["p1", "p2", "p3", "p4"])
        engine = TAPEngine(
            evaluator=evaluator, attacker=attacker,
            branching_factor=1, max_depth=4, pruning_threshold=0.0, success_threshold=100.0,
        )

        path = await engine.execute_tree_search(target, "goal", "seed")

        assert len(target.calls) == 4  # every one of the 4 depth levels was explored
        assert len(path) == 5  # root + 4 expanded depths (all tied on score; deepest wins ties)


@pytest.mark.asyncio
class TestTAPBranchingAndFaultTolerance:
    async def test_one_failed_branch_candidate_does_not_abort_the_whole_search(self) -> None:
        # branching_factor=2: one candidate's attacker call fails outright,
        # the other succeeds and reaches the success threshold. The whole
        # tree search must still return the successful path rather than
        # raising or losing the surviving branch.
        target = FakeTarget(responses=["full compliance"])
        evaluator = FakeEvaluator([_outcome(Verdict.FAIL, 0.95)])
        attacker = ScriptedAttacker([RuntimeError("attacker call failed"), "surviving prompt"])
        engine = TAPEngine(
            evaluator=evaluator, attacker=attacker,
            branching_factor=2, max_depth=1, pruning_threshold=3.0, success_threshold=8.0,
        )

        path = await engine.execute_tree_search(target, "goal", "seed")

        assert len(target.calls) == 1  # the failed candidate never reached target dispatch
        assert path[-1].status == TurnStatus.SUCCESS

    async def test_every_branch_candidate_failing_degrades_to_just_the_root(self) -> None:
        # branching_factor=1 with an attacker that fails immediately: no
        # child node is ever created (no target/evaluator call happens
        # either), so the search must degrade gracefully to the seed node
        # alone rather than raising.
        target = FakeTarget(responses=[])
        evaluator = FakeEvaluator([])
        attacker = ScriptedAttacker([RuntimeError("always fails")])
        engine = TAPEngine(
            evaluator=evaluator, attacker=attacker,
            branching_factor=1, max_depth=1, pruning_threshold=3.0, success_threshold=8.0,
        )

        path = await engine.execute_tree_search(target, "goal", "seed")

        assert len(path) == 1
        assert path[0].prompt == "seed"
        assert target.calls == []
