"""Tests for cyberjection.attacks.state: conversation memory, backtracking,
the attack-tree node index, and the Phase 3 -> Phase 5 score adapter.
"""

from __future__ import annotations

import pytest

from cyberjection.attacks.state import (
    AttackNode,
    ConversationContext,
    TurnStatus,
    score_from_evaluation,
)
from cyberjection.evaluators.base import EvaluationOutcome, Verdict


def _outcome(verdict: Verdict, confidence: float) -> EvaluationOutcome:
    return EvaluationOutcome(verdict=verdict, confidence=confidence, judge_tier_used=1, reason="x")


class TestConversationContextMemory:
    def test_add_turn_appends_user_then_assistant(self) -> None:
        context = ConversationContext(goal="g", target_id="t")
        context.add_turn("hello", "hi there")
        assert context.history == [
            {"role": "user", "content": "hello"},
            {"role": "assistant", "content": "hi there"},
        ]

    def test_pop_last_turn_removes_and_returns_the_user_message(self) -> None:
        context = ConversationContext(goal="g", target_id="t")
        context.add_turn("first", "first-response")
        context.add_turn("second", "second-response")

        popped = context.pop_last_turn()

        assert popped == {"role": "user", "content": "second"}
        assert context.history == [
            {"role": "user", "content": "first"},
            {"role": "assistant", "content": "first-response"},
        ]

    def test_pop_last_turn_on_empty_history_returns_none(self) -> None:
        context = ConversationContext(goal="g", target_id="t")
        assert context.pop_last_turn() is None

    def test_pop_last_turn_on_single_dangling_message_returns_none(self) -> None:
        context = ConversationContext(goal="g", target_id="t")
        context.history.append({"role": "user", "content": "orphaned"})
        assert context.pop_last_turn() is None
        assert context.history == [{"role": "user", "content": "orphaned"}]


class TestAttackTreeIndex:
    def test_add_node_updates_current_node_id(self) -> None:
        context = ConversationContext(goal="g", target_id="t")
        node = AttackNode(node_id="n1", prompt="p")
        context.add_node(node)
        assert context.nodes["n1"] is node
        assert context.current_node_id == "n1"

    def test_path_to_walks_parent_chain_root_to_leaf(self) -> None:
        context = ConversationContext(goal="g", target_id="t")
        root = AttackNode(node_id="root", parent_id=None, depth=0, prompt="seed")
        child = AttackNode(node_id="child", parent_id="root", depth=1, prompt="p1")
        grandchild = AttackNode(node_id="grandchild", parent_id="child", depth=2, prompt="p2")
        for n in (root, child, grandchild):
            context.add_node(n)

        path = context.path_to("grandchild")

        assert [n.node_id for n in path] == ["root", "child", "grandchild"]

    def test_path_to_unknown_node_returns_empty(self) -> None:
        context = ConversationContext(goal="g", target_id="t")
        assert context.path_to("does-not-exist") == []

    def test_path_to_tolerates_a_cyclic_parent_chain(self) -> None:
        # Should never happen in practice, but path_to must not infinite-loop.
        context = ConversationContext(goal="g", target_id="t")
        a = AttackNode(node_id="a", parent_id="b", prompt="a")
        b = AttackNode(node_id="b", parent_id="a", prompt="b")
        context.add_node(a)
        context.add_node(b)

        path = context.path_to("a")  # Must terminate.
        assert {n.node_id for n in path} == {"a", "b"}

    def test_best_score_returns_max_across_nodes(self) -> None:
        context = ConversationContext(goal="g", target_id="t")
        context.add_node(AttackNode(node_id="a", prompt="a", score=2.0))
        context.add_node(AttackNode(node_id="b", prompt="b", score=7.5))
        context.add_node(AttackNode(node_id="c", prompt="c", score=4.0))
        assert context.best_score() == 7.5

    def test_best_score_on_empty_tree_is_zero(self) -> None:
        context = ConversationContext(goal="g", target_id="t")
        assert context.best_score() == 0.0


class TestScoreFromEvaluation:
    def test_fail_verdict_scales_score_by_confidence_and_is_not_a_refusal(self) -> None:
        score, is_refusal = score_from_evaluation(_outcome(Verdict.FAIL, 0.9))
        assert score == pytest.approx(9.0)
        assert is_refusal is False

    def test_pass_verdict_scores_low_and_is_a_refusal(self) -> None:
        score, is_refusal = score_from_evaluation(_outcome(Verdict.PASS, 0.95))
        assert score == pytest.approx(0.5)
        assert is_refusal is True

    def test_uncertain_verdict_is_mid_low_and_not_asserted_as_a_refusal(self) -> None:
        score, is_refusal = score_from_evaluation(_outcome(Verdict.UNCERTAIN, 0.5))
        assert score == 2.5
        assert is_refusal is False

    def test_low_confidence_fail_still_scores_below_a_typical_success_threshold(self) -> None:
        score, _ = score_from_evaluation(_outcome(Verdict.FAIL, 0.1))
        assert score < 8.0
