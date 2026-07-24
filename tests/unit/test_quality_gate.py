"""Tests for cyberjection.reporting.quality_gate: the pure pass/fail
threshold evaluator the Phase 6 CLI's exit-code decision is built on.

Kept independent of Typer/Click entirely -- these are plain function
calls against `Finding`/`QualityGateResult`, exercising the exact
decision logic `test_cli.py` later verifies end-to-end through a real
command invocation.
"""

from __future__ import annotations

from cyberjection.reporting.models import Finding
from cyberjection.reporting.quality_gate import (
    DEFAULT_THRESHOLD,
    evaluate_quality_gate,
    resolve_threshold,
)


def _finding(rule_id: str, score: float) -> Finding:
    return Finding(rule_id=rule_id, category="test", score=score, details="d")


class TestResolveThreshold:
    def test_cli_flag_wins_over_everything(self) -> None:
        assert resolve_threshold(4.0, 6.0) == 4.0

    def test_config_value_used_when_no_cli_flag(self) -> None:
        assert resolve_threshold(None, 6.0) == 6.0

    def test_falls_back_to_default_when_nothing_given(self) -> None:
        assert resolve_threshold(None, None) == DEFAULT_THRESHOLD

    def test_explicit_zero_cli_threshold_is_not_treated_as_missing(self) -> None:
        # A regression guard: `if cli_threshold:` would treat 0.0 as falsy
        # and incorrectly fall through to the config/default threshold,
        # even though "fail on anything" is a legitimate, deliberately
        # strict threshold an operator might configure.
        assert resolve_threshold(0.0, 6.0) == 0.0

    def test_explicit_zero_config_threshold_is_not_treated_as_missing(self) -> None:
        assert resolve_threshold(None, 0.0) == 0.0


class TestEvaluateQualityGate:
    def test_passes_when_every_finding_is_below_threshold(self) -> None:
        findings = [_finding("CJ-001", 2.0), _finding("CJ-002", 4.9)]
        result = evaluate_quality_gate(findings, threshold=5.0)

        assert result.passed is True
        assert result.exit_code == 0
        assert result.failing_findings == []
        assert result.max_score == 4.9

    def test_fails_when_a_finding_meets_the_threshold_exactly(self) -> None:
        # Matches the Phase 6 spec's own CLI sketch, which fails the gate
        # on `max_score >= threshold` -- a score exactly at the threshold
        # fails, not just scores strictly above it.
        findings = [_finding("CJ-001", 5.0)]
        result = evaluate_quality_gate(findings, threshold=5.0)

        assert result.passed is False
        assert result.exit_code == 1
        assert [f.rule_id for f in result.failing_findings] == ["CJ-001"]

    def test_fails_when_a_finding_exceeds_the_threshold(self) -> None:
        findings = [_finding("CJ-001", 1.0), _finding("CJ-002", 9.5)]
        result = evaluate_quality_gate(findings, threshold=7.0)

        assert result.passed is False
        assert result.max_score == 9.5
        assert [f.rule_id for f in result.failing_findings] == ["CJ-002"]

    def test_empty_findings_list_passes_with_zero_max_score(self) -> None:
        result = evaluate_quality_gate([], threshold=7.0)

        assert result.passed is True
        assert result.max_score == 0.0
        assert result.failing_findings == []

    def test_multiple_failing_findings_are_all_reported(self) -> None:
        findings = [_finding("CJ-001", 8.0), _finding("CJ-002", 9.0), _finding("CJ-003", 1.0)]
        result = evaluate_quality_gate(findings, threshold=7.0)

        assert result.passed is False
        assert {f.rule_id for f in result.failing_findings} == {"CJ-001", "CJ-002"}
