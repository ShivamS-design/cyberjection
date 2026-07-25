"""Tests for the three Phase 10 subsystem registries added alongside the
plugin architecture: `cyberjection.attacks.registry` (single-turn
strategies), `cyberjection.evaluators.registry` (cascade tier
evaluators), and `cyberjection.reporting.registry` (report exporters).

Each mirrors `cyberjection.mutators.registry`'s registration/collision/
idempotency contract exactly (see `tests/unit/test_mutators.py`'s
`TestMutatorRegistry` for the pattern these tests copy), so this file
verifies the same three properties for each of the three new registries
rather than re-deriving new test shapes per registry.
"""

from __future__ import annotations

import pytest

from cyberjection.attacks.base import BaseStrategy, ExecutionContext, SingleTurnResult
from cyberjection.attacks.registry import (
    StrategyRegistrationError,
    _reset_registry_for_tests as _reset_strategy_registry,
    _restore_registry_for_tests as _restore_strategy_registry,
    build_strategy,
    get_strategy_class,
    is_registered as strategy_is_registered,
    list_strategy_aliases,
    register_strategy,
)
from cyberjection.evaluators.base import BaseEvaluator, EvaluationOutcome, Verdict
from cyberjection.evaluators.registry import (
    EvaluatorRegistrationError,
    _reset_registry_for_tests as _reset_evaluator_registry,
    _restore_registry_for_tests as _restore_evaluator_registry,
    build_evaluator,
    get_evaluator_class,
    is_registered as evaluator_is_registered,
    list_evaluator_aliases,
    register_evaluator,
)
from cyberjection.reporting.registry import (
    ExporterRegistrationError,
    _reset_registry_for_tests as _reset_exporter_registry,
    _restore_registry_for_tests as _restore_exporter_registry,
    get_exporter_class,
    is_registered as exporter_is_registered,
    list_exporter_aliases,
    register_exporter,
)

# Importing these packages registers every built-in implementation as a
# side effect (see each package's own __init__.py); imported once here so
# the "builtin aliases registered" tests below see them regardless of
# module import order across the test session.
import cyberjection.attacks  # noqa: F401,E402
import cyberjection.evaluators  # noqa: F401,E402
import cyberjection.reporting  # noqa: F401,E402


class _DummyStrategy(BaseStrategy):
    def __init__(self, mutator_pipeline=None) -> None:
        super().__init__(strategy_id="dummy", mutator_pipeline=mutator_pipeline)

    async def execute(self, target, seed_prompt: str, context: ExecutionContext) -> SingleTurnResult:
        raise NotImplementedError


class _OtherDummyStrategy(BaseStrategy):
    def __init__(self, mutator_pipeline=None) -> None:
        super().__init__(strategy_id="other-dummy", mutator_pipeline=mutator_pipeline)

    async def execute(self, target, seed_prompt: str, context: ExecutionContext) -> SingleTurnResult:
        raise NotImplementedError


class TestStrategyRegistry:
    def test_builtin_aliases_registered(self) -> None:
        aliases = list_strategy_aliases()
        for expected in (
            "direct_prompt_injection",
            "jailbreak",
            "jailbreak_roleplay",
            "system_prompt_extraction",
        ):
            assert expected in aliases

    def test_jailbreak_and_jailbreak_roleplay_share_one_class(self) -> None:
        assert get_strategy_class("jailbreak") is get_strategy_class("jailbreak_roleplay")

    def test_build_strategy_returns_correct_type(self) -> None:
        strategy = build_strategy("direct_prompt_injection")
        assert type(strategy).__name__ == "DirectPromptInjectionStrategy"

    def test_get_unknown_alias_raises(self) -> None:
        with pytest.raises(StrategyRegistrationError, match="No strategy registered"):
            get_strategy_class("does-not-exist")

    def test_is_registered_reflects_known_and_unknown_aliases(self) -> None:
        assert strategy_is_registered("direct_prompt_injection") is True
        assert strategy_is_registered("does-not-exist") is False

    def test_register_rejects_non_strategy_class(self) -> None:
        previous = _reset_strategy_registry()
        try:
            with pytest.raises(StrategyRegistrationError):
                register_strategy("not_a_strategy")(object)
        finally:
            _restore_strategy_registry(previous)

    def test_register_rejects_alias_collision_with_different_class(self) -> None:
        previous = _reset_strategy_registry()
        try:
            register_strategy("dup")(_DummyStrategy)
            with pytest.raises(StrategyRegistrationError, match="already registered"):
                register_strategy("dup")(_OtherDummyStrategy)
        finally:
            _restore_strategy_registry(previous)

    def test_reregistering_same_class_under_same_alias_is_idempotent(self) -> None:
        previous = _reset_strategy_registry()
        try:
            register_strategy("idempotent")(_DummyStrategy)
            register_strategy("idempotent")(_DummyStrategy)  # should not raise
            assert "idempotent" in list_strategy_aliases()
        finally:
            _restore_strategy_registry(previous)

    def test_one_class_registered_under_two_aliases(self) -> None:
        previous = _reset_strategy_registry()
        try:
            register_strategy("alias-one")(_DummyStrategy)
            register_strategy("alias-two")(_DummyStrategy)
            assert get_strategy_class("alias-one") is get_strategy_class("alias-two")
        finally:
            _restore_strategy_registry(previous)


class _DummyEvaluator(BaseEvaluator):
    def __init__(self) -> None:
        super().__init__(tier_level=1)

    async def evaluate(self, prompt_sent: str, response_text: str) -> EvaluationOutcome:
        return EvaluationOutcome(
            verdict=Verdict.UNCERTAIN, confidence=0.0, judge_tier_used=1, reason="dummy"
        )


class _OtherDummyEvaluator(BaseEvaluator):
    def __init__(self) -> None:
        super().__init__(tier_level=1)

    async def evaluate(self, prompt_sent: str, response_text: str) -> EvaluationOutcome:
        return EvaluationOutcome(
            verdict=Verdict.UNCERTAIN, confidence=0.0, judge_tier_used=1, reason="other-dummy"
        )


class TestEvaluatorRegistry:
    def test_builtin_aliases_registered(self) -> None:
        aliases = list_evaluator_aliases()
        for expected in ("regex", "onnx", "llm_judge"):
            assert expected in aliases

    def test_build_evaluator_returns_correct_type(self) -> None:
        evaluator = build_evaluator("regex")
        assert type(evaluator).__name__ == "RegexEvaluator"

    def test_get_unknown_alias_raises(self) -> None:
        with pytest.raises(EvaluatorRegistrationError, match="No evaluator registered"):
            get_evaluator_class("does-not-exist")

    def test_is_registered_reflects_known_and_unknown_aliases(self) -> None:
        assert evaluator_is_registered("regex") is True
        assert evaluator_is_registered("does-not-exist") is False

    def test_register_rejects_non_evaluator_class(self) -> None:
        previous = _reset_evaluator_registry()
        try:
            with pytest.raises(EvaluatorRegistrationError):
                register_evaluator("not_an_evaluator")(object)
        finally:
            _restore_evaluator_registry(previous)

    def test_register_rejects_alias_collision_with_different_class(self) -> None:
        previous = _reset_evaluator_registry()
        try:
            register_evaluator("dup")(_DummyEvaluator)
            with pytest.raises(EvaluatorRegistrationError, match="already registered"):
                register_evaluator("dup")(_OtherDummyEvaluator)
        finally:
            _restore_evaluator_registry(previous)

    def test_reregistering_same_class_under_same_alias_is_idempotent(self) -> None:
        previous = _reset_evaluator_registry()
        try:
            register_evaluator("idempotent")(_DummyEvaluator)
            register_evaluator("idempotent")(_DummyEvaluator)  # should not raise
            assert "idempotent" in list_evaluator_aliases()
        finally:
            _restore_evaluator_registry(previous)


class _DummyExporter:
    @staticmethod
    def export(findings, output_path, *, threshold: float = 7.0) -> None:
        raise NotImplementedError


class _OtherDummyExporter:
    @staticmethod
    def export(findings, output_path, *, threshold: float = 7.0) -> None:
        raise NotImplementedError


class TestExporterRegistry:
    def test_builtin_aliases_registered(self) -> None:
        aliases = list_exporter_aliases()
        for expected in ("json", "markdown", "sarif"):
            assert expected in aliases

    def test_get_exporter_class_returns_correct_type(self) -> None:
        assert get_exporter_class("json").__name__ == "JSONExporter"
        assert get_exporter_class("markdown").__name__ == "MarkdownExporter"
        assert get_exporter_class("sarif").__name__ == "SARIFReporter"

    def test_get_unknown_alias_raises(self) -> None:
        with pytest.raises(ExporterRegistrationError, match="No exporter registered"):
            get_exporter_class("does-not-exist")

    def test_is_registered_reflects_known_and_unknown_aliases(self) -> None:
        assert exporter_is_registered("json") is True
        assert exporter_is_registered("does-not-exist") is False

    def test_register_rejects_class_without_export_attribute(self) -> None:
        previous = _reset_exporter_registry()
        try:
            with pytest.raises(ExporterRegistrationError):
                register_exporter("not_an_exporter")(object)
        finally:
            _restore_exporter_registry(previous)

    def test_register_rejects_alias_collision_with_different_class(self) -> None:
        previous = _reset_exporter_registry()
        try:
            register_exporter("dup")(_DummyExporter)
            with pytest.raises(ExporterRegistrationError, match="already registered"):
                register_exporter("dup")(_OtherDummyExporter)
        finally:
            _restore_exporter_registry(previous)

    def test_reregistering_same_class_under_same_alias_is_idempotent(self) -> None:
        previous = _reset_exporter_registry()
        try:
            register_exporter("idempotent")(_DummyExporter)
            register_exporter("idempotent")(_DummyExporter)  # should not raise
            assert "idempotent" in list_exporter_aliases()
        finally:
            _restore_exporter_registry(previous)
