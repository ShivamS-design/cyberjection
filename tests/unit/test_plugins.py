"""Tests for cyberjection.plugins: third-party plugin discovery
(`discover_plugins`) and the cross-cutting alias view
(`known_aliases_by_group`).

`discover_plugins` is tested against a fake `entry_points_fn` (a plain
function returning canned `_FakeEntryPoint` objects) rather than real
installed distributions, so this suite exercises the exact same discovery
logic a real `importlib.metadata.entry_points(group=...)` call would drive
without needing to install a real third-party package into the test
environment -- the seam `entry_points_fn=` exists in
`cyberjection.plugins.loader.discover_plugins` specifically for this.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, List

import pytest

from cyberjection.attacks.base import BaseStrategy, ExecutionContext, SingleTurnResult
from cyberjection.attacks.registry import (
    _reset_registry_for_tests as _reset_strategy_registry,
    _restore_registry_for_tests as _restore_strategy_registry,
    is_registered as strategy_is_registered,
)
from cyberjection.evaluators.registry import (
    _reset_registry_for_tests as _reset_evaluator_registry,
    _restore_registry_for_tests as _restore_evaluator_registry,
)
from cyberjection.mutators.base import BaseMutator
from cyberjection.mutators.registry import (
    _reset_registry_for_tests as _reset_mutator_registry,
    _restore_registry_for_tests as _restore_mutator_registry,
    is_registered as mutator_is_registered,
)
from cyberjection.plugins.base import (
    EVALUATOR_GROUP,
    EXPORTER_GROUP,
    MUTATOR_GROUP,
    STRATEGY_GROUP,
)
from cyberjection.plugins.loader import discover_plugins
from cyberjection.plugins.registry import known_aliases_by_group
from cyberjection.reporting.registry import (
    _reset_registry_for_tests as _reset_exporter_registry,
    _restore_registry_for_tests as _restore_exporter_registry,
    is_registered as exporter_is_registered,
)
from cyberjection.utils.exceptions import PluginLoadError


@dataclass
class _FakeEntryPoint:
    """Stands in for `importlib.metadata.EntryPoint`: `.name` is the
    alias to register under, `.value` is the diagnostic `module:attr`
    string, and `.load()` returns (or raises, for failure-path tests) the
    plugin object itself."""

    name: str
    value: str
    _loader: Callable[[], Any]

    def load(self) -> Any:
        return self._loader()


def _entry_points_fn(mapping: Dict[str, List[_FakeEntryPoint]]) -> Callable[[str], List[_FakeEntryPoint]]:
    return lambda group: mapping.get(group, [])


class _PluginMutator(BaseMutator):
    def __init__(self) -> None:
        super().__init__(name="plugin-mutator", description="A third-party test mutator.")

    def mutate(self, prompt: str) -> str:
        return prompt.upper()


class _PluginStrategy(BaseStrategy):
    def __init__(self, mutator_pipeline=None) -> None:
        super().__init__(strategy_id="plugin-strategy", mutator_pipeline=mutator_pipeline)

    async def execute(self, target, seed_prompt: str, context: ExecutionContext) -> SingleTurnResult:
        raise NotImplementedError


class _PluginEvaluator:
    """Deliberately *not* a `BaseEvaluator` subclass -- used to exercise
    the "wrong base type" failure path."""


class _PluginExporter:
    @staticmethod
    def export(findings, output_path, *, threshold: float = 7.0) -> None:
        raise NotImplementedError


@pytest.fixture
def _clean_registries():
    """Snapshots and clears the mutator/strategy/evaluator/exporter
    registries around a test, so plugin registrations made during the
    test can't leak into (or collide with) built-in aliases or other
    tests -- the same isolation `tests/unit/test_mutators.py`'s registry
    tests already rely on, applied across all four registries at once
    since `discover_plugins` can touch any of them in one call."""

    previous = (
        _reset_mutator_registry(),
        _reset_strategy_registry(),
        _reset_evaluator_registry(),
        _reset_exporter_registry(),
    )
    try:
        yield
    finally:
        _restore_mutator_registry(previous[0])
        _restore_strategy_registry(previous[1])
        _restore_evaluator_registry(previous[2])
        _restore_exporter_registry(previous[3])


class TestDiscoverPlugins:
    def test_successfully_loads_and_registers_one_plugin_per_group(self, _clean_registries) -> None:
        mapping = {
            MUTATOR_GROUP: [_FakeEntryPoint("leetspeak", "pkg.mutators:Leetspeak", lambda: _PluginMutator)],
            STRATEGY_GROUP: [_FakeEntryPoint("my_strategy", "pkg.attacks:MyStrategy", lambda: _PluginStrategy)],
            EXPORTER_GROUP: [_FakeEntryPoint("csv", "pkg.reporting:CSVExporter", lambda: _PluginExporter)],
        }
        result = discover_plugins(entry_points_fn=_entry_points_fn(mapping))

        assert not result.failures
        assert len(result.loaded) == 3
        assert mutator_is_registered("leetspeak")
        assert strategy_is_registered("my_strategy")
        assert exporter_is_registered("csv")

    def test_loaded_plugin_records_group_alias_and_qualified_name(self, _clean_registries) -> None:
        mapping = {MUTATOR_GROUP: [_FakeEntryPoint("leetspeak", "pkg.mutators:Leetspeak", lambda: _PluginMutator)]}
        result = discover_plugins(entry_points_fn=_entry_points_fn(mapping))

        assert len(result.loaded) == 1
        plugin = result.loaded[0]
        assert plugin.group == MUTATOR_GROUP
        assert plugin.alias == "leetspeak"
        assert plugin.qualified_name == "pkg.mutators:Leetspeak"
        assert plugin.obj is _PluginMutator

    def test_wrong_base_type_is_a_non_fatal_failure_by_default(self, _clean_registries) -> None:
        mapping = {
            EVALUATOR_GROUP: [
                _FakeEntryPoint("bad-evaluator", "pkg.evaluators:Bad", lambda: _PluginEvaluator)
            ]
        }
        result = discover_plugins(entry_points_fn=_entry_points_fn(mapping))

        assert not result.loaded
        assert len(result.failures) == 1
        assert isinstance(result.failures[0], PluginLoadError)
        assert "bad-evaluator" in str(result.failures[0])

    def test_load_raising_is_a_non_fatal_failure_by_default(self, _clean_registries) -> None:
        def _broken_loader():
            raise ImportError("pkg.mutators module not found")

        mapping = {MUTATOR_GROUP: [_FakeEntryPoint("broken", "pkg.mutators:Broken", _broken_loader)]}
        result = discover_plugins(entry_points_fn=_entry_points_fn(mapping))

        assert not result.loaded
        assert len(result.failures) == 1
        assert "broken" in str(result.failures[0])

    def test_one_bad_plugin_does_not_block_the_others_in_the_same_group(self, _clean_registries) -> None:
        def _broken_loader():
            raise ImportError("boom")

        mapping = {
            MUTATOR_GROUP: [
                _FakeEntryPoint("broken", "pkg.mutators:Broken", _broken_loader),
                _FakeEntryPoint("leetspeak", "pkg.mutators:Leetspeak", lambda: _PluginMutator),
            ]
        }
        result = discover_plugins(entry_points_fn=_entry_points_fn(mapping))

        assert len(result.loaded) == 1
        assert result.loaded[0].alias == "leetspeak"
        assert len(result.failures) == 1
        assert mutator_is_registered("leetspeak")

    def test_strict_mode_raises_on_first_failure_instead_of_collecting(self, _clean_registries) -> None:
        def _broken_loader():
            raise ImportError("boom")

        mapping = {MUTATOR_GROUP: [_FakeEntryPoint("broken", "pkg.mutators:Broken", _broken_loader)]}
        with pytest.raises(PluginLoadError, match="broken"):
            discover_plugins(entry_points_fn=_entry_points_fn(mapping), strict=True)

    def test_unknown_group_is_a_non_fatal_failure_by_default(self, _clean_registries) -> None:
        result = discover_plugins(groups=["cyberjection.not-a-real-group"], entry_points_fn=_entry_points_fn({}))
        assert len(result.failures) == 1
        assert not result.loaded

    def test_no_entry_points_is_a_clean_no_op(self, _clean_registries) -> None:
        result = discover_plugins(entry_points_fn=_entry_points_fn({}))
        assert not result.loaded
        assert not result.failures

    def test_alias_collision_with_a_different_class_is_a_non_fatal_failure(self, _clean_registries) -> None:
        class _OtherPluginMutator(BaseMutator):
            def __init__(self) -> None:
                super().__init__(name="other", description="other")

            def mutate(self, prompt: str) -> str:
                return prompt

        mapping = {
            MUTATOR_GROUP: [
                _FakeEntryPoint("dup", "pkg.mutators:One", lambda: _PluginMutator),
            ]
        }
        discover_plugins(entry_points_fn=_entry_points_fn(mapping))

        mapping2 = {
            MUTATOR_GROUP: [
                _FakeEntryPoint("dup", "pkg.mutators:Two", lambda: _OtherPluginMutator),
            ]
        }
        result = discover_plugins(entry_points_fn=_entry_points_fn(mapping2))
        assert len(result.failures) == 1
        assert not result.loaded


class TestKnownAliasesByGroup:
    def test_returns_all_four_groups(self) -> None:
        aliases = known_aliases_by_group()
        assert set(aliases) == {MUTATOR_GROUP, STRATEGY_GROUP, EVALUATOR_GROUP, EXPORTER_GROUP}

    def test_includes_builtin_aliases(self) -> None:
        aliases = known_aliases_by_group()
        assert "base64" in aliases[MUTATOR_GROUP]
        assert "direct_prompt_injection" in aliases[STRATEGY_GROUP]
        assert "regex" in aliases[EVALUATOR_GROUP]
        assert "sarif" in aliases[EXPORTER_GROUP]

    def test_lists_are_sorted(self) -> None:
        aliases = known_aliases_by_group()
        for group_aliases in aliases.values():
            assert group_aliases == sorted(group_aliases)
