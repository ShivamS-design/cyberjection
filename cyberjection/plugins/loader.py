"""Third-party plugin discovery via Python packaging entry points.

Cyberjection's four pluggable subsystems (mutators, single-turn strategies,
evaluators, report exporters) each already expose a registry a built-in
implementation self-registers into at import time (see
`cyberjection.mutators.registry` and its three siblings). This module is
the other half: at process startup (or on demand, e.g. `cyberjection
plugins list`), `discover_plugins` scans every distribution installed in
the current environment for entry points advertised under one of the four
groups in `cyberjection.plugins.base.ALL_PLUGIN_GROUPS`, imports the
referenced object, and registers it into the matching subsystem registry
under the entry point's own name -- so a plugin-provided
`StrategyConfig.type` or `--format` alias works exactly like a built-in
one everywhere downstream (`cyberjection.orchestrator.campaign`,
`cyberjection.cli.main export`, ...) without those call sites knowing the
plugin exists ahead of time.

Discovery is deliberately best-effort by default (`strict=False`): one
malformed or broken third-party plugin shouldn't prevent every other
plugin -- or every built-in feature -- from working. Each failure is
still captured (as a `PluginLoadError`) rather than silently swallowed, so
`cyberjection plugins list` and the Phase 10 dashboard's Plugins page can
surface exactly which plugin failed and why.
"""

from __future__ import annotations

import importlib.metadata
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional

from cyberjection.attacks.registry import register_strategy
from cyberjection.evaluators.registry import register_evaluator
from cyberjection.mutators.registry import register_mutator
from cyberjection.plugins.base import (
    ALL_PLUGIN_GROUPS,
    EVALUATOR_GROUP,
    EXPORTER_GROUP,
    MUTATOR_GROUP,
    STRATEGY_GROUP,
    LoadedPlugin,
)
from cyberjection.reporting.registry import register_exporter
from cyberjection.utils.exceptions import PluginLoadError

# Each registrar has the same shape as the class decorators it wraps:
# `registrar(alias)(obj)` registers `obj` under `alias` in that
# subsystem's registry (raising that registry's own `*RegistrationError`
# subclass on an incompatible type or a colliding alias), and returns the
# now-registered object unchanged. Reusing the decorator functions
# directly -- rather than duplicating their validation -- means a plugin
# is held to exactly the same contract a built-in implementation is.
_REGISTRARS: Dict[str, Callable[[str], Callable[[Any], Any]]] = {
    MUTATOR_GROUP: register_mutator,
    STRATEGY_GROUP: register_strategy,
    EVALUATOR_GROUP: register_evaluator,
    EXPORTER_GROUP: register_exporter,
}

# Default entry-point lookup: `importlib.metadata.entry_points(group=...)`.
# Exposed as a parameter default (rather than being hardcoded inside the
# loop) purely so tests can inject a fake list of entry points without
# needing a real installed distribution -- see `tests/unit/test_plugins.py`.
EntryPointsFn = Callable[[str], Iterable[Any]]


def _default_entry_points(group: str) -> Iterable[Any]:
    return importlib.metadata.entry_points(group=group)


@dataclass
class DiscoveryResult:
    """Outcome of one `discover_plugins` call: every plugin that loaded
    and registered successfully, plus every failure encountered along the
    way (empty in `strict=True` mode, since that mode raises on the first
    failure instead of collecting it)."""

    loaded: List[LoadedPlugin] = field(default_factory=list)
    failures: List[PluginLoadError] = field(default_factory=list)


def discover_plugins(
    *,
    groups: Iterable[str] = ALL_PLUGIN_GROUPS,
    entry_points_fn: Optional[EntryPointsFn] = None,
    strict: bool = False,
) -> DiscoveryResult:
    """Scans `groups` (default: all four plugin groups) for entry points,
    imports each referenced object, and registers it into the matching
    subsystem registry under the entry point's own name.

    With `strict=False` (the default), a failure loading or registering
    one entry point is recorded in the returned `DiscoveryResult.failures`
    list and discovery continues with the next one. With `strict=True`,
    the first failure is raised immediately as a `PluginLoadError`.
    """

    resolve = entry_points_fn or _default_entry_points
    result = DiscoveryResult()

    for group in groups:
        registrar = _REGISTRARS.get(group)
        if registrar is None:
            # Not one of the four groups this loader knows how to route --
            # unreachable via the default `groups=ALL_PLUGIN_GROUPS`, but a
            # caller passing a custom `groups` iterable could hit this.
            error = PluginLoadError(
                f"No registrar configured for entry-point group '{group}'."
            )
            if strict:
                raise error
            result.failures.append(error)
            continue

        try:
            entry_points = list(resolve(group))
        except Exception as exc:  # pragma: no cover - defensive; importlib.metadata is stable
            error = PluginLoadError(
                f"Failed to enumerate entry points for group '{group}': {exc}"
            )
            if strict:
                raise error
            result.failures.append(error)
            continue

        for entry_point in entry_points:
            try:
                loaded_obj = entry_point.load()
                registrar(entry_point.name)(loaded_obj)
            except Exception as exc:
                error = PluginLoadError(
                    f"Failed to load plugin '{entry_point.name}' from group '{group}' "
                    f"({getattr(entry_point, 'value', '<unknown>')}): {exc}"
                )
                if strict:
                    raise error
                result.failures.append(error)
                continue

            result.loaded.append(
                LoadedPlugin(
                    group=group,
                    alias=entry_point.name,
                    qualified_name=getattr(entry_point, "value", "<unknown>"),
                    obj=loaded_obj,
                )
            )

    return result
