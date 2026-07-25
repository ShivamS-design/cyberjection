"""Plugin architecture (Phase 10): entry-point-based discovery for
third-party mutators, single-turn strategies, evaluators, and report
exporters.

There is no fifth, plugin-specific registry here -- a plugin is just a
class that gets routed, via `discover_plugins`, into the exact same
registry a built-in implementation already registers itself into at
import time (`cyberjection.mutators.registry`,
`cyberjection.attacks.registry`, `cyberjection.evaluators.registry`,
`cyberjection.reporting.registry`). This keeps "is this alias valid" a
single source of truth per subsystem, rather than a plugin registry that
could disagree with the subsystem it's supposedly extending.
"""

from __future__ import annotations

from cyberjection.plugins.base import (
    ALL_PLUGIN_GROUPS,
    EVALUATOR_GROUP,
    EXPORTER_GROUP,
    MUTATOR_GROUP,
    STRATEGY_GROUP,
    LoadedPlugin,
)
from cyberjection.plugins.loader import DiscoveryResult, discover_plugins
from cyberjection.plugins.registry import known_aliases_by_group

__all__ = [
    "ALL_PLUGIN_GROUPS",
    "MUTATOR_GROUP",
    "STRATEGY_GROUP",
    "EVALUATOR_GROUP",
    "EXPORTER_GROUP",
    "LoadedPlugin",
    "DiscoveryResult",
    "discover_plugins",
    "known_aliases_by_group",
]
