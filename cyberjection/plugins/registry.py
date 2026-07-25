"""Cross-cutting read-only view over the four subsystem registries.

`cyberjection.mutators.registry`, `cyberjection.attacks.registry`,
`cyberjection.evaluators.registry`, and `cyberjection.reporting.registry`
each already expose their own `list_*_aliases()` function; this module
just combines all four into the single shape the CLI's `plugins list`
command and the Phase 10 API's `/api/plugins` endpoint both want, so
neither has to know about every individual registry module.
"""

from __future__ import annotations

from typing import Dict, List

from cyberjection.attacks.registry import list_strategy_aliases
from cyberjection.evaluators.registry import list_evaluator_aliases
from cyberjection.mutators.registry import list_mutator_aliases
from cyberjection.plugins.base import (
    EVALUATOR_GROUP,
    EXPORTER_GROUP,
    MUTATOR_GROUP,
    STRATEGY_GROUP,
)
from cyberjection.reporting.registry import list_exporter_aliases

# Maps each plugin group name to the function that lists every alias
# currently registered for it (built-in aliases plus anything a prior
# `cyberjection.plugins.loader.discover_plugins()` call registered).
_ALIAS_LISTERS = {
    MUTATOR_GROUP: list_mutator_aliases,
    STRATEGY_GROUP: list_strategy_aliases,
    EVALUATOR_GROUP: list_evaluator_aliases,
    EXPORTER_GROUP: list_exporter_aliases,
}


def known_aliases_by_group() -> Dict[str, List[str]]:
    """Returns every registered alias in every subsystem registry, keyed
    by plugin group name, each list sorted for stable output."""

    return {group: sorted(lister()) for group, lister in _ALIAS_LISTERS.items()}
