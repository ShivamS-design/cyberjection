"""Shared plugin data structures: the entry-point group vocabulary and the
record type describing one successfully loaded third-party plugin.

Cyberjection's pluggable architecture (Task 10.1) reuses the four
subsystem registries that already existed before this phase --
`cyberjection.mutators.registry`, `cyberjection.attacks.registry`,
`cyberjection.evaluators.registry`, `cyberjection.reporting.registry` --
rather than introducing a fifth, parallel plugin-specific registry. This
module only adds the vocabulary needed to *discover* third-party
implementations of those four kinds via Python packaging entry points and
route each one to the registry that already knows how to validate and
store it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# One entry-point group per pluggable subsystem. A third-party
# distribution advertises a plugin by adding, e.g.,
#
#   [project.entry-points."cyberjection.mutators"]
#   leetspeak = "my_package.mutators:LeetspeakMutator"
#
# to its own `pyproject.toml`. The dict value on each line below is the
# registrar Cyberjection calls with `(alias, loaded_object)` once the
# entry point resolves -- see `cyberjection.plugins.loader`.
MUTATOR_GROUP = "cyberjection.mutators"
STRATEGY_GROUP = "cyberjection.strategies"
EVALUATOR_GROUP = "cyberjection.evaluators"
EXPORTER_GROUP = "cyberjection.exporters"

ALL_PLUGIN_GROUPS = (MUTATOR_GROUP, STRATEGY_GROUP, EVALUATOR_GROUP, EXPORTER_GROUP)


@dataclass(frozen=True)
class LoadedPlugin:
    """One third-party plugin successfully discovered and registered.

    `qualified_name` is the entry point's own `module:attribute` value
    (`importlib.metadata.EntryPoint.value`), kept for diagnostics -- it's
    what a user would need to find the plugin's source when reporting a
    bug, independent of whichever alias it happens to be registered under.
    """

    group: str
    alias: str
    qualified_name: str
    obj: Any
