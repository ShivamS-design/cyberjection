"""Dynamic report exporter registry.

Mirrors :mod:`cyberjection.mutators.registry`,
:mod:`cyberjection.attacks.registry`, and
:mod:`cyberjection.evaluators.registry`: lets a report exporter be looked
up by a short format alias (``"json"``, ``"markdown"``, ``"sarif"``)
instead of the CLI's `export` command switching on a hardcoded
if/elif/else chain.

Every built-in exporter implements the same `export(findings, output_path,
*, threshold=7.0)` static-method shape (see
`cyberjection.reporting.exporters.JSONExporter`/`MarkdownExporter` and
`cyberjection.reporting.sarif.SARIFReporter`) and self-registers via
`@register_exporter(...)` at class-definition time; Phase 10's plugin
loader (`cyberjection.plugins.loader`) registers third-party exporters
into this same registry at runtime, discovered via the
``cyberjection.exporters`` entry-point group, so `cyberjection export
--format <plugin-alias>` works without `cyberjection.cli.main` knowing the
plugin exists ahead of time.

Exporters aren't instantiated (`register_mutator`/`register_strategy`/
`register_evaluator` all register instantiable classes) -- every built-in
exporter exposes `export` as a `@staticmethod`, so the registry stores and
returns the class itself rather than building an instance. A plugin
exporter with per-call state should still expose `export` as a
`staticmethod`/`classmethod` to fit this contract.
"""

from __future__ import annotations

from typing import Dict, List, Type


class ExporterRegistrationError(Exception):
    """Raised on invalid registration or lookup of an exporter alias."""


class _ExporterProtocolError(ExporterRegistrationError):
    """Raised when a registered class doesn't expose a callable `export`
    attribute -- the one contract every exporter must satisfy, since this
    registry has no common base class to `issubclass`-check against (see
    module docstring)."""


_REGISTRY: Dict[str, type] = {}


def register_exporter(alias: str):
    """Class decorator registering an exporter class under ``alias``. Any
    class exposing a callable `export` attribute qualifies -- see the
    module docstring for why there's no shared base class to check
    against. Re-registering the same class under the same alias is
    idempotent; registering a *different* class under an alias already in
    use raises :class:`ExporterRegistrationError`."""

    def decorator(cls: Type) -> Type:
        if not callable(getattr(cls, "export", None)):
            raise _ExporterProtocolError(
                f"Cannot register '{alias}': {cls!r} has no callable 'export' attribute."
            )
        existing = _REGISTRY.get(alias)
        if existing is not None and existing is not cls:
            raise ExporterRegistrationError(
                f"Alias '{alias}' is already registered to {existing.__name__}; "
                f"refusing to overwrite with {cls.__name__}."
            )
        _REGISTRY[alias] = cls
        return cls

    return decorator


def is_registered(alias: str) -> bool:
    return alias in _REGISTRY


def get_exporter_class(alias: str) -> type:
    try:
        return _REGISTRY[alias]
    except KeyError as exc:
        raise ExporterRegistrationError(
            f"No exporter registered under alias '{alias}'. "
            f"Known aliases: {list_exporter_aliases()}"
        ) from exc


def list_exporter_aliases() -> List[str]:
    return sorted(_REGISTRY)


def _reset_registry_for_tests() -> Dict[str, type]:
    previous = dict(_REGISTRY)
    _REGISTRY.clear()
    return previous


def _restore_registry_for_tests(previous: Dict[str, type]) -> None:
    _REGISTRY.clear()
    _REGISTRY.update(previous)
