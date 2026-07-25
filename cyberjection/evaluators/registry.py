"""Dynamic evaluator registry.

Mirrors :mod:`cyberjection.mutators.registry` and
:mod:`cyberjection.attacks.registry`: lets a :class:`BaseEvaluator`
subclass be looked up and instantiated by a short alias (``"regex"``,
``"onnx"``, ``"llm_judge"``) instead of importing the concrete class
directly. Built-in evaluators self-register via `@register_evaluator(...)`
at class-definition time; Phase 10's plugin loader
(`cyberjection.plugins.loader`) registers third-party evaluators into this
same registry at runtime, discovered via the ``cyberjection.evaluators``
entry-point group.

Unlike the mutator and strategy registries, this registry is not (yet)
consulted by `cyberjection.evaluators.cascade.CascadeEvaluator` to build
its fixed three-tier pipeline -- Tier 1/2/3 each have a specific,
load-bearing position in the cascade (deterministic-first,
escalate-on-uncertain) that a registry lookup alone doesn't express. It
exists so a plugin-provided evaluator can be discovered, listed (`
cyberjection plugins`, the Phase 10 dashboard's Plugins page), and
constructed standalone -- wiring one into the cascade itself is left to
whatever code builds a `CascadeEvaluator`, exactly like `tier3=` already
works in `cyberjection.orchestrator.campaign._build_cascade_evaluator`.
"""

from __future__ import annotations

from typing import Any, Dict, List, Type

from cyberjection.evaluators.base import BaseEvaluator


class EvaluatorRegistrationError(Exception):
    """Raised on invalid registration or lookup of an evaluator alias."""


_REGISTRY: Dict[str, Type[BaseEvaluator]] = {}


def register_evaluator(alias: str):
    """Class decorator registering a :class:`BaseEvaluator` subclass under
    ``alias``. Re-registering the same class under the same alias is
    idempotent; registering a *different* class under an alias already in
    use raises :class:`EvaluatorRegistrationError`."""

    def decorator(cls: Type[BaseEvaluator]) -> Type[BaseEvaluator]:
        if not (isinstance(cls, type) and issubclass(cls, BaseEvaluator)):
            raise EvaluatorRegistrationError(
                f"Cannot register '{alias}': {cls!r} is not a BaseEvaluator subclass."
            )
        existing = _REGISTRY.get(alias)
        if existing is not None and existing is not cls:
            raise EvaluatorRegistrationError(
                f"Alias '{alias}' is already registered to {existing.__name__}; "
                f"refusing to overwrite with {cls.__name__}."
            )
        _REGISTRY[alias] = cls
        return cls

    return decorator


def is_registered(alias: str) -> bool:
    return alias in _REGISTRY


def get_evaluator_class(alias: str) -> Type[BaseEvaluator]:
    try:
        return _REGISTRY[alias]
    except KeyError as exc:
        raise EvaluatorRegistrationError(
            f"No evaluator registered under alias '{alias}'. "
            f"Known aliases: {list_evaluator_aliases()}"
        ) from exc


def build_evaluator(alias: str, **kwargs: Any) -> BaseEvaluator:
    """Instantiate the evaluator registered under ``alias``, forwarding
    ``kwargs`` to its constructor."""

    cls = get_evaluator_class(alias)
    return cls(**kwargs)


def list_evaluator_aliases() -> List[str]:
    return sorted(_REGISTRY)


def _reset_registry_for_tests() -> Dict[str, Type[BaseEvaluator]]:
    previous = dict(_REGISTRY)
    _REGISTRY.clear()
    return previous


def _restore_registry_for_tests(previous: Dict[str, Type[BaseEvaluator]]) -> None:
    _REGISTRY.clear()
    _REGISTRY.update(previous)
