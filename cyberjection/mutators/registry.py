"""Dynamic mutator registry.

Lets mutators be looked up and instantiated by a short alias (e.g.
``"base64"``, ``"unicode_zero_width"``) rather than importing the concrete
class directly, so campaign YAML can declare a mutator chain as a plain list
of strings (see ``StrategyConfig.converters`` in
:mod:`cyberjection.config.schema`).
"""

from __future__ import annotations

from typing import Any, Dict, List, Type

from cyberjection.mutators.base import BaseMutator, MutatorPipeline


class MutatorRegistrationError(Exception):
    """Raised on invalid registration or lookup of a mutator alias."""


_REGISTRY: Dict[str, Type[BaseMutator]] = {}


def register_mutator(alias: str):
    """Class decorator registering a :class:`BaseMutator` subclass under
    ``alias``. Re-registering the same class under the same alias is
    idempotent (safe under repeated module import); registering a
    *different* class under an alias already in use raises
    :class:`MutatorRegistrationError`.
    """

    def decorator(cls: Type[BaseMutator]) -> Type[BaseMutator]:
        if not (isinstance(cls, type) and issubclass(cls, BaseMutator)):
            raise MutatorRegistrationError(
                f"Cannot register '{alias}': {cls!r} is not a BaseMutator subclass."
            )
        existing = _REGISTRY.get(alias)
        if existing is not None and existing is not cls:
            raise MutatorRegistrationError(
                f"Alias '{alias}' is already registered to {existing.__name__}; "
                f"refusing to overwrite with {cls.__name__}."
            )
        _REGISTRY[alias] = cls
        return cls

    return decorator


def get_mutator(alias: str, **kwargs: Any) -> BaseMutator:
    """Instantiate the mutator registered under ``alias``, forwarding
    ``kwargs`` to its constructor."""

    try:
        cls = _REGISTRY[alias]
    except KeyError as exc:
        raise MutatorRegistrationError(
            f"No mutator registered under alias '{alias}'. "
            f"Known aliases: {list_mutator_aliases()}"
        ) from exc
    return cls(**kwargs)


def list_mutator_aliases() -> List[str]:
    """Return every registered mutator alias, sorted for stable output."""

    return sorted(_REGISTRY)


def build_pipeline(aliases: List[str]) -> MutatorPipeline:
    """Convenience factory: build a :class:`MutatorPipeline` from a list of
    registered aliases, in the given order."""

    return MutatorPipeline([get_mutator(alias) for alias in aliases])


def _reset_registry_for_tests() -> Dict[str, Type[BaseMutator]]:
    """Test-only helper: snapshot and clear the registry so tests can
    verify registration/collision behavior without leaking state into
    other tests. Returns the previous registry contents for restoration."""

    previous = dict(_REGISTRY)
    _REGISTRY.clear()
    return previous


def _restore_registry_for_tests(previous: Dict[str, Type[BaseMutator]]) -> None:
    _REGISTRY.clear()
    _REGISTRY.update(previous)
