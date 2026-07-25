"""Dynamic single-turn strategy registry.

Mirrors :mod:`cyberjection.mutators.registry` exactly (same registration
semantics, same idempotent-re-registration/collision rules): lets a
:class:`~cyberjection.attacks.base.BaseStrategy` subclass be looked up and
instantiated by a short alias (e.g. ``"direct_prompt_injection"``,
``"jailbreak"``) rather than the orchestrator importing every concrete
strategy class and switching on `StrategyConfig.type` directly.

Built-in strategies register themselves via `@register_strategy(...)` at
class-definition time in their own modules (`prompt_injection.py`,
`jailbreak.py`, `system_extraction.py`); importing
:mod:`cyberjection.attacks` (which every one of those modules is imported
by, as a side effect documented in that package's own `__init__.py`)
guarantees they're registered before anything looks one up. Phase 10's
plugin loader (`cyberjection.plugins.loader`) registers third-party
strategies into this same registry at runtime, discovered via the
``cyberjection.strategies`` entry-point group, so a campaign config can
reference a plugin-provided `StrategyConfig.type` exactly like a built-in
one -- `cyberjection.orchestrator.campaign._build_strategy` doesn't
distinguish between the two.

Multi-turn engines (`CrescendoEngine`, `TAPEngine`) are deliberately not
registered here: they aren't `BaseStrategy` subclasses (see
`cyberjection/attacks/base.py`'s module docstring), and
`cyberjection.orchestrator.campaign` already dispatches them by a fixed
`_MULTI_TURN_STRATEGY_TYPES` name set rather than a factory lookup.
"""

from __future__ import annotations

from typing import Any, Dict, List, Type

from cyberjection.attacks.base import BaseStrategy


class StrategyRegistrationError(Exception):
    """Raised on invalid registration or lookup of a strategy alias."""


_REGISTRY: Dict[str, Type[BaseStrategy]] = {}


def register_strategy(alias: str):
    """Class decorator registering a :class:`BaseStrategy` subclass under
    ``alias``. Re-registering the same class under the same alias is
    idempotent (safe under repeated module import, and lets one class
    answer to more than one alias -- see `JailbreakStrategy`, registered
    under both ``"jailbreak"`` and ``"jailbreak_roleplay"``); registering a
    *different* class under an alias already in use raises
    :class:`StrategyRegistrationError`.
    """

    def decorator(cls: Type[BaseStrategy]) -> Type[BaseStrategy]:
        if not (isinstance(cls, type) and issubclass(cls, BaseStrategy)):
            raise StrategyRegistrationError(
                f"Cannot register '{alias}': {cls!r} is not a BaseStrategy subclass."
            )
        existing = _REGISTRY.get(alias)
        if existing is not None and existing is not cls:
            raise StrategyRegistrationError(
                f"Alias '{alias}' is already registered to {existing.__name__}; "
                f"refusing to overwrite with {cls.__name__}."
            )
        _REGISTRY[alias] = cls
        return cls

    return decorator


def is_registered(alias: str) -> bool:
    """True if ``alias`` resolves to a registered strategy class."""

    return alias in _REGISTRY


def get_strategy_class(alias: str) -> Type[BaseStrategy]:
    """Returns the :class:`BaseStrategy` subclass registered under
    ``alias`` without instantiating it."""

    try:
        return _REGISTRY[alias]
    except KeyError as exc:
        raise StrategyRegistrationError(
            f"No strategy registered under alias '{alias}'. "
            f"Known aliases: {list_strategy_aliases()}"
        ) from exc


def build_strategy(alias: str, **kwargs: Any) -> BaseStrategy:
    """Instantiate the strategy registered under ``alias``, forwarding
    ``kwargs`` (typically ``mutator_pipeline=...``) to its constructor."""

    cls = get_strategy_class(alias)
    return cls(**kwargs)


def list_strategy_aliases() -> List[str]:
    """Return every registered strategy alias, sorted for stable output."""

    return sorted(_REGISTRY)


def _reset_registry_for_tests() -> Dict[str, Type[BaseStrategy]]:
    """Test-only helper: snapshot and clear the registry so tests can
    verify registration/collision behavior without leaking state into
    other tests. Returns the previous registry contents for restoration."""

    previous = dict(_REGISTRY)
    _REGISTRY.clear()
    return previous


def _restore_registry_for_tests(previous: Dict[str, Type[BaseStrategy]]) -> None:
    _REGISTRY.clear()
    _REGISTRY.update(previous)
