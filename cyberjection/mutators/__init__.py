"""Prompt mutation and obfuscation pipeline.

Importing this package registers every built-in mutator (see
:mod:`cyberjection.mutators.registry`) under its short alias, so campaign
configuration can reference mutators by name (e.g. ``"base64"``,
``"homoglyph"``) without importing the concrete classes directly.
"""

from __future__ import annotations

from cyberjection.mutators.base import BaseMutator, MutatorPipeline
from cyberjection.mutators.registry import (
    MutatorRegistrationError,
    build_pipeline,
    get_mutator,
    list_mutator_aliases,
    register_mutator,
)

# Import side effect: each module below registers its mutator classes with
# the alias registry on import.
from cyberjection.mutators import base64_mutator  # noqa: F401,E402
from cyberjection.mutators import rot13  # noqa: F401,E402
from cyberjection.mutators import typoglycemia  # noqa: F401,E402
from cyberjection.mutators import unicode_mutator  # noqa: F401,E402

__all__ = [
    "BaseMutator",
    "MutatorPipeline",
    "MutatorRegistrationError",
    "build_pipeline",
    "get_mutator",
    "list_mutator_aliases",
    "register_mutator",
]
