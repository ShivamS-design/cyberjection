"""Base interface and chaining engine for prompt mutators.

A mutator is a deterministic-by-default string transformer that takes a
seed prompt and returns an obfuscated payload string. Mutators are meant to
be composed: :class:`MutatorPipeline` runs a prompt through an ordered list
of mutators, feeding each mutator's output into the next.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List


class BaseMutator(ABC):
    """Abstract base class for all prompt transformation and obfuscation
    modules.

    Concrete mutators must be pure functions of their input (given the same
    prompt and, where applicable, the same ``seed``, ``mutate`` should
    return the same output) so that generated attack payloads are
    reproducible across runs and safe to log/replay for evaluation.
    """

    def __init__(self, name: str, description: str) -> None:
        self.name = name
        self.description = description

    @abstractmethod
    def mutate(self, prompt: str) -> str:
        """Transform an input prompt string into an obfuscated payload."""
        raise NotImplementedError

    def __repr__(self) -> str:
        return f"{type(self).__name__}(name={self.name!r})"


class MutatorPipeline:
    """Sequencing engine that chains multiple prompt mutators.

    Mutators are applied in list order, each receiving the previous
    mutator's output. Character-level and encoding mutators (Base64) are
    order-sensitive: an encoding mutator should generally run *last* in a
    chain, since any mutator applied after it (homoglyph substitution,
    zero-width injection, letter scrambling) will corrupt the encoded
    payload rather than the underlying attack text.
    """

    def __init__(self, mutators: List[BaseMutator]) -> None:
        self.mutators = list(mutators)

    def execute(self, prompt: str) -> str:
        """Run ``prompt`` through every mutator in sequence and return the
        final transformed payload. An empty pipeline returns the prompt
        unchanged."""

        transformed_prompt = prompt
        for mutator in self.mutators:
            transformed_prompt = mutator.mutate(transformed_prompt)
        return transformed_prompt

    def __len__(self) -> int:
        return len(self.mutators)

    def __iter__(self):
        return iter(self.mutators)

    def __repr__(self) -> str:
        chain = " -> ".join(mutator.name for mutator in self.mutators) or "(empty)"
        return f"MutatorPipeline[{chain}]"
