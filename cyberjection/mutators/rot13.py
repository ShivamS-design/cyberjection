"""Substitution-cipher mutators: ROT13 and the general Caesar-cipher case."""

from __future__ import annotations

from typing import Optional

from cyberjection.mutators.base import BaseMutator
from cyberjection.mutators.registry import register_mutator

_ALPHA_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
_ALPHA_LOWER = "abcdefghijklmnopqrstuvwxyz"


class CaesarCipherMutator(BaseMutator):
    """Applies a Caesar (shift) substitution cipher to obscure payload
    intent from plaintext keyword scanners; non-alphabetic characters
    (digits, punctuation, whitespace, non-Latin scripts) pass through
    unchanged. ``shift=13`` is ROT13, its own inverse."""

    def __init__(self, shift: int = 13, name: str = "caesar", description: Optional[str] = None):
        super().__init__(
            name=name,
            description=description or f"Applies a Caesar cipher with shift={shift}.",
        )
        self.shift = shift % 26
        self._upper_table = str.maketrans(
            _ALPHA_UPPER, _ALPHA_UPPER[self.shift:] + _ALPHA_UPPER[: self.shift]
        )
        self._lower_table = str.maketrans(
            _ALPHA_LOWER, _ALPHA_LOWER[self.shift:] + _ALPHA_LOWER[: self.shift]
        )

    def mutate(self, prompt: str) -> str:
        return prompt.translate(self._upper_table).translate(self._lower_table)


@register_mutator("rot13")
class ROT13Mutator(CaesarCipherMutator):
    """ROT13: the special-case Caesar cipher with shift 13, its own
    inverse, so applying it twice returns the original text."""

    def __init__(self) -> None:
        super().__init__(
            shift=13,
            name="rot13",
            description="Applies a ROT13 substitution cipher to obscure payload intent.",
        )
