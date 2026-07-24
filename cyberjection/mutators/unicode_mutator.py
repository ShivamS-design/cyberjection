"""Unicode-based obfuscation mutators: zero-width space injection and
Latin -> Cyrillic/Greek homoglyph substitution."""

from __future__ import annotations

import random
from typing import Optional

from cyberjection.mutators.base import BaseMutator
from cyberjection.mutators.registry import register_mutator

ZERO_WIDTH_SPACE = "​"


@register_mutator("unicode_zero_width")
class UnicodeZeroWidthMutator(BaseMutator):
    """Injects zero-width space characters (U+200B) between letters to
    bypass exact-string-match filters while remaining visually identical
    (and semantically identical, to the target model's tokenizer/renderer
    in most cases) to the original text.

    ``insertion_rate`` and ``seed`` control the transformation. A mutator is
    expected to be reproducible: this class uses a private
    :class:`random.Random` instance seeded per-instance rather than the
    shared global ``random`` module, so passing the same ``seed`` always
    produces the same output and running mutators concurrently never
    perturbs unrelated code's random state.
    """

    def __init__(self, insertion_rate: float = 0.4, seed: Optional[int] = None) -> None:
        super().__init__(
            name="unicode_zero_width",
            description="Injects invisible zero-width spaces into words.",
        )
        if not 0.0 <= insertion_rate <= 1.0:
            raise ValueError("insertion_rate must be between 0.0 and 1.0")
        self.insertion_rate = insertion_rate
        self.seed = seed
        self._rng = random.Random(seed)

    def mutate(self, prompt: str) -> str:
        return "".join(
            char + (ZERO_WIDTH_SPACE if self._rng.random() < self.insertion_rate else "")
            for char in prompt
        )


@register_mutator("homoglyph")
class HomoglyphMutator(BaseMutator):
    """Replaces standard Latin characters with visually identical
    Cyrillic/Greek homoglyphs, evading keyword filters that operate on the
    literal Latin-alphabet substrings without normalizing confusable
    scripts (see Unicode TR39)."""

    HOMOGLYPH_MAP = {
        "a": "а", "c": "с", "e": "е", "i": "і", "j": "ϳ",
        "o": "о", "p": "р", "s": "ѕ", "x": "х", "y": "у",
        "A": "А", "B": "В", "C": "С", "E": "Е", "H": "Н",
        "K": "К", "M": "М", "O": "О", "P": "Р", "T": "Т",
        "X": "Х", "Y": "Ү",
    }

    def __init__(self, substitution_rate: float = 1.0, seed: Optional[int] = None) -> None:
        super().__init__(
            name="homoglyph",
            description="Replaces Latin characters with Cyrillic/Greek homoglyphs.",
        )
        if not 0.0 <= substitution_rate <= 1.0:
            raise ValueError("substitution_rate must be between 0.0 and 1.0")
        self.substitution_rate = substitution_rate
        self.seed = seed
        self._rng = random.Random(seed)

    def mutate(self, prompt: str) -> str:
        if self.substitution_rate >= 1.0:
            return "".join(self.HOMOGLYPH_MAP.get(char, char) for char in prompt)
        return "".join(
            self.HOMOGLYPH_MAP.get(char, char)
            if char in self.HOMOGLYPH_MAP and self._rng.random() < self.substitution_rate
            else char
            for char in prompt
        )
