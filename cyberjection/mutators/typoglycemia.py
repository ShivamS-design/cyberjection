"""Typoglycemia mutator: scrambles the interior letters of words while
keeping the first/last characters fixed."""

from __future__ import annotations

import random
import re
from typing import Optional

from cyberjection.mutators.base import BaseMutator
from cyberjection.mutators.registry import register_mutator

_WORD_SPLIT_RE = re.compile(r"(\s+)")


@register_mutator("typoglycemia")
class TypoglycemiaMutator(BaseMutator):
    """Scrambles the internal letters of words longer than 3 characters,
    keeping the first and last characters fixed.

    Exploits the "typoglycemia" reading effect: humans (and LLMs trained on
    human text) can generally still parse a word whose interior letters are
    reordered, as long as the first and last letters stay put. This lets an
    attack payload dodge exact-keyword blocklists while remaining
    semantically legible to the target model.

    Uses a private :class:`random.Random` instance seeded per-instance (not
    the shared global ``random`` module) so a given ``seed`` reproduces the
    exact same scramble every time.
    """

    def __init__(self, seed: Optional[int] = None) -> None:
        super().__init__(
            name="typoglycemia",
            description=(
                "Scrambles inner letters of words while keeping first and "
                "last characters fixed."
            ),
        )
        self.seed = seed
        self._rng = random.Random(seed)

    def _scramble_word(self, word: str) -> str:
        if len(word) <= 3 or not word.isalpha():
            return word
        first, middle, last = word[0], list(word[1:-1]), word[-1]
        self._rng.shuffle(middle)
        return first + "".join(middle) + last

    def mutate(self, prompt: str) -> str:
        words = _WORD_SPLIT_RE.split(prompt)
        return "".join(self._scramble_word(word) for word in words)
