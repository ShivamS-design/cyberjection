"""Pure-Python Aho-Corasick automaton for multi-pattern substring matching.

Used by the Tier 1 regex evaluator to scan a response against a curated
list of refusal phrases in a single left-to-right pass. Building a trie
with failure links means matching cost is O(len(text) + number of matches)
regardless of how many phrases are registered, versus O(patterns *
len(text)) for testing each phrase independently -- the standard approach
for keyword/phrase blocklist scanning.

No third-party dependency (e.g. `pyahocorasick`) is required.
"""

from __future__ import annotations

from collections import deque
from typing import Dict, Iterator, List, NamedTuple, Optional


class Match(NamedTuple):
    """A single pattern occurrence found in the scanned text."""

    pattern: str
    start: int
    end: int  # exclusive


class _Node:
    __slots__ = ("children", "fail", "output")

    def __init__(self) -> None:
        self.children: Dict[str, "_Node"] = {}
        self.fail: Optional["_Node"] = None
        self.output: List[str] = []


class AhoCorasick:
    """Multi-pattern substring matcher built once, queried many times.

    Patterns are treated as literal substrings (not regexes). Matching is
    case-insensitive by default, matching how refusal-phrase detection is
    meant to behave (a model that says "I Cannot Assist" should trigger the
    same rule as "i cannot assist").
    """

    def __init__(self, patterns: List[str], *, case_insensitive: bool = True) -> None:
        self.case_insensitive = case_insensitive
        self._root = _Node()
        # Preserve original casing for reporting; normalize only for matching.
        self._patterns = [p for p in patterns if p]
        for pattern in self._patterns:
            self._insert(pattern.lower() if case_insensitive else pattern)
        self._build_fail_links()

    def _insert(self, pattern: str) -> None:
        node = self._root
        for char in pattern:
            node = node.children.setdefault(char, _Node())
        if pattern not in node.output:
            node.output.append(pattern)

    def _build_fail_links(self) -> None:
        queue: deque = deque()
        for child in self._root.children.values():
            child.fail = self._root
            queue.append(child)

        while queue:
            current = queue.popleft()
            for char, child in current.children.items():
                queue.append(child)
                fallback = current.fail
                while fallback is not None and char not in fallback.children:
                    fallback = fallback.fail
                child.fail = fallback.children[char] if fallback is not None else self._root
                if child.fail is child:
                    # Root's own self-referencing children: fail back to root.
                    child.fail = self._root
                # Merge in the output of whatever this node fails back to,
                # so a match ending here also reports shorter suffix matches
                # (e.g. "hers" ending also reports "he" ending at the same spot
                # only if "he" is itself a registered pattern reachable via fail links).
                if child.fail.output:
                    child.output = child.output + [
                        p for p in child.fail.output if p not in child.output
                    ]

    def search(self, text: str) -> Iterator[Match]:
        """Yield every (possibly overlapping) pattern occurrence in `text`,
        in left-to-right order of match end position."""

        if not self._patterns:
            return
        haystack = text.lower() if self.case_insensitive else text
        node = self._root
        for i, char in enumerate(haystack):
            while node is not self._root and char not in node.children:
                node = node.fail  # type: ignore[assignment]
            node = node.children.get(char, self._root)
            for pattern in node.output:
                start = i - len(pattern) + 1
                yield Match(pattern=pattern, start=start, end=i + 1)

    def first_match(self, text: str) -> Optional[Match]:
        """Return the first match by end position, or None."""

        for match in self.search(text):
            return match
        return None

    def __len__(self) -> int:
        return len(self._patterns)

    def __repr__(self) -> str:
        return f"AhoCorasick({len(self._patterns)} patterns)"
