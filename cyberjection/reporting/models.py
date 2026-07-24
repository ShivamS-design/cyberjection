"""Typed shapes shared across every Phase 6 reporter.

`Finding` replaces the raw `dict` result shape sketched in the Phase 6
design spec's CLI artifact: every exporter (SARIF, JSON, Markdown) and the
quality gate consumed that dict via bare string-key lookups
(`item["rule_id"]`, `item["score"]`, ...), which fails at export time --
after a real evaluation run has already spent real target/attacker/judge
calls -- if a producer ever forgets a key or misspells one, instead of
failing immediately at construction the way a typed model does. Kept as a
plain Pydantic model (rather than reusing Phase 5's `AttackNode`) because a
`Finding` is a reporting-layer summary, not a conversation-tree node -- it
has no `parent_id`/`depth` and does not need to survive backtracking.
"""

from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel, Field


class Finding(BaseModel):
    """One rule evaluation result, the unit every Phase 6 exporter emits."""

    rule_id: str
    category: str
    score: float = Field(ge=0.0, le=10.0)
    details: str
    location: str = Field(
        default="config/security_policy.yaml",
        description="Artifact URI this finding is attributed to, for SARIF's physicalLocation.",
    )


class QualityGateResult(BaseModel):
    """The outcome of evaluating a set of findings against a threshold --
    the CLI's exit-code decision, factored out into a plain, synchronous,
    fully unit-testable value rather than being decided inline inside the
    `run` command alongside argument parsing and terminal rendering."""

    passed: bool
    threshold: float
    max_score: float
    failing_findings: List[Finding] = Field(default_factory=list)

    @property
    def exit_code(self) -> int:
        return 0 if self.passed else 1
