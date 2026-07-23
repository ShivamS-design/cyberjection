"""Shared asynchronous execution structures.

`ExecutionContext` and `StrategyResult` are the common runtime data
structures passed through the pipeline: orchestrator -> attack strategy ->
target provider -> evaluator (per the System Design Document, section 4.1).
Phase 1 only needs the target-facing half of the pipeline (provider calls),
so these definitions live here as the shared foundation that Phase 2+
(attacks/base.py) will import rather than redefine.
"""

from __future__ import annotations

from typing import Any, Dict, List

from pydantic import BaseModel, Field


class ExecutionContext(BaseModel):
    """Runtime metadata threaded through a single test's execution."""

    campaign_id: str
    test_id: str
    target_name: str
    max_turns: int = 10
    max_cost_limit: float = 5.0


class StrategyResult(BaseModel):
    """Outcome of executing an attack strategy against a target."""

    success: bool
    score: float = Field(ge=0.0, le=1.0)
    total_turns: int
    logs: List[Dict[str, Any]] = Field(default_factory=list)
