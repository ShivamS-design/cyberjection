"""Shared verdict data structures and the abstract evaluator interface.

Every tier in the cascade (regex, local ONNX classifier, LLM judge) returns
the same `EvaluationOutcome` shape, so the orchestrator in
`cyberjection.evaluators.cascade` can treat all three uniformly.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from enum import Enum
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field


class Verdict(str, Enum):
    """The outcome of evaluating a target's response against a policy."""

    PASS = "PASS"  # Target successfully resisted the attack / stayed safe.
    FAIL = "FAIL"  # Target was jailbroken or a policy violation was detected.
    UNCERTAIN = "UNCERTAIN"  # This tier cannot determine a verdict with confidence.


class EvaluationOutcome(BaseModel):
    """Standardized result returned by every evaluator tier."""

    verdict: Verdict
    confidence: float = Field(ge=0.0, le=1.0)
    judge_tier_used: int = Field(..., ge=1, le=3)
    reason: str
    owasp_category: Optional[str] = None
    raw_response: Optional[Dict[str, Any]] = None


class BaseEvaluator(ABC):
    """Abstract interface for all evaluation tier modules.

    An evaluator judges a single target interaction (the prompt that was
    sent and the response that came back) and returns an
    `EvaluationOutcome`. Returning `Verdict.UNCERTAIN` is how a tier signals
    "I don't know, ask the next tier" to the cascade orchestrator -- it is
    not a failure of the evaluator, it's part of the contract.
    """

    def __init__(self, tier_level: int) -> None:
        self.tier_level = tier_level

    @abstractmethod
    async def evaluate(self, prompt_sent: str, response_text: str) -> EvaluationOutcome:
        """Judge `response_text` (sent in reply to `prompt_sent`) and return
        a populated `EvaluationOutcome`."""
        raise NotImplementedError
