"""3-tier cascade evaluation pipeline.

Tier 1 (`regex.RegexEvaluator`) is a zero-cost deterministic pass; Tier 2
(`llamaguard.LocalONNXGuardEvaluator`) is a local, low-latency classifier;
Tier 3 (`llmjudge.LLMJudgeEvaluator`) is a structured-output LLM judge.
`cascade.CascadeEvaluator` chains all three, escalating only on
`Verdict.UNCERTAIN` so the expensive tier is reached only when needed.
"""

from __future__ import annotations

from cyberjection.evaluators.base import BaseEvaluator, EvaluationOutcome, Verdict
from cyberjection.evaluators.cascade import CascadeEvaluator, tiers_invoked_for
from cyberjection.evaluators.llamaguard import LocalONNXGuardEvaluator
from cyberjection.evaluators.llmjudge import LLMJudgeEvaluator, StructuredJudgeResponse
from cyberjection.evaluators.regex import RegexEvaluator

__all__ = [
    "BaseEvaluator",
    "EvaluationOutcome",
    "Verdict",
    "CascadeEvaluator",
    "tiers_invoked_for",
    "LocalONNXGuardEvaluator",
    "LLMJudgeEvaluator",
    "StructuredJudgeResponse",
    "RegexEvaluator",
]
