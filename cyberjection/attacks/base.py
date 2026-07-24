"""Abstract strategy interface and execution context for single-turn
attacks.

A strategy takes a seed prompt, frames it as an attack payload, mutates it
through a configured pipeline, and dispatches it to a target. This module
defines the shared contract every attack strategy implements, so the
(future) campaign runner can execute any strategy uniformly.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field

from cyberjection.mutators.base import MutatorPipeline
from cyberjection.providers.litellm_provider import LiteLLMTarget, TargetResponse


class ExecutionContext(BaseModel):
    """Per-test metadata threaded through a strategy execution: which test
    is running, which target it's aimed at, which OWASP LLM Top 10 category
    it exercises, and a soft per-test cost ceiling enforced by later-phase
    budget tracking."""

    test_id: str
    target_id: str
    owasp_category: str = "LLM01_PROMPT_INJECTION"
    max_cost_limit: float = 5.0


class SingleTurnResult(BaseModel):
    """Standardized outcome of a single-turn attack execution, ready to be
    handed to the (future) evaluation cascade."""

    test_id: str
    original_prompt: str
    mutated_prompt: str
    target_response: str
    latency_ms: float
    tokens_used: int
    raw_response: Dict[str, Any] = Field(default_factory=dict)


class BaseStrategy(ABC):
    """Abstract interface for all attack strategies.

    Subclasses implement :meth:`execute`: frame the seed prompt as an
    attack payload, then call :meth:`_apply_mutations` (rather than calling
    ``self.mutator_pipeline.execute`` directly) so every strategy applies
    its configured mutation pipeline the same way.
    """

    def __init__(self, strategy_id: str, mutator_pipeline: Optional[MutatorPipeline] = None) -> None:
        self.strategy_id = strategy_id
        self.mutator_pipeline = mutator_pipeline or MutatorPipeline([])

    def _apply_mutations(self, framed_prompt: str) -> str:
        """Mutation injection pre-hook: run a framed prompt through this
        strategy's configured mutator pipeline before it is sent to the
        target endpoint. An empty pipeline is a no-op passthrough."""

        return self.mutator_pipeline.execute(framed_prompt)

    @staticmethod
    def _to_result(
        *,
        context: ExecutionContext,
        original_prompt: str,
        mutated_prompt: str,
        response: TargetResponse,
    ) -> SingleTurnResult:
        """Shared helper: normalize a `TargetResponse` into a
        `SingleTurnResult` for the given execution context."""

        return SingleTurnResult(
            test_id=context.test_id,
            original_prompt=original_prompt,
            mutated_prompt=mutated_prompt,
            target_response=response.content,
            latency_ms=response.metrics.latency_ms,
            tokens_used=response.metrics.total_tokens,
            raw_response=response.raw_response,
        )

    @abstractmethod
    async def execute(
        self,
        target: LiteLLMTarget,
        seed_prompt: str,
        context: ExecutionContext,
    ) -> SingleTurnResult:
        """Frame, mutate, and dispatch ``seed_prompt`` against ``target``,
        returning a populated :class:`SingleTurnResult`."""

        raise NotImplementedError
