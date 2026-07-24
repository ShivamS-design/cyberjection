"""Attack strategy modules: single-turn framings (Phase 2) and stateful
multi-turn engines (Phase 5).

Single-turn strategies frame a seed prompt as an attack payload (override
framing, roleplay jailbreak, system-prompt extraction probe), run it
through a configured :class:`~cyberjection.mutators.base.MutatorPipeline`,
and dispatch it through the Phase 1 target gateway
(:class:`~cyberjection.providers.litellm_provider.LiteLLMTarget`).

Multi-turn engines (`CrescendoEngine`, `TAPEngine`) instead own a growing
:class:`~cyberjection.attacks.state.ConversationContext` across many turns,
using an :class:`~cyberjection.attacks.attacker.AttackerAgent` to generate
adaptive follow-up prompts and the Phase 3
:class:`~cyberjection.evaluators.cascade.CascadeEvaluator` to judge each
exchange and drive escalation, pruning, and backtracking decisions.
"""

from __future__ import annotations

from cyberjection.attacks.attacker import AttackerAgent, AttackerResponse
from cyberjection.attacks.base import BaseStrategy, ExecutionContext, SingleTurnResult
from cyberjection.attacks.crescendo import CrescendoEngine
from cyberjection.attacks.jailbreak import JailbreakStrategy
from cyberjection.attacks.prompt_injection import DirectPromptInjectionStrategy
from cyberjection.attacks.state import (
    AttackNode,
    ConversationContext,
    TurnStatus,
    score_from_evaluation,
)
from cyberjection.attacks.system_extraction import SystemPromptExtractionStrategy
from cyberjection.attacks.tap import TAPEngine

__all__ = [
    "BaseStrategy",
    "ExecutionContext",
    "SingleTurnResult",
    "DirectPromptInjectionStrategy",
    "JailbreakStrategy",
    "SystemPromptExtractionStrategy",
    "AttackNode",
    "ConversationContext",
    "TurnStatus",
    "score_from_evaluation",
    "AttackerAgent",
    "AttackerResponse",
    "CrescendoEngine",
    "TAPEngine",
]
