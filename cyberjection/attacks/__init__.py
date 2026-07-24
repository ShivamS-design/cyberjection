"""Single-turn attack strategy modules.

Each strategy frames a seed prompt as an attack payload (override framing,
roleplay jailbreak, system-prompt extraction probe), runs it through a
configured :class:`~cyberjection.mutators.base.MutatorPipeline`, and
dispatches it through the Phase 1 target gateway
(:class:`~cyberjection.providers.litellm_provider.LiteLLMTarget`).
"""

from __future__ import annotations

from cyberjection.attacks.base import BaseStrategy, ExecutionContext, SingleTurnResult
from cyberjection.attacks.jailbreak import JailbreakStrategy
from cyberjection.attacks.prompt_injection import DirectPromptInjectionStrategy
from cyberjection.attacks.system_extraction import SystemPromptExtractionStrategy

__all__ = [
    "BaseStrategy",
    "ExecutionContext",
    "SingleTurnResult",
    "DirectPromptInjectionStrategy",
    "JailbreakStrategy",
    "SystemPromptExtractionStrategy",
]
