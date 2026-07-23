"""Abstract target interface.

Every provider adapter (LiteLLM-backed models, custom HTTP endpoints added
in a later phase, etc.) implements this async interface so the orchestrator
and attack engine never need to know which concrete provider they are
talking to.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from cyberjection.providers.litellm_provider import TargetResponse


class BaseTarget(ABC):
    """Abstract base class for all target (system-under-test) adapters."""

    @abstractmethod
    async def generate(
        self,
        prompt: str,
        system_prompt_override: Optional[str] = None,
    ) -> "TargetResponse":
        """Send `prompt` to the target and return a normalized response.

        Implementations must not raise raw provider SDK exceptions; failures
        should be translated into `cyberjection.utils.exceptions` types.
        """

        raise NotImplementedError
