"""Unified exception hierarchy for Cyberjection.

All provider-specific and configuration-specific failures are normalized
into these types so orchestration code (later phases) and CLI/API error
handlers (later phases) only need to catch one family of exceptions rather
than every underlying HTTP/YAML/Pydantic library's native error types.
"""

from __future__ import annotations

from typing import Optional


class CyberjectionException(Exception):
    """Base class for all Cyberjection-raised errors."""

    def __init__(self, message: str, *, target_id: Optional[str] = None) -> None:
        self.target_id = target_id
        prefix = f"[{target_id}] " if target_id else ""
        super().__init__(f"{prefix}{message}")


class ConfigValidationError(CyberjectionException):
    """Raised for malformed YAML, unresolved env vars, or schema violations."""


class ProviderError(CyberjectionException):
    """Base class for target-provider communication failures."""


class ProviderConnectionError(ProviderError):
    """Raised when a target provider call fails due to a network/API error."""


class ProviderTimeoutError(ProviderError):
    """Raised when a target provider call exceeds its configured timeout."""


class ProviderRateLimitError(ProviderError):
    """Raised when a target provider returns a 429 / rate-limit response."""


class BudgetExceededError(CyberjectionException):
    """Raised when a campaign's cumulative spend exceeds --max-cost."""
