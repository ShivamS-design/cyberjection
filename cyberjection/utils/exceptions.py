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


class AttackerGenerationError(CyberjectionException):
    """Raised when the Phase 5 attacker agent can't produce a next payload.

    Unlike `LLMJudgeEvaluator` (which has a legitimate "I don't know" value
    -- `Verdict.UNCERTAIN` -- to fall back to after exhausting retries), the
    attacker agent's job is to produce the literal next prompt to send to
    the target under test. There's no safe placeholder value for that: a
    fabricated or empty prompt would still consume a real turn and real
    cost against the target for no signal. So a multi-turn engine that
    can't get a next payload from the attacker raises loudly and stops that
    attack trajectory, rather than silently sending garbage.
    """


class UnknownTargetError(CyberjectionException):
    """Raised by the Phase 6 CLI when `--target` references a target id
    that isn't present in the loaded campaign configuration. Caught at the
    CLI boundary and reported with a clear list of known ids rather than
    letting a `StopIteration`/`KeyError` from a naive lookup surface as a
    traceback for what is, from the operator's side, a typo."""


class RateLimitCapacityExceededError(CyberjectionException):
    """Raised by `DistributedRateLimiter.acquire` when a single request asks
    for more units than the bucket's configured capacity can ever hold.

    A token bucket's level is capped at its max capacity, so a request for
    more than that maximum can never succeed no matter how long the caller
    waits. Without this guard, `acquire` would loop forever sleeping on a
    request that was misconfigured (e.g. a per-call token estimate larger
    than the provider's configured `max_tpm`) instead of surfacing the
    misconfiguration immediately.
    """


class DeadLetterQueueError(CyberjectionException):
    """Raised when a distributed task exhausts its retry budget and is
    routed to the dead-letter queue. Carries the original failure so the
    caller can distinguish "gave up after retries" from a first-attempt
    failure that hasn't even started retrying yet."""
