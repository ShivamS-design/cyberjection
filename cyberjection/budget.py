"""Campaign spend tracking and `max_cost_cap` enforcement.

Every paid model call a campaign makes -- the target under test, the
multi-turn attacker agent, and the Tier 3 LLM judge -- goes through two
steps:

1. `preflight()` *before* the call: if the campaign has already reached its
   cap, raise `BudgetExceededError` and don't make the call.
2. `record()` *after* the call, with the call's real cost.

Checking before rather than after bounds overspend to the calls already
in flight when the cap is reached (at most one per concurrent worker),
and `record()` never raises, so a call that has already been paid for is
never discarded.

Cost comes from LiteLLM's own pricing data for the model
(`response._hidden_params["response_cost"]`, else
`litellm.completion_cost`), or from a target's explicit `pricing` block for
self-hosted or custom models LiteLLM doesn't know. A call whose cost
can't be determined is counted in `unpriced_calls` rather than charged
an invented amount: the cap then covers only measured spend, and the CLI
says so instead of implying more protection than exists.

The tracker is found through a context variable, so the providers,
evaluators and attack engines need no budget parameter threaded through
them. `CampaignOrchestrator` installs a campaign-wide tracker and one
child tracker per test case (children forward to their parent and keep a
per-test subtotal for the persisted metrics).
"""

from __future__ import annotations

import contextvars
import logging
from dataclasses import dataclass, field
from typing import Any, Iterator, Optional
from contextlib import contextmanager

from cyberjection.utils.exceptions import BudgetExceededError

logger = logging.getLogger("cyberjection.budget")

_CURRENT: "contextvars.ContextVar[Optional[BudgetTracker]]" = contextvars.ContextVar(
    "cyberjection_budget", default=None
)


@dataclass
class BudgetTracker:
    """Cumulative spend against an optional USD cap. `cap_usd=None` or `0`
    means unlimited (spend is still measured and reported)."""

    cap_usd: Optional[float] = None
    parent: Optional["BudgetTracker"] = None
    spent_usd: float = 0.0
    priced_calls: int = 0
    unpriced_calls: int = 0
    exceeded: bool = False
    _children: "list[BudgetTracker]" = field(default_factory=list, repr=False)

    @property
    def root(self) -> "BudgetTracker":
        node = self
        while node.parent is not None:
            node = node.parent
        return node

    @property
    def limited(self) -> bool:
        cap = self.root.cap_usd
        return cap is not None and cap > 0

    @property
    def remaining_usd(self) -> Optional[float]:
        root = self.root
        if not root.limited:
            return None
        return max(0.0, float(root.cap_usd or 0.0) - root.spent_usd)

    def child(self) -> "BudgetTracker":
        child = BudgetTracker(parent=self)
        self._children.append(child)
        return child

    def preflight(self, *, source: str = "model call") -> None:
        """Raise `BudgetExceededError` if the campaign has no budget left."""

        root = self.root
        if root.limited and root.spent_usd >= float(root.cap_usd or 0.0):
            root.exceeded = True
            raise BudgetExceededError(
                f"Campaign budget cap of ${root.cap_usd:.4f} reached (spent ${root.spent_usd:.4f}); "
                f"refusing further {source}s.",
                spent_usd=root.spent_usd,
                cap_usd=root.cap_usd,
            )

    def record(self, cost_usd: Optional[float], *, source: str = "model call") -> None:
        """Charge one completed call. `None` means the cost is unknown."""

        node: Optional[BudgetTracker] = self
        while node is not None:
            if cost_usd is None:
                node.unpriced_calls += 1
            else:
                node.spent_usd += max(0.0, float(cost_usd))
                node.priced_calls += 1
            node = node.parent
        root = self.root
        if cost_usd is None and root.unpriced_calls == 1:
            logger.warning(
                "Cost of a %s could not be determined (model not in LiteLLM's pricing data and no "
                "`pricing` configured); max_cost_cap only covers calls with a known cost.",
                source,
            )
        if root.limited and root.spent_usd >= float(root.cap_usd or 0.0):
            root.exceeded = True


def current_tracker() -> Optional[BudgetTracker]:
    return _CURRENT.get()


@contextmanager
def use_tracker(tracker: BudgetTracker) -> Iterator[BudgetTracker]:
    token = _CURRENT.set(tracker)
    try:
        yield tracker
    finally:
        _CURRENT.reset(token)


def preflight(source: str) -> None:
    tracker = _CURRENT.get()
    if tracker is not None:
        tracker.preflight(source=source)


def record(cost_usd: Optional[float], source: str) -> None:
    tracker = _CURRENT.get()
    if tracker is not None:
        tracker.record(cost_usd, source=source)


def response_cost(response: Any, *, pricing: Any = None) -> Optional[float]:
    """Best-effort real cost (USD) of one LiteLLM response.

    Order: an explicit per-target `pricing` override (USD per million
    input/output tokens), then LiteLLM's own computed `response_cost`, then
    `litellm.completion_cost`. Returns `None` -- never a guess -- if none
    of those can price the call.
    """

    usage = getattr(response, "usage", None)
    if pricing is not None and usage is not None:
        prompt = getattr(usage, "prompt_tokens", 0) or 0
        completion = getattr(usage, "completion_tokens", 0) or 0
        return float(prompt * pricing.input_per_million_usd + completion * pricing.output_per_million_usd) / 1_000_000

    hidden = getattr(response, "_hidden_params", None)
    if isinstance(hidden, dict):
        cost = hidden.get("response_cost")
        if isinstance(cost, (int, float)) and not isinstance(cost, bool) and cost >= 0:
            return float(cost)
    try:
        import litellm

        cost = litellm.completion_cost(completion_response=response)
    except Exception:  # noqa: BLE001 -- unknown model, missing usage, offline pricing map...
        return None
    if isinstance(cost, (int, float)) and cost >= 0:
        return float(cost)
    return None
