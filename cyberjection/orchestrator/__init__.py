"""Campaign orchestration: wires a loaded `CampaignConfig`'s test cases
through the real Phase 1-5 attack/evaluator stack and the Phase 4
persistence layer.

Every phase from 2 through 7 shipped its machinery standalone, with an
explicit note in its own changelog entry that wiring it into one end-to-end
run was deferred: Phase 6's `cyberjection.cli.main._execute_pipeline` has
returned two hardcoded `Finding`s since it was written, precisely so a
later phase could replace its body without touching any of its callers.
This package is that later phase -- see `campaign.CampaignOrchestrator` for
the wiring itself and `campaign.execute_campaign` for the high-level
entrypoint the CLI calls.
"""

from __future__ import annotations

from cyberjection.orchestrator.campaign import (
    CampaignOrchestrator,
    TestOutcome,
    TurnRecord,
    execute_campaign,
)

__all__ = [
    "CampaignOrchestrator",
    "TestOutcome",
    "TurnRecord",
    "execute_campaign",
]
