"""Campaign resumability: reconciles what's already in the database against
a campaign's configured test cases so a restarted run can skip completed
work and pick a partially-completed multi-turn test back up mid-conversation
instead of starting over.

The reconciliation algorithm (`build_resume_map` and its helpers) is a pure
function of plain data -- it only reads `.target_id` / `.strategy` /
`.seed_prompt` / `.status` / `.verdict` / `.score` / `.id` off a test-like
object and `.turn_number` / `.prompt_payload` / `.response_payload` /
`.latency_ms` off a turn-like object -- so it has no SQLAlchemy or database
dependency and can be unit-tested with plain stand-in objects. Only
`ResumabilityManager` touches the database, by delegating to
`CampaignRepository.get_campaign_with_tests`.

`CampaignRepository` is imported only under `TYPE_CHECKING` (used purely as
a type hint, made a lazy string by `from __future__ import annotations`)
rather than at module level, so importing this module -- and exercising
every pure function above it -- never pulls in `cyberjection.persistence.
repository` or its `sqlalchemy` dependency. Only actually constructing a
`ResumabilityManager` and calling its async methods touches the database.
"""

from __future__ import annotations

from enum import Enum
from typing import TYPE_CHECKING, Dict, List, Optional, Tuple

from pydantic import BaseModel

if TYPE_CHECKING:
    from cyberjection.persistence.repository import CampaignRepository


class ResumabilityError(Exception):
    """Base exception for resumability reconciliation failures."""


class ResumabilityKeyCollisionError(ResumabilityError):
    """Raised when two persisted tests in the same campaign share the exact
    same (target_id, strategy, seed_prompt) key. This can only happen if the
    campaign config itself defines two test cases with identical target,
    strategy, and seed_prompt -- an authoring ambiguity resumability can't
    safely resolve on its own, since there'd be no way to tell which
    persisted row corresponds to which config entry. Raised loudly rather
    than silently picking one and losing resume state for the other."""

    def __init__(self, key: Tuple[str, str, str], test_ids: List[str]) -> None:
        self.key = key
        self.test_ids = test_ids
        target_id, strategy, seed_prompt = key
        super().__init__(
            f"Multiple persisted tests share the same (target={target_id!r}, "
            f"strategy={strategy!r}, seed_prompt={seed_prompt!r}) key: "
            f"{test_ids!r}. Campaign config must not define two test cases "
            f"with identical target, strategy, and seed_prompt."
        )


class ResumeDecision(str, Enum):
    FRESH = "FRESH"
    SKIP_COMPLETE = "SKIP_COMPLETE"
    RESUME = "RESUME"


class ResumedTurnState(BaseModel):
    turn_number: int
    prompt: str
    response: str
    latency_ms: float


class ResumedTestState(BaseModel):
    test_id: str
    target_id: str
    strategy: str
    seed_prompt: str
    status: str
    verdict: str
    score: float
    completed_turns: List[ResumedTurnState]
    next_turn_number: int


def _compute_next_turn_number(turns: List[ResumedTurnState]) -> int:
    """Returns the lowest turn number (starting at 1) not already present.

    The execution engine records turn N+1 only after turn N has been
    persisted, so under normal operation this is just `max(turn_numbers) +
    1`. But trusting `max()` alone means a turn lost to a crash between
    "turn 3 committed" and "turn 2's commit landing" (unlikely given the
    per-turn commit-immediately design in `CampaignRepository.record_turn`,
    but not impossible under process-level corruption or manual DB
    surgery) would be silently skipped forever. Scanning for the first gap
    costs nothing extra for the common gapless case and eliminates that
    failure mode for the uncommon one.
    """

    seen = {t.turn_number for t in turns}
    candidate = 1
    while candidate in seen:
        candidate += 1
    return candidate


def reconcile_test_state(test) -> ResumedTestState:
    """Builds a `ResumedTestState` from one persisted test-like object.

    `test` needs only duck-typed attributes: `.id`, `.target_id`,
    `.strategy`, `.seed_prompt`, `.status`, `.verdict`, `.score`, and
    `.turns` (an iterable of objects with `.turn_number`,
    `.prompt_payload`, `.response_payload`, `.latency_ms`). Works equally
    well against a real `TestModel` (with its `turns` relationship
    eager-loaded) or a lightweight stand-in used in offline unit tests.
    """

    completed_turns = sorted(
        (
            ResumedTurnState(
                turn_number=turn.turn_number,
                prompt=turn.prompt_payload,
                response=turn.response_payload,
                latency_ms=turn.latency_ms,
            )
            for turn in test.turns
        ),
        key=lambda t: t.turn_number,
    )
    return ResumedTestState(
        test_id=test.id,
        target_id=test.target_id,
        strategy=test.strategy,
        seed_prompt=test.seed_prompt,
        status=test.status,
        verdict=test.verdict,
        score=test.score,
        completed_turns=completed_turns,
        next_turn_number=_compute_next_turn_number(completed_turns),
    )


def build_resume_map(tests) -> Dict[Tuple[str, str, str], ResumedTestState]:
    """Reconciles every persisted test in a campaign into a lookup keyed by
    the natural (target_id, strategy, seed_prompt) key a campaign config's
    `TestCaseConfig` entries carry -- so the orchestrator can look up
    "has this exact test case already run, and how far did it get?" without
    depending on database-generated ids that don't exist until a test is
    first created.

    Keying by `seed_prompt` alone (the original design) silently collides
    whenever two `TestCaseConfig` entries in the same campaign share a
    seed_prompt but differ in target or strategy -- a realistic setup,
    e.g. running the same seed prompt against several targets. Keying by
    the full composite tuple fixes that. A genuine collision (two
    persisted tests sharing the identical full triple) can still only
    happen if the campaign config itself defines duplicate test cases;
    that case raises `ResumabilityKeyCollisionError` instead of silently
    dropping one, since there's no principled way to pick a winner.
    """

    resume_map: Dict[Tuple[str, str, str], ResumedTestState] = {}
    collisions: Dict[Tuple[str, str, str], List[str]] = {}

    for test in tests:
        key = (test.target_id, test.strategy, test.seed_prompt)
        state = reconcile_test_state(test)
        if key in resume_map:
            collisions.setdefault(key, [resume_map[key].test_id]).append(state.test_id)
            continue
        resume_map[key] = state

    if collisions:
        key, test_ids = next(iter(collisions.items()))
        raise ResumabilityKeyCollisionError(key, test_ids)

    return resume_map


def decide_resume_action(state: Optional[ResumedTestState]) -> ResumeDecision:
    """Given the (possibly absent) persisted state for a configured test
    case, decides what the orchestrator should do with it."""

    if state is None:
        return ResumeDecision.FRESH
    if state.status == "COMPLETED":
        return ResumeDecision.SKIP_COMPLETE
    return ResumeDecision.RESUME


class ResumabilityManager:
    """Thin database-facing wrapper: loads a campaign's persisted tests (with
    turns eager-loaded) via `CampaignRepository` and hands them to the pure
    `build_resume_map` function above."""

    def __init__(self, repository: CampaignRepository) -> None:
        self.repository = repository

    async def get_campaign_resume_state(
        self, campaign_id: str
    ) -> Dict[Tuple[str, str, str], ResumedTestState]:
        campaign = await self.repository.get_campaign_with_tests(campaign_id)
        if campaign is None:
            return {}
        return build_resume_map(campaign.tests)

    async def get_resume_decision(
        self, campaign_id: str, target_id: str, strategy: str, seed_prompt: str
    ) -> Tuple[ResumeDecision, Optional[ResumedTestState]]:
        resume_map = await self.get_campaign_resume_state(campaign_id)
        state = resume_map.get((target_id, strategy, seed_prompt))
        return decide_resume_action(state), state
