"""Campaign & test repository: an async Data Access Object (DAO) wrapping
every database read/write the execution engine needs.

Every mutating method commits immediately (rather than batching writes and
committing once at the end of a test or campaign) by design: Phase 4's
resiliency goal is that a turn or evaluator verdict written to the database
is durable the instant it's written, so a crash immediately afterward loses
at most the in-flight operation, not an unbounded batch of prior work.
"""

from __future__ import annotations

from typing import List, Optional

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from cyberjection.persistence.models import (
    CampaignModel,
    FindingModel,
    MetricModel,
    TestModel,
    TurnModel,
    utc_now,
)


class CampaignRepository:
    """Data Access Object (DAO) for campaign/test state persistence and
    retrieval. Wraps a single `AsyncSession`; callers own that session's
    lifecycle (typically one session per campaign worker task)."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    # -- Campaigns ---------------------------------------------------

    async def create_campaign(self, name: str, campaign_id: Optional[str] = None) -> CampaignModel:
        campaign = CampaignModel(name=name)
        if campaign_id:
            campaign.id = campaign_id
        self.session.add(campaign)
        await self.session.commit()
        await self.session.refresh(campaign)
        return campaign

    async def get_campaign(self, campaign_id: str) -> Optional[CampaignModel]:
        return await self.session.get(CampaignModel, campaign_id)

    async def get_campaign_with_tests(self, campaign_id: str) -> Optional[CampaignModel]:
        """Eager-loads `tests` and each test's `turns`, the shape the
        resumability engine needs to reconcile completed work."""

        stmt = (
            select(CampaignModel)
            .where(CampaignModel.id == campaign_id)
            .options(selectinload(CampaignModel.tests).selectinload(TestModel.turns))
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def list_recent_campaigns(self, limit: int = 10) -> List[CampaignModel]:
        """Newest-first campaign listing for the Phase 6 CLI's `inspect`
        command -- "inspecting persistent scan histories" (Task 6.1) needs
        a way to enumerate campaigns at all, which nothing before Phase 6
        required: every prior consumer of this repository already knew
        the specific `campaign_id` it wanted."""

        stmt = select(CampaignModel).order_by(CampaignModel.started_at.desc()).limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def update_campaign_status(
        self, campaign_id: str, status: str, *, total_cost: Optional[float] = None
    ) -> None:
        values: dict = {"status": status}
        if total_cost is not None:
            values["total_cost"] = total_cost
        if status in ("COMPLETED", "FAILED", "INTERRUPTED"):
            values["finished_at"] = utc_now()
        stmt = update(CampaignModel).where(CampaignModel.id == campaign_id).values(**values)
        await self.session.execute(stmt)
        await self.session.commit()

    # -- Tests ---------------------------------------------------------

    async def create_test(
        self,
        campaign_id: str,
        target_id: str,
        strategy: str,
        seed_prompt: str,
        test_id: Optional[str] = None,
    ) -> TestModel:
        test = TestModel(
            campaign_id=campaign_id,
            target_id=target_id,
            strategy=strategy,
            seed_prompt=seed_prompt,
        )
        if test_id:
            test.id = test_id
        self.session.add(test)
        await self.session.commit()
        await self.session.refresh(test)
        return test

    async def get_test(self, test_id: str) -> Optional[TestModel]:
        return await self.session.get(TestModel, test_id)

    async def find_test(
        self, campaign_id: str, target_id: str, strategy: str, seed_prompt: str
    ) -> Optional[TestModel]:
        """Looks up a test by its natural key rather than its (randomly
        generated) id. Used to make campaign resumption idempotent: before
        creating a new `TestModel`, the orchestrator checks whether one
        already exists for this exact (target, strategy, seed_prompt)
        combination within the campaign."""

        stmt = select(TestModel).where(
            TestModel.campaign_id == campaign_id,
            TestModel.target_id == target_id,
            TestModel.strategy == strategy,
            TestModel.seed_prompt == seed_prompt,
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def list_tests_for_campaign(self, campaign_id: str) -> List[TestModel]:
        stmt = select(TestModel).where(TestModel.campaign_id == campaign_id)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def list_incomplete_tests(self, campaign_id: str) -> List[TestModel]:
        """Tests that haven't reached a terminal COMPLETED status -- the
        query the resumability engine and any "how far along is this
        campaign" reporting both need."""

        stmt = select(TestModel).where(
            TestModel.campaign_id == campaign_id,
            TestModel.status != "COMPLETED",
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def update_test_outcome(
        self, test_id: str, verdict: str, score: float, status: str = "COMPLETED"
    ) -> None:
        stmt = update(TestModel).where(TestModel.id == test_id).values(
            verdict=verdict, score=score, status=status
        )
        await self.session.execute(stmt)
        await self.session.commit()

    async def get_test_with_history(self, test_id: str) -> Optional[TestModel]:
        stmt = (
            select(TestModel)
            .where(TestModel.id == test_id)
            .options(selectinload(TestModel.turns), selectinload(TestModel.findings))
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    # -- Turns -----------------------------------------------------------

    async def record_turn(
        self, test_id: str, turn_number: int, prompt: str, response: str, latency_ms: float
    ) -> TurnModel:
        """Persists one conversation turn and commits immediately -- the
        incremental checkpoint Task 4.1 requires. `turn_number` must be
        unique per test (enforced by a unique index in
        `cyberjection.persistence.models.TurnModel`); re-recording an
        already-persisted turn number raises `IntegrityError` rather than
        silently duplicating or overwriting it, since a resuming caller
        should be skipping turns it already has, not re-recording them.
        """

        turn = TurnModel(
            test_id=test_id,
            turn_number=turn_number,
            prompt_payload=prompt,
            response_payload=response,
            latency_ms=latency_ms,
        )
        self.session.add(turn)
        await self.session.commit()
        await self.session.refresh(turn)
        return turn

    # -- Findings and metrics ---------------------------------------------

    async def record_finding(
        self, test_id: str, severity: str, owasp_category: str, description: str
    ) -> FindingModel:
        finding = FindingModel(
            test_id=test_id,
            severity=severity,
            owasp_category=owasp_category,
            description=description,
        )
        self.session.add(finding)
        await self.session.commit()
        await self.session.refresh(finding)
        return finding

    async def upsert_metrics(
        self,
        test_id: str,
        *,
        prompt_tokens: Optional[int] = None,
        completion_tokens: Optional[int] = None,
        total_cost: Optional[float] = None,
        judge_tier_used: Optional[int] = None,
    ) -> MetricModel:
        """Creates a test's `MetricModel` row on first call, or updates
        whichever fields are given (accumulating tokens/cost by addition
        rather than overwriting) on subsequent calls -- metrics for a
        multi-turn test accumulate across turns rather than being known
        all at once."""

        existing = await self.session.get(MetricModel, test_id)
        if existing is None:
            metrics = MetricModel(
                test_id=test_id,
                prompt_tokens=prompt_tokens or 0,
                completion_tokens=completion_tokens or 0,
                total_cost=total_cost or 0.0,
                judge_tier_used=judge_tier_used or 1,
            )
            self.session.add(metrics)
            await self.session.commit()
            await self.session.refresh(metrics)
            return metrics

        if prompt_tokens is not None:
            existing.prompt_tokens += prompt_tokens
        if completion_tokens is not None:
            existing.completion_tokens += completion_tokens
        if total_cost is not None:
            existing.total_cost += total_cost
        if judge_tier_used is not None:
            existing.judge_tier_used = judge_tier_used
        await self.session.commit()
        await self.session.refresh(existing)
        return existing
