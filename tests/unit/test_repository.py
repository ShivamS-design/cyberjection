"""Tests for cyberjection.persistence.repository.CampaignRepository: the DAO
covering campaign/test lifecycle, turn/finding/metric recording, and the
execution-state queries the resumability engine and orchestrator rely on.

Requires the real `sqlalchemy` + `aiosqlite` packages -- see
`test_database_models.py`'s module docstring for why this suite doesn't run
inside the offline sandbox this project was hard-tested in.
"""

from __future__ import annotations

import pytest

pytest.importorskip("sqlalchemy")
pytest.importorskip("aiosqlite")

from cyberjection.persistence.repository import CampaignRepository
from cyberjection.persistence.sqlite import DatabaseManager


@pytest.fixture
async def db_manager():
    manager = DatabaseManager.in_memory()
    await manager.init_db()
    yield manager
    await manager.close()


@pytest.fixture
async def repo(db_manager: DatabaseManager):
    async with db_manager.session() as session:
        yield CampaignRepository(session)


@pytest.mark.asyncio
class TestCampaignLifecycle:
    async def test_create_and_get_campaign(self, repo: CampaignRepository) -> None:
        campaign = await repo.create_campaign("nightly-run")
        assert campaign.id
        assert campaign.status == "QUEUED"

        fetched = await repo.get_campaign(campaign.id)
        assert fetched is not None
        assert fetched.name == "nightly-run"

    async def test_update_campaign_status_sets_finished_at_on_terminal_status(
        self, repo: CampaignRepository
    ) -> None:
        campaign = await repo.create_campaign("nightly-run")
        assert campaign.finished_at is None

        await repo.update_campaign_status(campaign.id, "COMPLETED", total_cost=1.23)

        fetched = await repo.get_campaign(campaign.id)
        assert fetched.status == "COMPLETED"
        assert fetched.total_cost == 1.23
        assert fetched.finished_at is not None

    async def test_update_campaign_status_does_not_set_finished_at_for_running(
        self, repo: CampaignRepository
    ) -> None:
        campaign = await repo.create_campaign("nightly-run")
        await repo.update_campaign_status(campaign.id, "RUNNING")

        fetched = await repo.get_campaign(campaign.id)
        assert fetched.status == "RUNNING"
        assert fetched.finished_at is None


@pytest.mark.asyncio
class TestTestLifecycle:
    async def test_create_and_find_test_by_natural_key(self, repo: CampaignRepository) -> None:
        campaign = await repo.create_campaign("c1")
        test = await repo.create_test(campaign.id, "target-a", "jailbreak_roleplay", "seed prompt")

        found = await repo.find_test(campaign.id, "target-a", "jailbreak_roleplay", "seed prompt")
        assert found is not None
        assert found.id == test.id

        not_found = await repo.find_test(campaign.id, "target-b", "jailbreak_roleplay", "seed prompt")
        assert not_found is None

    async def test_list_incomplete_tests_excludes_completed(self, repo: CampaignRepository) -> None:
        campaign = await repo.create_campaign("c1")
        running = await repo.create_test(campaign.id, "target-a", "s", "p1")
        done = await repo.create_test(campaign.id, "target-a", "s", "p2")
        await repo.update_test_outcome(done.id, verdict="FAIL", score=0.9, status="COMPLETED")

        incomplete = await repo.list_incomplete_tests(campaign.id)
        incomplete_ids = {t.id for t in incomplete}
        assert running.id in incomplete_ids
        assert done.id not in incomplete_ids

    async def test_update_test_outcome(self, repo: CampaignRepository) -> None:
        campaign = await repo.create_campaign("c1")
        test = await repo.create_test(campaign.id, "target-a", "s", "p1")

        await repo.update_test_outcome(test.id, verdict="FAIL", score=0.75, status="COMPLETED")

        fetched = await repo.get_test(test.id)
        assert fetched.verdict == "FAIL"
        assert fetched.score == 0.75
        assert fetched.status == "COMPLETED"


@pytest.mark.asyncio
class TestTurnsFindingsAndMetrics:
    async def test_record_turn_and_get_test_with_history(self, repo: CampaignRepository) -> None:
        campaign = await repo.create_campaign("c1")
        test = await repo.create_test(campaign.id, "target-a", "s", "p1")

        await repo.record_turn(test.id, 1, "prompt-1", "response-1", 15.0)
        await repo.record_turn(test.id, 2, "prompt-2", "response-2", 20.0)

        fetched = await repo.get_test_with_history(test.id)
        assert [t.turn_number for t in fetched.turns] == [1, 2]
        assert fetched.turns[0].prompt_payload == "prompt-1"

    async def test_record_finding(self, repo: CampaignRepository) -> None:
        campaign = await repo.create_campaign("c1")
        test = await repo.create_test(campaign.id, "target-a", "s", "p1")

        await repo.record_finding(test.id, "HIGH", "LLM01_PROMPT_INJECTION", "bypassed refusal")

        fetched = await repo.get_test_with_history(test.id)
        assert len(fetched.findings) == 1
        assert fetched.findings[0].severity == "HIGH"

    async def test_upsert_metrics_creates_then_accumulates(self, repo: CampaignRepository) -> None:
        campaign = await repo.create_campaign("c1")
        test = await repo.create_test(campaign.id, "target-a", "s", "p1")

        created = await repo.upsert_metrics(test.id, prompt_tokens=100, completion_tokens=50, total_cost=0.01)
        assert created.prompt_tokens == 100
        assert created.completion_tokens == 50

        updated = await repo.upsert_metrics(test.id, prompt_tokens=20, completion_tokens=10, judge_tier_used=3)
        # Tokens/cost accumulate across turns rather than being overwritten.
        assert updated.prompt_tokens == 120
        assert updated.completion_tokens == 60
        assert updated.total_cost == 0.01
        assert updated.judge_tier_used == 3


@pytest.mark.asyncio
class TestCampaignWithTestsEagerLoad:
    async def test_get_campaign_with_tests_loads_turns(self, repo: CampaignRepository) -> None:
        campaign = await repo.create_campaign("c1")
        test = await repo.create_test(campaign.id, "target-a", "s", "p1")
        await repo.record_turn(test.id, 1, "p", "r", 5.0)

        fetched = await repo.get_campaign_with_tests(campaign.id)
        assert len(fetched.tests) == 1
        assert len(fetched.tests[0].turns) == 1


@pytest.mark.asyncio
class TestListRecentCampaigns:
    """Phase 6: the `inspect` CLI command's data source."""

    async def test_lists_newest_first(self, repo: CampaignRepository) -> None:
        first = await repo.create_campaign("older-run")
        second = await repo.create_campaign("newer-run")

        campaigns = await repo.list_recent_campaigns(limit=10)

        ids = [c.id for c in campaigns]
        assert ids.index(second.id) < ids.index(first.id)

    async def test_respects_limit(self, repo: CampaignRepository) -> None:
        for i in range(5):
            await repo.create_campaign(f"run-{i}")

        campaigns = await repo.list_recent_campaigns(limit=2)

        assert len(campaigns) == 2

    async def test_empty_database_returns_empty_list(self, repo: CampaignRepository) -> None:
        campaigns = await repo.list_recent_campaigns(limit=10)
        assert campaigns == []
