"""Persistence-backed happy-path tests for `cyberjection.api.app`: the
dashboard API's campaign/test endpoints served against a real (in-memory)
database, rather than the "persistence unavailable" 503 path
`test_api.py` covers without any database dependency.

Requires the real `sqlalchemy` + `aiosqlite` packages -- see
`test_database_models.py`'s and `test_repository.py`'s module docstrings
for why this suite doesn't run inside the offline sandbox this project
was hard-tested in, and `docs/TESTING.md#persistence-layer` for what was
verified instead. Kept in its own module (rather than a class inside
`test_api.py` gated by a class-scoped fixture) so the whole file
cleanly module-skips via `pytest.importorskip` exactly like those two
files already do, instead of relying on per-test or per-class skip
logic.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Tuple

import pytest

pytest.importorskip("sqlalchemy")
pytest.importorskip("aiosqlite")

from cyberjection.api.app import build_app
from cyberjection.api.asgi import ASGIApp
from cyberjection.persistence.repository import CampaignRepository
from cyberjection.persistence.sqlite import DatabaseManager


async def _call_asgi_app(
    app: ASGIApp, method: str, path: str, *, query_string: bytes = b""
) -> Tuple[int, Dict[str, Any]]:
    """Same minimal ASGI test client as `test_api.py`'s -- duplicated
    rather than imported so this module stays independently skippable
    (importing anything from `test_api.py` would pull in its own imports,
    none of which need guarding, but the duplication keeps the two files'
    skip boundaries obviously independent at a glance)."""

    scope = {"type": "http", "method": method, "path": path, "query_string": query_string, "headers": []}
    sent: List[Dict[str, Any]] = []

    async def receive() -> Dict[str, Any]:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: Dict[str, Any]) -> None:
        sent.append(message)

    await app(scope, receive, send)

    start = next(m for m in sent if m["type"] == "http.response.start")
    body_msg = next(m for m in sent if m["type"] == "http.response.body")
    parsed = json.loads(body_msg["body"].decode("utf-8")) if body_msg["body"] else None
    return start["status"], parsed


@pytest.fixture
async def seeded_app():
    """Seeds an in-memory database with one campaign/test/turn, then
    builds the API app pointed directly at that same already-initialized
    `DatabaseManager` (via `build_app`'s `manager=` parameter) so the app
    serves the exact data just seeded rather than opening a second,
    separate, empty database."""

    manager = DatabaseManager.in_memory()
    await manager.init_db()
    async with manager.session() as session:
        repo = CampaignRepository(session)
        campaign = await repo.create_campaign("phase-10-test-campaign")
        test = await repo.create_test(campaign.id, "target-1", "direct_prompt_injection", "seed prompt")
        await repo.record_turn(test.id, 1, "seed prompt", "response text", 12.5)
        await repo.update_test_outcome(test.id, "FAIL", 8.5)

    app = build_app(manager=manager)
    try:
        yield app, campaign.id, test.id
    finally:
        await manager.close()


@pytest.fixture
async def seeded_app_with_metrics():
    """Same seeding as `seeded_app`, plus a `MetricModel` row via
    `upsert_metrics` -- exists so at least one test exercises
    `_test_detail`'s `metrics is not None` branch, which `seeded_app`
    alone never reaches."""

    manager = DatabaseManager.in_memory()
    await manager.init_db()
    async with manager.session() as session:
        repo = CampaignRepository(session)
        campaign = await repo.create_campaign("phase-10-metrics-campaign")
        test = await repo.create_test(campaign.id, "target-1", "direct_prompt_injection", "seed prompt")
        await repo.record_turn(test.id, 1, "seed prompt", "response text", 12.5)
        await repo.update_test_outcome(test.id, "FAIL", 8.5)
        await repo.upsert_metrics(
            test.id,
            prompt_tokens=120,
            completion_tokens=45,
            total_cost=0.0033,
            judge_tier_used=2,
        )

    app = build_app(manager=manager)
    try:
        yield app, campaign.id, test.id
    finally:
        await manager.close()


class TestCampaignEndpointsWithDatabase:
    async def test_list_campaigns_returns_the_seeded_campaign(self, seeded_app) -> None:
        app, campaign_id, _test_id = seeded_app
        status, body = await _call_asgi_app(app, "GET", "/api/campaigns")
        assert status == 200
        assert any(c["id"] == campaign_id for c in body["campaigns"])

    async def test_get_campaign_includes_its_tests(self, seeded_app) -> None:
        app, campaign_id, test_id = seeded_app
        status, body = await _call_asgi_app(app, "GET", f"/api/campaigns/{campaign_id}")
        assert status == 200
        assert body["id"] == campaign_id
        assert any(t["id"] == test_id for t in body["tests"])

    async def test_get_unknown_campaign_returns_404(self, seeded_app) -> None:
        app, _campaign_id, _test_id = seeded_app
        status, body = await _call_asgi_app(app, "GET", "/api/campaigns/does-not-exist")
        assert status == 404
        assert body["error"] == "not_found"

    async def test_get_test_includes_turns(self, seeded_app) -> None:
        app, campaign_id, test_id = seeded_app
        status, body = await _call_asgi_app(app, "GET", f"/api/campaigns/{campaign_id}/tests/{test_id}")
        assert status == 200
        assert body["verdict"] == "FAIL"
        assert body["score"] == 8.5
        assert len(body["turns"]) == 1
        assert body["turns"][0]["prompt"] == "seed prompt"
        assert body["turns"][0]["response"] == "response text"

    async def test_get_test_without_a_metrics_row_has_null_metrics(self, seeded_app) -> None:
        """`seeded_app` never calls `upsert_metrics`, so this test's
        `MetricModel` relationship is empty. Regression test for the bug
        `get_test_with_history` had for most of Phase 10: its query
        eager-loaded `turns`/`findings` but not `metrics`, so
        `_test_detail`'s `test.metrics` access triggered an implicit lazy
        load under `AsyncSession` -- which raises (`MissingGreenlet`)
        rather than returning `None` -- turning this into a 500 regardless
        of whether the test actually had a metrics row. `_test_detail`
        always includes a `metrics` key (the dashboard's `TestDetail`
        TypeScript type likewise declares it as `MetricDetail | null`,
        never an optional/absent property), so the fixed, eager-loaded
        `None` case should serialize to a null `metrics` value rather than
        crash or get skipped."""

        app, campaign_id, test_id = seeded_app
        status, body = await _call_asgi_app(app, "GET", f"/api/campaigns/{campaign_id}/tests/{test_id}")
        assert status == 200
        assert "metrics" in body
        assert body["metrics"] is None

    async def test_get_test_with_a_metrics_row_includes_metrics(self, seeded_app_with_metrics) -> None:
        """Companion to the omits-the-key test above: covers the other
        branch of `_test_detail`'s `if test.metrics is not None`, which the
        original (pre-fix) bug report never actually exercised -- the test
        it was named after (`test_get_test_includes_turns_and_metrics`)
        never called `upsert_metrics` at all, so it only ever tested the
        `None` path by accident."""

        app, campaign_id, test_id = seeded_app_with_metrics
        status, body = await _call_asgi_app(app, "GET", f"/api/campaigns/{campaign_id}/tests/{test_id}")
        assert status == 200
        assert body["metrics"] == {
            "prompt_tokens": 120,
            "completion_tokens": 45,
            "total_cost": 0.0033,
            "judge_tier_used": 2,
        }

    async def test_get_test_under_wrong_campaign_returns_404(self, seeded_app) -> None:
        app, _campaign_id, test_id = seeded_app
        status, body = await _call_asgi_app(app, "GET", f"/api/campaigns/does-not-exist/tests/{test_id}")
        assert status == 404

    async def test_get_unknown_test_returns_404(self, seeded_app) -> None:
        app, campaign_id, _test_id = seeded_app
        status, body = await _call_asgi_app(app, "GET", f"/api/campaigns/{campaign_id}/tests/does-not-exist")
        assert status == 404
