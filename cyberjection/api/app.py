"""Dashboard REST API: read-only endpoints over the Phase 4 persistence
layer and the Phase 10 plugin registries, for `apps/dashboard` (or any
other HTTP client) to consume.

Every endpoint is a plain `async def handler(request: Request) ->
Response` closure built by `build_app`, routed through the dependency-free
`cyberjection.api.asgi` toolkit (see that module's docstring for why this
isn't built on FastAPI/Starlette). `build_app` opens one
`DatabaseManager` for the process's lifetime and hands out a fresh
`AsyncSession` per request -- the same one-session-per-unit-of-work
pattern `cyberjection.orchestrator.campaign.execute_campaign` already
uses for a campaign run.

Endpoints:

- `GET  /api/health`                                    liveness probe
- `GET  /api/plugins`                                    registered aliases by group
- `GET  /api/campaigns?limit=N`                           recent campaigns
- `GET  /api/campaigns/{campaign_id}`                     one campaign + its tests
- `GET  /api/campaigns/{campaign_id}/tests/{test_id}`     one test + its turns/findings

All persistence-backed endpoints return `503` (not a raised exception) if
SQLAlchemy/aiosqlite aren't installed in this environment -- the same
degrade-gracefully contract `cyberjection.cli.main inspect` already
honors via `_SQLALCHEMY_AVAILABLE`, rather than the API assuming its own
dependency stack is a hard requirement of the process running it.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional

from cyberjection.api.asgi import ASGIApp, JSONResponse, Request, Response, Router
from cyberjection.plugins import discover_plugins, known_aliases_by_group


def _iso(value: Optional[datetime]) -> Optional[str]:
    return value.isoformat() if value is not None else None


def _campaign_summary(campaign: Any) -> Dict[str, Any]:
    return {
        "id": campaign.id,
        "name": campaign.name,
        "status": campaign.status,
        "total_cost": campaign.total_cost,
        "started_at": _iso(campaign.started_at),
        "finished_at": _iso(campaign.finished_at),
    }


def _test_summary(test: Any) -> Dict[str, Any]:
    return {
        "id": test.id,
        "campaign_id": test.campaign_id,
        "target_id": test.target_id,
        "strategy": test.strategy,
        "status": test.status,
        "score": test.score,
        "verdict": test.verdict,
        "created_at": _iso(test.created_at),
    }


def _test_detail(test: Any) -> Dict[str, Any]:
    payload = _test_summary(test)
    payload["seed_prompt"] = test.seed_prompt
    payload["turns"] = [
        {
            "turn_number": turn.turn_number,
            "prompt": turn.prompt_payload,
            "response": turn.response_payload,
            "latency_ms": turn.latency_ms,
        }
        for turn in test.turns
    ]
    payload["findings"] = [
        {
            "severity": finding.severity,
            "owasp_category": finding.owasp_category,
            "description": finding.description,
        }
        for finding in test.findings
    ]
    if test.metrics is not None:
        payload["metrics"] = {
            "prompt_tokens": test.metrics.prompt_tokens,
            "completion_tokens": test.metrics.completion_tokens,
            "total_cost": test.metrics.total_cost,
            "judge_tier_used": test.metrics.judge_tier_used,
        }
    else:
        payload["metrics"] = None
    return payload


def build_app(db_url: Optional[str] = None, *, manager: Optional[Any] = None) -> ASGIApp:
    """Builds the dashboard API's `ASGIApp`.

    Opening the database (if SQLAlchemy is installed) is deferred to the
    first request rather than done here, so constructing the app itself
    never requires an event loop to already be running --
    `cyberjection.api.server.run_server` (and any test harness) can call
    this synchronously. Passing an already-constructed `manager` (a
    `cyberjection.persistence.DatabaseManager`) skips that lazy
    construction entirely and uses it as-is -- primarily so tests can
    point the app at a pre-seeded in-memory database
    (`DatabaseManager.in_memory()`) instead of a throwaway file-backed one
    `db_url` would otherwise create.
    """

    router = Router()
    state: Dict[str, Any] = {"db_url": db_url, "manager": manager, "initialized": manager is not None}

    async def _get_manager():
        from cyberjection.persistence import _SQLALCHEMY_AVAILABLE, DatabaseManager, DEFAULT_DB_URL

        if not _SQLALCHEMY_AVAILABLE:
            return None
        if state["manager"] is None:
            state["manager"] = DatabaseManager(state["db_url"] or DEFAULT_DB_URL)
        if not state["initialized"]:
            await state["manager"].init_db()
            state["initialized"] = True
        return state["manager"]

    def _unavailable() -> Response:
        return JSONResponse(
            {
                "error": "persistence_unavailable",
                "detail": "SQLAlchemy/aiosqlite are not installed, so there is no campaign "
                "history to serve.",
            },
            status_code=503,
        )

    async def health(request: Request) -> Response:
        return JSONResponse({"status": "ok"})

    async def list_plugins(request: Request) -> Response:
        # Best-effort: a broken third-party plugin is reported alongside
        # the successfully loaded ones rather than failing the whole
        # request (see cyberjection.plugins.loader's module docstring).
        discovery = discover_plugins()
        return JSONResponse(
            {
                "registered": known_aliases_by_group(),
                "discovered": [
                    {"group": p.group, "alias": p.alias, "qualified_name": p.qualified_name}
                    for p in discovery.loaded
                ],
                "failures": [str(failure) for failure in discovery.failures],
            }
        )

    async def list_campaigns(request: Request) -> Response:
        from cyberjection.persistence import CampaignRepository

        manager = await _get_manager()
        if manager is None:
            return _unavailable()
        limit = request.query_int("limit", 20)
        async with manager.session() as session:
            repo = CampaignRepository(session)
            campaigns = await repo.list_recent_campaigns(limit=limit)
            return JSONResponse({"campaigns": [_campaign_summary(c) for c in campaigns]})

    async def get_campaign(request: Request) -> Response:
        from cyberjection.persistence import CampaignRepository

        manager = await _get_manager()
        if manager is None:
            return _unavailable()
        campaign_id = request.path_params["campaign_id"]
        async with manager.session() as session:
            repo = CampaignRepository(session)
            campaign = await repo.get_campaign_with_tests(campaign_id)
            if campaign is None:
                return JSONResponse(
                    {"error": "not_found", "detail": f"No campaign with id {campaign_id!r}."},
                    status_code=404,
                )
            payload = _campaign_summary(campaign)
            payload["tests"] = [_test_summary(t) for t in campaign.tests]
            return JSONResponse(payload)

    async def get_test(request: Request) -> Response:
        from cyberjection.persistence import CampaignRepository

        manager = await _get_manager()
        if manager is None:
            return _unavailable()
        test_id = request.path_params["test_id"]
        async with manager.session() as session:
            repo = CampaignRepository(session)
            test = await repo.get_test_with_history(test_id)
            if test is None or test.campaign_id != request.path_params["campaign_id"]:
                return JSONResponse(
                    {"error": "not_found", "detail": f"No test with id {test_id!r}."},
                    status_code=404,
                )
            return JSONResponse(_test_detail(test))

    router.add_route("GET", "/api/health", health)
    router.add_route("GET", "/api/plugins", list_plugins)
    router.add_route("GET", "/api/campaigns", list_campaigns)
    router.add_route("GET", "/api/campaigns/{campaign_id}/tests/{test_id}", get_test)
    router.add_route("GET", "/api/campaigns/{campaign_id}", get_campaign)

    return ASGIApp(router)
