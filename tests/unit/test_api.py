"""Tests for cyberjection.api: the dependency-free ASGI toolkit
(`cyberjection.api.asgi`) and the dashboard REST API built on it
(`cyberjection.api.app`).

`_call_asgi_app` below is a minimal hand-rolled ASGI test client -- there's
no `httpx`/`starlette.testclient` available in every environment this
project supports (see `cyberjection.api.asgi`'s module docstring for why
the app itself doesn't depend on either), so this suite drives `ASGIApp`
instances the same way a real ASGI server would: by calling
`app(scope, receive, send)` directly and collecting whatever `send` is
called with.

The persistence-backed happy-path tests live in the sibling
`test_api_persistence.py` instead of here, since they require real
`sqlalchemy`/`aiosqlite` and skip at *module* import time via
`pytest.importorskip` when those aren't installed -- see that file's own
docstring. Every test in *this* file (the ASGI toolkit itself,
`/api/health`, `/api/plugins`, and the "persistence unavailable" 503
path) has no such dependency and always runs.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Tuple

import pytest

from cyberjection.api.app import build_app
from cyberjection.api.asgi import ASGIApp, JSONResponse, Request, Response, Router


async def _call_asgi_app(
    app: ASGIApp, method: str, path: str, *, query_string: bytes = b""
) -> Tuple[int, Dict[str, Any]]:
    """Drives an ASGI app through one `http` request/response cycle and
    returns `(status_code, parsed_json_body)`."""

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


class TestRouter:
    def test_matches_static_path(self) -> None:
        router = Router()

        async def handler(request: Request) -> Response:
            return JSONResponse({"ok": True})

        router.add_route("GET", "/api/health", handler)
        matched = router.match("GET", "/api/health")
        assert matched is not None
        assert matched[1] == {}

    def test_matches_path_with_params(self) -> None:
        router = Router()

        async def handler(request: Request) -> Response:
            return JSONResponse({})

        router.add_route("GET", "/api/campaigns/{campaign_id}/tests/{test_id}", handler)
        matched = router.match("GET", "/api/campaigns/c-1/tests/t-2")
        assert matched is not None
        assert matched[1] == {"campaign_id": "c-1", "test_id": "t-2"}

    def test_no_match_for_unknown_path_returns_none(self) -> None:
        router = Router()
        assert router.match("GET", "/does/not/exist") is None

    def test_no_match_for_wrong_method_on_known_path(self) -> None:
        router = Router()

        async def handler(request: Request) -> Response:
            return JSONResponse({})

        router.add_route("GET", "/api/health", handler)
        assert router.match("POST", "/api/health") is None

    def test_more_specific_route_registered_first_wins(self) -> None:
        router = Router()

        async def specific(request: Request) -> Response:
            return JSONResponse({"which": "specific"})

        async def general(request: Request) -> Response:
            return JSONResponse({"which": "general"})

        router.add_route("GET", "/api/campaigns/{campaign_id}/tests/{test_id}", specific)
        router.add_route("GET", "/api/campaigns/{campaign_id}", general)

        matched = router.match("GET", "/api/campaigns/c-1/tests/t-2")
        assert matched is not None
        handler, params = matched
        assert params == {"campaign_id": "c-1", "test_id": "t-2"}

    def test_path_param_does_not_cross_a_slash_boundary(self) -> None:
        router = Router()

        async def handler(request: Request) -> Response:
            return JSONResponse({})

        router.add_route("GET", "/api/campaigns/{campaign_id}", handler)
        # A path with an extra segment must not be swallowed into
        # `campaign_id` -- it should fail to match this pattern at all.
        assert router.match("GET", "/api/campaigns/c-1/tests/t-2") is None


class TestRequestQueryInt:
    def test_returns_default_when_absent(self) -> None:
        request = Request(method="GET", path="/x", query_params={})
        assert request.query_int("limit", 20) == 20

    def test_parses_valid_integer(self) -> None:
        request = Request(method="GET", path="/x", query_params={"limit": "5"})
        assert request.query_int("limit", 20) == 5

    def test_falls_back_to_default_on_invalid_integer(self) -> None:
        request = Request(method="GET", path="/x", query_params={"limit": "not-a-number"})
        assert request.query_int("limit", 20) == 20


class TestASGIAppLifespan:
    async def test_startup_and_shutdown_complete(self) -> None:
        router = Router()
        app = ASGIApp(router)
        events = iter(
            [
                {"type": "lifespan.startup"},
                {"type": "lifespan.shutdown"},
            ]
        )
        sent: List[Dict[str, Any]] = []

        async def receive() -> Dict[str, Any]:
            return next(events)

        async def send(message: Dict[str, Any]) -> None:
            sent.append(message)

        await app({"type": "lifespan"}, receive, send)

        assert sent == [
            {"type": "lifespan.startup.complete"},
            {"type": "lifespan.shutdown.complete"},
        ]


class TestASGIAppHTTP:
    async def test_unmatched_route_returns_404(self) -> None:
        app = ASGIApp(Router())
        status, body = await _call_asgi_app(app, "GET", "/nope")
        assert status == 404
        assert body["error"] == "not_found"

    async def test_handler_exception_becomes_500(self) -> None:
        router = Router()

        async def broken(request: Request) -> Response:
            raise RuntimeError("boom")

        router.add_route("GET", "/broken", broken)
        app = ASGIApp(router)
        status, body = await _call_asgi_app(app, "GET", "/broken")
        assert status == 500
        assert body["error"] == "internal_error"

    async def test_query_string_is_parsed_into_request(self) -> None:
        router = Router()
        seen = {}

        async def handler(request: Request) -> Response:
            seen["limit"] = request.query_params.get("limit")
            return JSONResponse({"ok": True})

        router.add_route("GET", "/x", handler)
        app = ASGIApp(router)
        await _call_asgi_app(app, "GET", "/x", query_string=b"limit=7")
        assert seen["limit"] == "7"

    async def test_unsupported_scope_type_raises(self) -> None:
        app = ASGIApp(Router())
        with pytest.raises(NotImplementedError):
            await app({"type": "websocket"}, lambda: None, lambda message: None)


class TestHealthAndPluginsEndpoints:
    async def test_health_returns_ok(self) -> None:
        app = build_app()
        status, body = await _call_asgi_app(app, "GET", "/api/health")
        assert status == 200
        assert body == {"status": "ok"}

    async def test_plugins_endpoint_lists_builtin_aliases(self) -> None:
        app = build_app()
        status, body = await _call_asgi_app(app, "GET", "/api/plugins")
        assert status == 200
        assert "base64" in body["registered"]["cyberjection.mutators"]
        assert "direct_prompt_injection" in body["registered"]["cyberjection.strategies"]
        assert body["discovered"] == []
        assert body["failures"] == []


class TestCampaignEndpointsWithoutDatabase:
    """These assert the graceful-degradation contract when SQLAlchemy/
    aiosqlite aren't installed -- always exercised, unlike
    `TestCampaignEndpointsWithDatabase` below, since it doesn't require a
    real database dependency to be present."""

    async def test_list_campaigns_returns_503_when_persistence_unavailable(self, monkeypatch) -> None:
        import cyberjection.persistence as persistence_module

        monkeypatch.setattr(persistence_module, "_SQLALCHEMY_AVAILABLE", False)
        app = build_app()
        status, body = await _call_asgi_app(app, "GET", "/api/campaigns")
        assert status == 503
        assert body["error"] == "persistence_unavailable"

    async def test_get_campaign_returns_503_when_persistence_unavailable(self, monkeypatch) -> None:
        import cyberjection.persistence as persistence_module

        monkeypatch.setattr(persistence_module, "_SQLALCHEMY_AVAILABLE", False)
        app = build_app()
        status, body = await _call_asgi_app(app, "GET", "/api/campaigns/some-id")
        assert status == 503
