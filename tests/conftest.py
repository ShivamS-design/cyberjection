"""Shared pytest fixtures for the Cyberjection test suite."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, Iterator, Tuple
from urllib.parse import urlsplit, urlunsplit

import pytest


@pytest.fixture(autouse=True)
def _redis_backend(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Gives the Phase 7 distributed tests a Redis without any external
    service.

    `test_rate_limiter.py` / `test_coordinator.py` deliberately point each
    test at its own fake hostname (`redis://test-rl-1/0`,
    `redis://test-coord-4/0`, ...) for isolation. By default every
    `redis.asyncio.from_url` call is routed to an in-memory `fakeredis`
    server -- one per (host, port, db), so distinct hostnames stay isolated
    and two clients on the same URL share state, exactly like two clients
    on one real server. `fakeredis[lua]` executes the rate limiter's real
    Lua script, so its atomicity is still genuinely exercised.

    Set `CYBERJECTION_TEST_REDIS_URL=redis://host:port` to run the same
    tests against a real Redis server instead: each test URL's host/port is
    rewritten to that server and its database number is kept.
    """

    try:
        import redis.asyncio as aioredis
    except ImportError:
        yield
        return

    real_url = os.environ.get("CYBERJECTION_TEST_REDIS_URL")
    original_from_url = aioredis.from_url

    if real_url:
        target = urlsplit(real_url)

        def _rewrite(url: str, **kwargs: Any) -> Any:
            parts = urlsplit(url)
            return original_from_url(urlunsplit((target.scheme, target.netloc, parts.path, parts.query, "")), **kwargs)

        monkeypatch.setattr(aioredis, "from_url", _rewrite)
        yield
        return

    try:
        import fakeredis
        import fakeredis.aioredis
    except ImportError:
        yield  # tests needing Redis will fail with a clear connection error
        return

    servers: Dict[Tuple[Any, Any, str], "fakeredis.FakeServer"] = {}

    def _fake_from_url(url: str, **kwargs: Any) -> Any:
        parts = urlsplit(url)
        key = (parts.hostname, parts.port, parts.path or "/0")
        server = servers.setdefault(key, fakeredis.FakeServer())
        return fakeredis.aioredis.FakeRedis(server=server, decode_responses=kwargs.get("decode_responses", False))

    monkeypatch.setattr(aioredis, "from_url", _fake_from_url)
    yield


@pytest.fixture
def tmp_yaml_file(tmp_path: Path):
    """Factory fixture: write text to a temp .yaml file and return its path."""

    def _write(text: str, filename: str = "campaign.yaml") -> Path:
        path = tmp_path / filename
        path.write_text(text, encoding="utf-8")
        return path

    return _write


@pytest.fixture
def clean_env(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Ensure OPENAI_API_KEY-style vars used in tests don't leak between tests."""

    for var in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "OLLAMA_API_BASE"):
        monkeypatch.delenv(var, raising=False)
    yield
