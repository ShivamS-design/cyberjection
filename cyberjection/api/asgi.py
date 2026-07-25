"""A minimal, dependency-free ASGI toolkit: request/response types, a path
router, and an application object implementing the ASGI 3.0 `http` and
`lifespan` protocols.

Cyberjection's dashboard backend (`cyberjection.api.app`) is deliberately
built on nothing but this module and the Python standard library rather
than a web framework (FastAPI/Starlette/Flask): none of those are
installable in every environment this project already supports without
one (the same offline-friendly constraint that led `cyberjection.cli.main`
to build on `typer`/`rich`, which -- unlike a web framework -- were
already declared dependencies since Phase 1). An `ASGIApp` instance here
is a plain `async def __call__(self, scope, receive, send)` callable, so
it runs unmodified under any real ASGI server (`uvicorn`, `hypercorn`,
`daphne`) in production; `cyberjection.api.server.run_server` is the only
place that ever imports one of those, and only at call time, so importing
`cyberjection.api` itself never requires one to be installed.

This is not a general-purpose web framework: no middleware chain, no
dependency injection, no request body streaming, no WebSocket support --
just enough routing and JSON request/response handling for the dashboard
API's five read-only endpoints (`cyberjection.api.app`). Extending it to
do more than that is out of scope for what this project needs a web layer
for.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl

_PATH_PARAM_RE = re.compile(r"\{(\w+)\}")


def _compile_path(pattern: str) -> "re.Pattern[str]":
    """Compiles a route pattern like ``/api/campaigns/{campaign_id}`` into
    a regex with one named group per ``{param}`` segment. Segments match
    one or more non-``/`` characters, so a path parameter can never itself
    contain an unescaped ``/``."""

    escaped_parts = []
    last_end = 0
    for match in _PATH_PARAM_RE.finditer(pattern):
        escaped_parts.append(re.escape(pattern[last_end:match.start()]))
        escaped_parts.append(f"(?P<{match.group(1)}>[^/]+)")
        last_end = match.end()
    escaped_parts.append(re.escape(pattern[last_end:]))
    return re.compile("^" + "".join(escaped_parts) + "$")


@dataclass
class Request:
    """One inbound HTTP request, as much of it as the dashboard API's
    handlers need: method, matched path parameters, and parsed query
    string. Request bodies aren't parsed here -- none of Phase 10's
    endpoints accept one (they're all read-only `GET`s); a future
    write endpoint would extend this class rather than every handler
    reading `receive` directly."""

    method: str
    path: str
    path_params: Dict[str, str] = field(default_factory=dict)
    query_params: Dict[str, str] = field(default_factory=dict)

    def query_int(self, name: str, default: int) -> int:
        """Parses a query parameter as an int, falling back to `default`
        if it's absent or not a valid integer -- so a malformed
        `?limit=abc` degrades to the default rather than raising a 500."""

        raw = self.query_params.get(name)
        if raw is None:
            return default
        try:
            return int(raw)
        except ValueError:
            return default


@dataclass
class Response:
    """An outbound HTTP response. `JSONResponse` is the constructor every
    handler in `cyberjection.api.app` actually uses; this base class stays
    format-agnostic in case a future endpoint needs to return something
    that isn't JSON (a health-check plaintext body, for instance)."""

    status_code: int
    body: bytes
    headers: List[Tuple[str, str]] = field(default_factory=list)


def JSONResponse(payload: Any, *, status_code: int = 200) -> Response:
    """Builds a `Response` whose body is `payload` serialized as JSON.
    Named like a class (`JSONResponse(...)`, not `json_response(...)`) to
    match the shape every handler in `cyberjection.api.app` is written
    against -- callers don't need to know it's a plain function."""

    body = json.dumps(payload, default=str).encode("utf-8")
    return Response(status_code=status_code, body=body, headers=[("content-type", "application/json")])


Handler = Callable[[Request], Awaitable[Response]]


class Router:
    """Matches `(method, path)` against a list of registered routes, in
    registration order -- the first pattern that matches wins, so a more
    specific route (e.g. `/api/campaigns/{id}/tests/{test_id}`) must be
    registered before a less specific one that could also match a prefix
    of the same path, if such an ambiguity is ever introduced."""

    def __init__(self) -> None:
        self._routes: List[Tuple[str, "re.Pattern[str]", Handler]] = []

    def add_route(self, method: str, path_pattern: str, handler: Handler) -> None:
        self._routes.append((method.upper(), _compile_path(path_pattern), handler))

    def match(self, method: str, path: str) -> Optional[Tuple[Handler, Dict[str, str]]]:
        for route_method, compiled, handler in self._routes:
            if route_method != method.upper():
                continue
            found = compiled.match(path)
            if found:
                return handler, found.groupdict()
        return None


class ASGIApp:
    """A minimal ASGI 3.0 application: handles `lifespan` (so an ASGI
    server's startup/shutdown handshake completes cleanly even though
    this app has no startup/shutdown work to do) and `http` (routing
    through `self.router`, JSON error responses for a 404/405/500)."""

    def __init__(self, router: Router) -> None:
        self.router = router

    async def __call__(self, scope: Dict[str, Any], receive: Callable, send: Callable) -> None:
        if scope["type"] == "lifespan":
            await self._handle_lifespan(receive, send)
            return
        if scope["type"] != "http":
            # No WebSocket support (see module docstring) -- refuse
            # anything that isn't `http`/`lifespan` rather than silently
            # doing nothing, which would hang the connecting client.
            raise NotImplementedError(f"Unsupported ASGI scope type: {scope['type']!r}")
        await self._handle_http(scope, receive, send)

    async def _handle_lifespan(self, receive: Callable, send: Callable) -> None:
        while True:
            message = await receive()
            if message["type"] == "lifespan.startup":
                await send({"type": "lifespan.startup.complete"})
            elif message["type"] == "lifespan.shutdown":
                await send({"type": "lifespan.shutdown.complete"})
                return

    async def _handle_http(self, scope: Dict[str, Any], receive: Callable, send: Callable) -> None:
        method = scope["method"]
        path = scope["path"]
        query_params = dict(parse_qsl((scope.get("query_string") or b"").decode("utf-8")))

        matched = self.router.match(method, path)
        if matched is None:
            response = JSONResponse({"error": "not_found", "path": path}, status_code=404)
        else:
            handler, path_params = matched
            request = Request(method=method, path=path, path_params=path_params, query_params=query_params)
            try:
                response = await handler(request)
            except Exception as exc:  # noqa: BLE001 - last-resort handler boundary
                response = JSONResponse({"error": "internal_error", "detail": str(exc)}, status_code=500)

        await send(
            {
                "type": "http.response.start",
                "status": response.status_code,
                "headers": [
                    (name.encode("utf-8"), value.encode("utf-8")) for name, value in response.headers
                ],
            }
        )
        await send({"type": "http.response.body", "body": response.body})
