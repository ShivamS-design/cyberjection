"""Runs the dashboard API (`cyberjection.api.app.build_app`) under a real
ASGI server.

`cyberjection.api.asgi.ASGIApp` needs nothing beyond the standard library
to build and unit-test (see that module's docstring), but actually
serving HTTP connections over a socket does need a real ASGI server --
this project doesn't reimplement `uvicorn`. `uvicorn` is declared as the
optional `api` extra in `pyproject.toml` rather than a hard dependency, so
importing `cyberjection.api` (or running `cyberjection serve --help`)
never requires it; only calling `run_server` does, matching the same
optional-dependency contract `cyberjection.persistence` uses for
SQLAlchemy and `cyberjection.evaluators.llamaguard` uses for
`onnxruntime`.
"""

from __future__ import annotations

from typing import Optional


class UvicornUnavailableError(RuntimeError):
    """Raised by `run_server` when `uvicorn` isn't installed."""


def run_server(*, host: str = "127.0.0.1", port: int = 8000, db_url: Optional[str] = None) -> None:
    """Builds the dashboard API app and serves it with `uvicorn.run`.
    Blocks until the server is stopped (Ctrl+C / SIGTERM). Raises
    `UvicornUnavailableError` if `uvicorn` isn't installed rather than
    letting a bare `ImportError` surface -- `cyberjection.cli.main`'s
    `serve` command catches this and reports it the same way `inspect`
    reports a missing persistence layer."""

    try:
        import uvicorn
    except ImportError as exc:
        raise UvicornUnavailableError(
            "uvicorn is not installed. Install it with `pip install cyberjection[api]` "
            "(or `pip install uvicorn`) to run `cyberjection serve`."
        ) from exc

    from cyberjection.api.app import build_app

    app = build_app(db_url=db_url)
    uvicorn.run(app, host=host, port=port)
