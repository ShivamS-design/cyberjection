"""Dashboard API (Phase 10): a dependency-free ASGI application
(`cyberjection.api.asgi`, `cyberjection.api.app`) plus the `uvicorn`-backed
entrypoint that actually serves it (`cyberjection.api.server`).

Only `cyberjection.api.server.run_server` requires `uvicorn` to be
installed; building and unit-testing the app itself (`build_app`) needs
nothing beyond the standard library and this project's own persistence
layer.
"""

from __future__ import annotations

from cyberjection.api.app import build_app

__all__ = ["build_app"]
