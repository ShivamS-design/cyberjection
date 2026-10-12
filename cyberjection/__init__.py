"""Cyberjection: enterprise-grade asynchronous LLM red-teaming and security
orchestration framework.

Phase 1 scope: declarative configuration engine, target abstraction gateway
(LiteLLM), and the shared async execution/exception primitives that later
phases (mutation engine, cascade evaluator, orchestrator, CLI/API) build on.
"""

from importlib.metadata import PackageNotFoundError, version as _version

try:
    # Single source of truth: the version in pyproject.toml, as installed.
    __version__ = _version("cyberjection")
except PackageNotFoundError:  # running from a source tree that isn't installed
    __version__ = "0.0.0+unknown"
