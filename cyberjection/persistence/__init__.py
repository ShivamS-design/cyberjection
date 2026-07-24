"""Persistence layer: SQLAlchemy models, the async SQLite engine/session
factory, the campaign/test repository, and campaign resumability.

The SQLAlchemy-backed pieces (`models`, `repository`, `sqlite`) are imported
here inside a `try`/`except ImportError` so that importing
`cyberjection.persistence` still succeeds in an environment without
SQLAlchemy/aiosqlite installed -- matching the same graceful-fallback
pattern `cyberjection.evaluators.llamaguard` uses for `onnxruntime`. The
resumability reconciliation logic (`build_resume_map` and friends) has no
SQLAlchemy dependency at all, so it stays importable and usable either way;
`_SQLALCHEMY_AVAILABLE` tells a caller which situation it's in.
"""

try:
    from cyberjection.persistence.models import (
        Base,
        CampaignModel,
        FindingModel,
        MetricModel,
        TestModel,
        TurnModel,
    )
    from cyberjection.persistence.repository import CampaignRepository
    from cyberjection.persistence.sqlite import DatabaseManager, DEFAULT_DB_URL

    _SQLALCHEMY_AVAILABLE = True
except ImportError:  # pragma: no cover - only without sqlalchemy installed
    Base = None
    CampaignModel = None
    FindingModel = None
    MetricModel = None
    TestModel = None
    TurnModel = None
    CampaignRepository = None
    DatabaseManager = None
    DEFAULT_DB_URL = "sqlite+aiosqlite:///.cyberjection/results.db"
    _SQLALCHEMY_AVAILABLE = False

from cyberjection.persistence.resumability import (
    ResumabilityError,
    ResumabilityKeyCollisionError,
    ResumabilityManager,
    ResumeDecision,
    ResumedTestState,
    ResumedTurnState,
    build_resume_map,
    decide_resume_action,
    reconcile_test_state,
)

__all__ = [
    "Base",
    "CampaignModel",
    "TestModel",
    "TurnModel",
    "FindingModel",
    "MetricModel",
    "CampaignRepository",
    "ResumabilityError",
    "ResumabilityKeyCollisionError",
    "ResumabilityManager",
    "ResumeDecision",
    "ResumedTestState",
    "ResumedTurnState",
    "build_resume_map",
    "decide_resume_action",
    "reconcile_test_state",
    "DatabaseManager",
    "DEFAULT_DB_URL",
]
