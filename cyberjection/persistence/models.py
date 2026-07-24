"""SQLAlchemy 2 declarative schema: campaigns, tests, conversation turns,
security findings, and per-test execution metrics.

Every table uses a string UUID primary key (rather than an auto-increment
integer) so IDs can be generated client-side before the first `INSERT` --
useful for the resumability engine, which needs to reference a campaign or
test id before persisting it, and for correlating IDs across log lines
without a round trip to the database first.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy import DateTime, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


def generate_uuid() -> str:
    return str(uuid.uuid4())


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class CampaignModel(Base):
    """A single campaign run: a named collection of tests executed against
    one or more targets, tracked from QUEUED through COMPLETED/FAILED/
    INTERRUPTED so an interrupted run can be identified and resumed."""

    __tablename__ = "campaigns"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    # QUEUED, RUNNING, COMPLETED, FAILED, INTERRUPTED
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="QUEUED")
    total_cost: Mapped[float] = mapped_column(Float, default=0.0)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    tests: Mapped[List["TestModel"]] = relationship(
        "TestModel", back_populates="campaign", cascade="all, delete-orphan"
    )

    __table_args__ = (Index("idx_campaigns_status", "status"),)


class TestModel(Base):
    """A single test case execution within a campaign: one target, one
    strategy, one seed prompt, and however many conversation turns that
    strategy needs (1 for single-turn attacks, up to `max_turns` for
    adaptive multi-turn strategies in later phases)."""

    __tablename__ = "tests"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    campaign_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("campaigns.id", ondelete="CASCADE"), nullable=False
    )
    target_id: Mapped[str] = mapped_column(String(100), nullable=False)
    strategy: Mapped[str] = mapped_column(String(100), nullable=False)
    seed_prompt: Mapped[str] = mapped_column(Text, nullable=False)
    # RUNNING, COMPLETED, FAILED
    status: Mapped[str] = mapped_column(String(50), default="RUNNING")
    score: Mapped[float] = mapped_column(Float, default=0.0)
    # PASS, FAIL, UNCERTAIN -- mirrors cyberjection.evaluators.base.Verdict
    verdict: Mapped[str] = mapped_column(String(20), default="UNCERTAIN")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    campaign: Mapped["CampaignModel"] = relationship("CampaignModel", back_populates="tests")
    turns: Mapped[List["TurnModel"]] = relationship(
        "TurnModel", back_populates="test", cascade="all, delete-orphan", order_by="TurnModel.turn_number"
    )
    findings: Mapped[List["FindingModel"]] = relationship(
        "FindingModel", back_populates="test", cascade="all, delete-orphan"
    )
    metrics: Mapped[Optional["MetricModel"]] = relationship(
        "MetricModel", back_populates="test", uselist=False, cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("idx_tests_campaign_status", "campaign_id", "status"),
        # The resumability engine looks up a test by (campaign, target,
        # strategy, seed_prompt) rather than by seed_prompt alone -- see
        # cyberjection/persistence/resumability.py -- so query performance
        # for that lookup pattern matters as much as the campaign+status one.
        Index("idx_tests_campaign_target_strategy", "campaign_id", "target_id", "strategy"),
    )


class TurnModel(Base):
    """One prompt/response exchange within a test. `turn_number` is
    1-indexed and unique per test; the resumability engine reconstructs
    conversation history by loading a test's turns ordered by this field."""

    __tablename__ = "turns"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    test_id: Mapped[str] = mapped_column(String(36), ForeignKey("tests.id", ondelete="CASCADE"), nullable=False)
    turn_number: Mapped[int] = mapped_column(Integer, nullable=False)
    prompt_payload: Mapped[str] = mapped_column(Text, nullable=False)
    response_payload: Mapped[str] = mapped_column(Text, nullable=False)
    latency_ms: Mapped[float] = mapped_column(Float, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    test: Mapped["TestModel"] = relationship("TestModel", back_populates="turns")

    __table_args__ = (
        Index("idx_turns_test_number", "test_id", "turn_number", unique=True),
    )


class FindingModel(Base):
    """A security finding raised against a test's outcome (e.g. a Tier 1/2/3
    evaluator FAIL verdict, or a manually flagged issue during review)."""

    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    test_id: Mapped[str] = mapped_column(String(36), ForeignKey("tests.id", ondelete="CASCADE"), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)  # LOW, MEDIUM, HIGH, CRITICAL
    owasp_category: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    test: Mapped["TestModel"] = relationship("TestModel", back_populates="findings")

    __table_args__ = (Index("idx_findings_test_severity", "test_id", "severity"),)


class MetricModel(Base):
    """Per-test execution telemetry: token usage, cost, and which cascade
    tier ultimately produced the verdict. One-to-one with `TestModel`
    (`test_id` is both the foreign key and the primary key)."""

    __tablename__ = "metrics"

    test_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tests.id", ondelete="CASCADE"), primary_key=True
    )
    prompt_tokens: Mapped[int] = mapped_column(Integer, default=0)
    completion_tokens: Mapped[int] = mapped_column(Integer, default=0)
    total_cost: Mapped[float] = mapped_column(Float, default=0.0)
    judge_tier_used: Mapped[int] = mapped_column(Integer, default=1)

    test: Mapped["TestModel"] = relationship("TestModel", back_populates="metrics")
