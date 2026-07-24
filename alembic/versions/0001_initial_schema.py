"""Initial schema: campaigns, tests, turns, findings, metrics.

Revision ID: 0001
Revises:
Create Date: 2026-07-23

Hand-authored rather than produced by `alembic revision --autogenerate`,
since this sandbox has no network access to install Alembic/SQLAlchemy and
run autogeneration against a live connection. Every column, type,
nullability, index, and foreign-key/cascade rule below was cross-checked
field-by-field against `cyberjection/persistence/models.py`; the two must
be kept in sync by hand if the models change.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "campaigns",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("status", sa.String(length=50), nullable=False, server_default="QUEUED"),
        sa.Column("total_cost", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("idx_campaigns_status", "campaigns", ["status"])

    op.create_table(
        "tests",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "campaign_id",
            sa.String(length=36),
            sa.ForeignKey("campaigns.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("target_id", sa.String(length=100), nullable=False),
        sa.Column("strategy", sa.String(length=100), nullable=False),
        sa.Column("seed_prompt", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=50), nullable=False, server_default="RUNNING"),
        sa.Column("score", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("verdict", sa.String(length=20), nullable=False, server_default="UNCERTAIN"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("idx_tests_campaign_status", "tests", ["campaign_id", "status"])
    op.create_index(
        "idx_tests_campaign_target_strategy",
        "tests",
        ["campaign_id", "target_id", "strategy"],
    )

    op.create_table(
        "turns",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "test_id",
            sa.String(length=36),
            sa.ForeignKey("tests.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("turn_number", sa.Integer(), nullable=False),
        sa.Column("prompt_payload", sa.Text(), nullable=False),
        sa.Column("response_payload", sa.Text(), nullable=False),
        sa.Column("latency_ms", sa.Float(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "idx_turns_test_number", "turns", ["test_id", "turn_number"], unique=True
    )

    op.create_table(
        "findings",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "test_id",
            sa.String(length=36),
            sa.ForeignKey("tests.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("owasp_category", sa.String(length=100), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("idx_findings_test_severity", "findings", ["test_id", "severity"])

    op.create_table(
        "metrics",
        sa.Column(
            "test_id",
            sa.String(length=36),
            sa.ForeignKey("tests.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("prompt_tokens", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("completion_tokens", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("total_cost", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("judge_tier_used", sa.Integer(), nullable=False, server_default="1"),
    )


def downgrade() -> None:
    op.drop_table("metrics")
    op.drop_table("findings")
    op.drop_table("turns")
    op.drop_table("tests")
    op.drop_table("campaigns")
