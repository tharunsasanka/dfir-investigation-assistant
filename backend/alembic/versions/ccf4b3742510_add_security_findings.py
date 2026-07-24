"""add security findings

Revision ID: ccf4b3742510
Revises: 3c694d61d600
Create Date: 2026-07-24 12:55:44.347777
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision: str = "ccf4b3742510"
down_revision: Union[str, None] = "3c694d61d600"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    existing_severity_enum = postgresql.ENUM(
        "unknown",
        "informational",
        "low",
        "medium",
        "high",
        "critical",
        name="logeventseverity",
        create_type=False,
    )

    op.create_table(
        "security_findings",
        sa.Column(
            "id",
            sa.Uuid(),
            nullable=False,
        ),
        sa.Column(
            "case_id",
            sa.Uuid(),
            nullable=False,
        ),
        sa.Column(
            "evidence_id",
            sa.Uuid(),
            nullable=False,
        ),
        sa.Column(
            "ingestion_job_id",
            sa.Uuid(),
            nullable=False,
        ),
        sa.Column(
            "parsed_event_id",
            sa.Uuid(),
            nullable=False,
        ),
        sa.Column(
            "event_index",
            sa.Integer(),
            nullable=False,
        ),
        sa.Column(
            "rule_id",
            sa.String(length=100),
            nullable=False,
        ),
        sa.Column(
            "title",
            sa.String(length=255),
            nullable=False,
        ),
        sa.Column(
            "description",
            sa.Text(),
            nullable=False,
        ),
        sa.Column(
            "severity",
            existing_severity_enum,
            nullable=False,
        ),
        sa.Column(
            "confidence",
            sa.Integer(),
            nullable=False,
        ),
        sa.Column(
            "event_time",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.Column(
            "event_code",
            sa.String(length=100),
            nullable=False,
        ),
        sa.Column(
            "source_type",
            sa.String(length=100),
            nullable=False,
        ),
        sa.Column(
            "mitre_tactic",
            sa.String(length=100),
            nullable=False,
        ),
        sa.Column(
            "mitre_technique_id",
            sa.String(length=50),
            nullable=False,
        ),
        sa.Column(
            "mitre_technique_name",
            sa.String(length=255),
            nullable=False,
        ),
        sa.Column(
            "indicators",
            sa.JSON(),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.CheckConstraint(
            "confidence >= 0 AND confidence <= 100",
            name="ck_security_findings_confidence",
        ),
        sa.ForeignKeyConstraint(
            ["case_id"],
            ["cases.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["evidence_id"],
            ["evidence.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["ingestion_job_id"],
            ["log_ingestion_jobs.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["parsed_event_id"],
            ["parsed_log_events.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "ingestion_job_id",
            "rule_id",
            "event_index",
            name="uq_security_findings_job_rule_event",
        ),
    )

    op.create_index(
        "ix_security_findings_case_created_at",
        "security_findings",
        ["case_id", "created_at"],
        unique=False,
    )

    op.create_index(
        op.f("ix_security_findings_case_id"),
        "security_findings",
        ["case_id"],
        unique=False,
    )

    op.create_index(
        "ix_security_findings_case_severity",
        "security_findings",
        ["case_id", "severity"],
        unique=False,
    )

    op.create_index(
        op.f("ix_security_findings_confidence"),
        "security_findings",
        ["confidence"],
        unique=False,
    )

    op.create_index(
        op.f("ix_security_findings_created_at"),
        "security_findings",
        ["created_at"],
        unique=False,
    )

    op.create_index(
        op.f("ix_security_findings_event_code"),
        "security_findings",
        ["event_code"],
        unique=False,
    )

    op.create_index(
        op.f("ix_security_findings_event_index"),
        "security_findings",
        ["event_index"],
        unique=False,
    )

    op.create_index(
        op.f("ix_security_findings_event_time"),
        "security_findings",
        ["event_time"],
        unique=False,
    )

    op.create_index(
        "ix_security_findings_evidence_created_at",
        "security_findings",
        ["evidence_id", "created_at"],
        unique=False,
    )

    op.create_index(
        op.f("ix_security_findings_evidence_id"),
        "security_findings",
        ["evidence_id"],
        unique=False,
    )

    op.create_index(
        op.f("ix_security_findings_ingestion_job_id"),
        "security_findings",
        ["ingestion_job_id"],
        unique=False,
    )

    op.create_index(
        "ix_security_findings_job_rule",
        "security_findings",
        ["ingestion_job_id", "rule_id"],
        unique=False,
    )

    op.create_index(
        op.f("ix_security_findings_mitre_tactic"),
        "security_findings",
        ["mitre_tactic"],
        unique=False,
    )

    op.create_index(
        op.f("ix_security_findings_mitre_technique_id"),
        "security_findings",
        ["mitre_technique_id"],
        unique=False,
    )

    op.create_index(
        op.f("ix_security_findings_parsed_event_id"),
        "security_findings",
        ["parsed_event_id"],
        unique=False,
    )

    op.create_index(
        op.f("ix_security_findings_rule_id"),
        "security_findings",
        ["rule_id"],
        unique=False,
    )

    op.create_index(
        op.f("ix_security_findings_severity"),
        "security_findings",
        ["severity"],
        unique=False,
    )

    op.create_index(
        op.f("ix_security_findings_source_type"),
        "security_findings",
        ["source_type"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        op.f("ix_security_findings_source_type"),
        table_name="security_findings",
    )

    op.drop_index(
        op.f("ix_security_findings_severity"),
        table_name="security_findings",
    )

    op.drop_index(
        op.f("ix_security_findings_rule_id"),
        table_name="security_findings",
    )

    op.drop_index(
        op.f("ix_security_findings_parsed_event_id"),
        table_name="security_findings",
    )

    op.drop_index(
        op.f("ix_security_findings_mitre_technique_id"),
        table_name="security_findings",
    )

    op.drop_index(
        op.f("ix_security_findings_mitre_tactic"),
        table_name="security_findings",
    )

    op.drop_index(
        "ix_security_findings_job_rule",
        table_name="security_findings",
    )

    op.drop_index(
        op.f("ix_security_findings_ingestion_job_id"),
        table_name="security_findings",
    )

    op.drop_index(
        op.f("ix_security_findings_evidence_id"),
        table_name="security_findings",
    )

    op.drop_index(
        "ix_security_findings_evidence_created_at",
        table_name="security_findings",
    )

    op.drop_index(
        op.f("ix_security_findings_event_time"),
        table_name="security_findings",
    )

    op.drop_index(
        op.f("ix_security_findings_event_index"),
        table_name="security_findings",
    )

    op.drop_index(
        op.f("ix_security_findings_event_code"),
        table_name="security_findings",
    )

    op.drop_index(
        op.f("ix_security_findings_created_at"),
        table_name="security_findings",
    )

    op.drop_index(
        op.f("ix_security_findings_confidence"),
        table_name="security_findings",
    )

    op.drop_index(
        "ix_security_findings_case_severity",
        table_name="security_findings",
    )

    op.drop_index(
        op.f("ix_security_findings_case_id"),
        table_name="security_findings",
    )

    op.drop_index(
        "ix_security_findings_case_created_at",
        table_name="security_findings",
    )

    op.drop_table("security_findings")