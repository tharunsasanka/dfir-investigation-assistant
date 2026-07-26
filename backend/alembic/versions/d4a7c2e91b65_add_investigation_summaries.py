from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision: str = "d4a7c2e91b65"
down_revision: str | None = "7f9d4c6e2a11"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


investigation_summary_status = postgresql.ENUM(
    "generating",
    "pending_review",
    "approved",
    "rejected",
    "failed",
    name="investigationsummarystatus",
    create_type=False,
)

investigation_summary_source = postgresql.ENUM(
    "deterministic",
    "local_ai",
    "hosted_ai",
    "analyst",
    name="investigationsummarysource",
    create_type=False,
)


def upgrade() -> None:
    postgresql.ENUM(
        "generating",
        "pending_review",
        "approved",
        "rejected",
        "failed",
        name="investigationsummarystatus",
    ).create(
        op.get_bind(),
        checkfirst=True,
    )

    postgresql.ENUM(
        "deterministic",
        "local_ai",
        "hosted_ai",
        "analyst",
        name="investigationsummarysource",
    ).create(
        op.get_bind(),
        checkfirst=True,
    )

    op.create_table(
        "investigation_summaries",
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
            "parent_summary_id",
            sa.Uuid(),
            nullable=True,
        ),
        sa.Column(
            "version_number",
            sa.Integer(),
            nullable=False,
        ),
        sa.Column(
            "status",
            investigation_summary_status,
            nullable=False,
        ),
        sa.Column(
            "generation_source",
            investigation_summary_source,
            nullable=False,
        ),
        sa.Column(
            "title",
            sa.String(length=255),
            nullable=False,
        ),
        sa.Column(
            "executive_summary",
            sa.Text(),
            nullable=False,
        ),
        sa.Column(
            "technical_narrative",
            sa.Text(),
            nullable=False,
        ),
        sa.Column(
            "technical_findings",
            sa.JSON(),
            nullable=False,
        ),
        sa.Column(
            "incident_scope",
            sa.JSON(),
            nullable=False,
        ),
        sa.Column(
            "mitre_coverage",
            sa.JSON(),
            nullable=False,
        ),
        sa.Column(
            "evidence_references",
            sa.JSON(),
            nullable=False,
        ),
        sa.Column(
            "recommended_actions",
            sa.JSON(),
            nullable=False,
        ),
        sa.Column(
            "verified_facts",
            sa.JSON(),
            nullable=False,
        ),
        sa.Column(
            "assumptions",
            sa.JSON(),
            nullable=False,
        ),
        sa.Column(
            "limitations",
            sa.JSON(),
            nullable=False,
        ),
        sa.Column(
            "confidence_score",
            sa.Integer(),
            nullable=False,
        ),
        sa.Column(
            "provider_name",
            sa.String(length=100),
            nullable=False,
        ),
        sa.Column(
            "model_name",
            sa.String(length=150),
            nullable=False,
        ),
        sa.Column(
            "prompt_template_version",
            sa.String(length=50),
            nullable=False,
        ),
        sa.Column(
            "generation_parameters",
            sa.JSON(),
            nullable=False,
        ),
        sa.Column(
            "source_snapshot",
            sa.JSON(),
            nullable=False,
        ),
        sa.Column(
            "source_snapshot_sha256",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column(
            "output_sha256",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column(
            "requested_by_user_id",
            sa.Uuid(),
            nullable=True,
        ),
        sa.Column(
            "reviewed_by_user_id",
            sa.Uuid(),
            nullable=True,
        ),
        sa.Column(
            "review_notes",
            sa.Text(),
            nullable=False,
        ),
        sa.Column(
            "generation_error",
            sa.Text(),
            nullable=False,
        ),
        sa.Column(
            "generation_started_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.Column(
            "generation_completed_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.Column(
            "reviewed_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.CheckConstraint(
            "version_number >= 1",
            name=(
                "ck_investigation_summaries_"
                "version_positive"
            ),
        ),
        sa.CheckConstraint(
            "confidence_score >= 0 "
            "AND confidence_score <= 100",
            name=(
                "ck_investigation_summaries_"
                "confidence"
            ),
        ),
        sa.ForeignKeyConstraint(
            ["case_id"],
            ["cases.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["parent_summary_id"],
            ["investigation_summaries.id"],
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["requested_by_user_id"],
            ["users.id"],
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["reviewed_by_user_id"],
            ["users.id"],
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "case_id",
            "version_number",
            name=(
                "uq_investigation_summaries_"
                "case_version"
            ),
        ),
    )

    op.create_index(
        "ix_investigation_summaries_case_created_at",
        "investigation_summaries",
        ["case_id", "created_at"],
        unique=False,
    )

    op.create_index(
        "ix_investigation_summaries_case_id",
        "investigation_summaries",
        ["case_id"],
        unique=False,
    )

    op.create_index(
        "ix_investigation_summaries_case_status",
        "investigation_summaries",
        ["case_id", "status"],
        unique=False,
    )

    op.create_index(
        "ix_investigation_summaries_case_version",
        "investigation_summaries",
        ["case_id", "version_number"],
        unique=False,
    )

    op.create_index(
        "ix_investigation_summaries_confidence_score",
        "investigation_summaries",
        ["confidence_score"],
        unique=False,
    )

    op.create_index(
        "ix_investigation_summaries_created_at",
        "investigation_summaries",
        ["created_at"],
        unique=False,
    )

    op.create_index(
        "ix_investigation_summaries_generation_source",
        "investigation_summaries",
        ["generation_source"],
        unique=False,
    )

    op.create_index(
        "ix_investigation_summaries_model_name",
        "investigation_summaries",
        ["model_name"],
        unique=False,
    )

    op.create_index(
        "ix_investigation_summaries_output_sha256",
        "investigation_summaries",
        ["output_sha256"],
        unique=False,
    )

    op.create_index(
        "ix_investigation_summaries_parent_summary_id",
        "investigation_summaries",
        ["parent_summary_id"],
        unique=False,
    )

    op.create_index(
        "ix_investigation_summaries_provider_model",
        "investigation_summaries",
        ["provider_name", "model_name"],
        unique=False,
    )

    op.create_index(
        "ix_investigation_summaries_provider_name",
        "investigation_summaries",
        ["provider_name"],
        unique=False,
    )

    op.create_index(
        "ix_investigation_summaries_requested_by_user_id",
        "investigation_summaries",
        ["requested_by_user_id"],
        unique=False,
    )

    op.create_index(
        "ix_investigation_summaries_reviewed_by_user_id",
        "investigation_summaries",
        ["reviewed_by_user_id"],
        unique=False,
    )

    op.create_index(
        "ix_investigation_summaries_source_snapshot_sha256",
        "investigation_summaries",
        ["source_snapshot_sha256"],
        unique=False,
    )

    op.create_index(
        "ix_investigation_summaries_status",
        "investigation_summaries",
        ["status"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_investigation_summaries_status",
        table_name="investigation_summaries",
    )

    op.drop_index(
        "ix_investigation_summaries_source_snapshot_sha256",
        table_name="investigation_summaries",
    )

    op.drop_index(
        "ix_investigation_summaries_reviewed_by_user_id",
        table_name="investigation_summaries",
    )

    op.drop_index(
        "ix_investigation_summaries_requested_by_user_id",
        table_name="investigation_summaries",
    )

    op.drop_index(
        "ix_investigation_summaries_provider_name",
        table_name="investigation_summaries",
    )

    op.drop_index(
        "ix_investigation_summaries_provider_model",
        table_name="investigation_summaries",
    )

    op.drop_index(
        "ix_investigation_summaries_parent_summary_id",
        table_name="investigation_summaries",
    )

    op.drop_index(
        "ix_investigation_summaries_output_sha256",
        table_name="investigation_summaries",
    )

    op.drop_index(
        "ix_investigation_summaries_model_name",
        table_name="investigation_summaries",
    )

    op.drop_index(
        "ix_investigation_summaries_generation_source",
        table_name="investigation_summaries",
    )

    op.drop_index(
        "ix_investigation_summaries_created_at",
        table_name="investigation_summaries",
    )

    op.drop_index(
        "ix_investigation_summaries_confidence_score",
        table_name="investigation_summaries",
    )

    op.drop_index(
        "ix_investigation_summaries_case_version",
        table_name="investigation_summaries",
    )

    op.drop_index(
        "ix_investigation_summaries_case_status",
        table_name="investigation_summaries",
    )

    op.drop_index(
        "ix_investigation_summaries_case_id",
        table_name="investigation_summaries",
    )

    op.drop_index(
        "ix_investigation_summaries_case_created_at",
        table_name="investigation_summaries",
    )

    op.drop_table(
        "investigation_summaries"
    )

    postgresql.ENUM(
        name="investigationsummarysource",
    ).drop(
        op.get_bind(),
        checkfirst=True,
    )

    postgresql.ENUM(
        name="investigationsummarystatus",
    ).drop(
        op.get_bind(),
        checkfirst=True,
    )