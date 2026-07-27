from collections.abc import (
    Sequence,
)

import sqlalchemy as sa
from alembic import op


revision: str = "a8f3c1d7e2b4"
down_revision: str | None = (
    "d4a7c2e91b65"
)
branch_labels: (
    str
    | Sequence[str]
    | None
) = None
depends_on: (
    str
    | Sequence[str]
    | None
) = None


def upgrade() -> None:
    op.create_table(
        (
            "investigation_summary_"
            "traceability_reports"
        ),
        sa.Column(
            "id",
            sa.Uuid(),
            nullable=False,
        ),
        sa.Column(
            "investigation_summary_id",
            sa.Uuid(),
            nullable=False,
        ),
        sa.Column(
            "case_id",
            sa.Uuid(),
            nullable=False,
        ),
        sa.Column(
            "schema_version",
            sa.String(length=50),
            nullable=False,
        ),
        sa.Column(
            "claims",
            sa.JSON(),
            nullable=False,
        ),
        sa.Column(
            "total_claim_count",
            sa.Integer(),
            nullable=False,
        ),
        sa.Column(
            "supported_claim_count",
            sa.Integer(),
            nullable=False,
        ),
        sa.Column(
            "unsupported_claim_count",
            sa.Integer(),
            nullable=False,
        ),
        sa.Column(
            "direct_support_count",
            sa.Integer(),
            nullable=False,
        ),
        sa.Column(
            "derived_support_count",
            sa.Integer(),
            nullable=False,
        ),
        sa.Column(
            "contextual_support_count",
            sa.Integer(),
            nullable=False,
        ),
        sa.Column(
            "citation_count",
            sa.Integer(),
            nullable=False,
        ),
        sa.Column(
            "source_summary_output_sha256",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column(
            "report_sha256",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column(
            "generated_at",
            sa.DateTime(
                timezone=True
            ),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(
                timezone=True
            ),
            nullable=False,
        ),
        sa.CheckConstraint(
            "total_claim_count >= 0 "
            "AND supported_claim_count >= 0 "
            "AND unsupported_claim_count >= 0 "
            "AND direct_support_count >= 0 "
            "AND derived_support_count >= 0 "
            "AND contextual_support_count >= 0 "
            "AND citation_count >= 0",
            name=(
                "ck_investigation_summary_"
                "traceability_counts_nonnegative"
            ),
        ),
        sa.CheckConstraint(
            "supported_claim_count + "
            "unsupported_claim_count = "
            "total_claim_count",
            name=(
                "ck_investigation_summary_"
                "traceability_claim_totals"
            ),
        ),
        sa.CheckConstraint(
            "direct_support_count + "
            "derived_support_count + "
            "contextual_support_count = "
            "supported_claim_count",
            name=(
                "ck_investigation_summary_"
                "traceability_support_totals"
            ),
        ),
        sa.CheckConstraint(
            "char_length("
            "source_summary_output_sha256"
            ") = 64 "
            "AND char_length("
            "report_sha256"
            ") = 64",
            name=(
                "ck_investigation_summary_"
                "traceability_hash_lengths"
            ),
        ),
        sa.ForeignKeyConstraint(
            [
                "investigation_summary_id"
            ],
            [
                "investigation_summaries.id"
            ],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["case_id"],
            ["cases.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint(
            "id"
        ),
        sa.UniqueConstraint(
            "investigation_summary_id",
            name=(
                "uq_investigation_summary_"
                "traceability_summary"
            ),
        ),
    )

    op.create_index(
        (
            "ix_investigation_summary_"
            "traceability_case_created_at"
        ),
        (
            "investigation_summary_"
            "traceability_reports"
        ),
        [
            "case_id",
            "created_at",
        ],
        unique=False,
    )

    op.create_index(
        (
            "ix_investigation_summary_"
            "traceability_case_generated_at"
        ),
        (
            "investigation_summary_"
            "traceability_reports"
        ),
        [
            "case_id",
            "generated_at",
        ],
        unique=False,
    )

    op.create_index(
        (
            "ix_investigation_summary_"
            "traceability_case_id"
        ),
        (
            "investigation_summary_"
            "traceability_reports"
        ),
        ["case_id"],
        unique=False,
    )

    op.create_index(
        (
            "ix_investigation_summary_"
            "traceability_created_at"
        ),
        (
            "investigation_summary_"
            "traceability_reports"
        ),
        ["created_at"],
        unique=False,
    )

    op.create_index(
        (
            "ix_investigation_summary_"
            "traceability_generated_at"
        ),
        (
            "investigation_summary_"
            "traceability_reports"
        ),
        ["generated_at"],
        unique=False,
    )

    op.create_index(
        (
            "ix_investigation_summary_"
            "traceability_report_sha256"
        ),
        (
            "investigation_summary_"
            "traceability_reports"
        ),
        ["report_sha256"],
        unique=False,
    )

    op.create_index(
        (
            "ix_investigation_summary_"
            "traceability_source_sha256"
        ),
        (
            "investigation_summary_"
            "traceability_reports"
        ),
        [
            "source_summary_output_sha256"
        ],
        unique=False,
    )

    op.create_index(
        (
            "ix_investigation_summary_"
            "traceability_summary_id"
        ),
        (
            "investigation_summary_"
            "traceability_reports"
        ),
        [
            "investigation_summary_id"
        ],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        (
            "ix_investigation_summary_"
            "traceability_summary_id"
        ),
        table_name=(
            "investigation_summary_"
            "traceability_reports"
        ),
    )

    op.drop_index(
        (
            "ix_investigation_summary_"
            "traceability_source_sha256"
        ),
        table_name=(
            "investigation_summary_"
            "traceability_reports"
        ),
    )

    op.drop_index(
        (
            "ix_investigation_summary_"
            "traceability_report_sha256"
        ),
        table_name=(
            "investigation_summary_"
            "traceability_reports"
        ),
    )

    op.drop_index(
        (
            "ix_investigation_summary_"
            "traceability_generated_at"
        ),
        table_name=(
            "investigation_summary_"
            "traceability_reports"
        ),
    )

    op.drop_index(
        (
            "ix_investigation_summary_"
            "traceability_created_at"
        ),
        table_name=(
            "investigation_summary_"
            "traceability_reports"
        ),
    )

    op.drop_index(
        (
            "ix_investigation_summary_"
            "traceability_case_id"
        ),
        table_name=(
            "investigation_summary_"
            "traceability_reports"
        ),
    )

    op.drop_index(
        (
            "ix_investigation_summary_"
            "traceability_case_generated_at"
        ),
        table_name=(
            "investigation_summary_"
            "traceability_reports"
        ),
    )

    op.drop_index(
        (
            "ix_investigation_summary_"
            "traceability_case_created_at"
        ),
        table_name=(
            "investigation_summary_"
            "traceability_reports"
        ),
    )

    op.drop_table(
        (
            "investigation_summary_"
            "traceability_reports"
        )
    )