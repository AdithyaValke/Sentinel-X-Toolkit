"""Add user-owned investigation data foundation.

Revision ID: 20261005_0003
Revises: 20261005_0002
Create Date: 2026-10-05
"""

from alembic import op
import sqlalchemy as sa


revision = "20261005_0003"
down_revision = "20261005_0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "investigations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("owner_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("description", sa.String(length=10000)),
        sa.Column("status", sa.String(length=20), server_default="open", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("closed_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint("status IN ('open', 'investigating', 'resolved', 'closed')", name="ck_investigations_status"),
        sa.CheckConstraint("length(trim(title)) > 0", name="ck_investigations_title_nonempty"),
        sa.CheckConstraint("description IS NULL OR length(description) <= 10000", name="ck_investigations_description_length"),
    )

    op.create_table(
        "investigation_iocs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("investigation_id", sa.Integer(), sa.ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("ioc_type", sa.String(length=32), nullable=False),
        sa.Column("value", sa.String(length=2048), nullable=False),
        sa.Column("normalized_value", sa.String(length=2048)),
        sa.Column("source", sa.String(length=32), server_default="manual", nullable=False),
        sa.Column("confidence", sa.Integer()),
        sa.Column("first_seen", sa.DateTime(timezone=True)),
        sa.Column("last_seen", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("confidence IS NULL OR confidence BETWEEN 0 AND 100", name="ck_investigation_iocs_confidence_range"),
        sa.CheckConstraint("length(value) > 0", name="ck_investigation_iocs_value_nonempty"),
    )

    op.create_table(
        "investigation_findings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("investigation_id", sa.Integer(), sa.ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("description", sa.String(length=10000)),
        sa.Column("severity", sa.String(length=16), server_default="info", nullable=False),
        sa.Column("status", sa.String(length=16), server_default="open", nullable=False),
        sa.Column("source", sa.String(length=32)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("severity IN ('info', 'low', 'medium', 'high', 'critical')", name="ck_investigation_findings_severity"),
        sa.CheckConstraint("status IN ('open', 'confirmed', 'dismissed', 'resolved')", name="ck_investigation_findings_status"),
        sa.CheckConstraint("length(trim(title)) > 0", name="ck_investigation_findings_title_nonempty"),
        sa.UniqueConstraint("id", "investigation_id", name="uq_investigation_findings_id_investigation"),
    )

    op.create_table(
        "investigation_evidence",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("investigation_id", sa.Integer(), sa.ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("finding_id", sa.Integer()),
        sa.Column("evidence_type", sa.String(length=32), nullable=False),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("source", sa.String(length=32)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(
            ["finding_id", "investigation_id"],
            ["investigation_findings.id", "investigation_findings.investigation_id"],
            name="fk_investigation_evidence_finding_investigation",
            ondelete="CASCADE",
        ),
    )

    op.create_table(
        "investigation_events",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("investigation_id", sa.Integer(), sa.ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("event_type", sa.String(length=40), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )

    for name, table, columns in (
        ("ix_investigations_owner_id", "investigations", ["owner_id"]),
        ("ix_investigations_status", "investigations", ["status"]),
        ("ix_investigations_updated_at", "investigations", ["updated_at"]),
        ("ix_investigation_iocs_investigation_id", "investigation_iocs", ["investigation_id"]),
        ("ix_investigation_iocs_ioc_type", "investigation_iocs", ["ioc_type"]),
        ("ix_investigation_iocs_normalized_value", "investigation_iocs", ["normalized_value"]),
        ("ix_investigation_findings_investigation_id", "investigation_findings", ["investigation_id"]),
        ("ix_investigation_findings_severity", "investigation_findings", ["severity"]),
        ("ix_investigation_findings_status", "investigation_findings", ["status"]),
        ("ix_investigation_evidence_investigation_id", "investigation_evidence", ["investigation_id"]),
        ("ix_investigation_events_investigation_id", "investigation_events", ["investigation_id"]),
        ("ix_investigation_events_created_at", "investigation_events", ["created_at"]),
    ):
        op.create_index(name, table, columns)


def downgrade() -> None:
    for name, table in (
        ("ix_investigation_events_created_at", "investigation_events"),
        ("ix_investigation_events_investigation_id", "investigation_events"),
        ("ix_investigation_evidence_investigation_id", "investigation_evidence"),
        ("ix_investigation_findings_status", "investigation_findings"),
        ("ix_investigation_findings_severity", "investigation_findings"),
        ("ix_investigation_findings_investigation_id", "investigation_findings"),
        ("ix_investigation_iocs_normalized_value", "investigation_iocs"),
        ("ix_investigation_iocs_ioc_type", "investigation_iocs"),
        ("ix_investigation_iocs_investigation_id", "investigation_iocs"),
        ("ix_investigations_updated_at", "investigations"),
        ("ix_investigations_status", "investigations"),
        ("ix_investigations_owner_id", "investigations"),
    ):
        op.drop_index(name, table_name=table)
    op.drop_table("investigation_events")
    op.drop_table("investigation_evidence")
    op.drop_table("investigation_findings")
    op.drop_table("investigation_iocs")
    op.drop_table("investigations")
