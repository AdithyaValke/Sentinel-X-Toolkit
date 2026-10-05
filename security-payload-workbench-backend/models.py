"""Database models for account and server-side session authentication."""

from datetime import datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(254), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    display_name: Mapped[str] = mapped_column(String(80), nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False, default="user", server_default="user")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, server_default="true")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())
    sessions: Mapped[list["AuthSession"]] = relationship(back_populates="user", cascade="all, delete-orphan")
    investigations: Mapped[list["Investigation"]] = relationship(back_populates="owner", cascade="all, delete-orphan")


class AuthSession(Base):
    __tablename__ = "sessions"
    __table_args__ = (
        Index("ix_sessions_user_active", "user_id", "expires_at", "revoked_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    session_token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    user: Mapped[User] = relationship(back_populates="sessions")


class Investigation(Base):
    __tablename__ = "investigations"
    __table_args__ = (
        CheckConstraint("status IN ('open', 'investigating', 'resolved', 'closed')", name="ck_investigations_status"),
        CheckConstraint("length(trim(title)) > 0", name="ck_investigations_title_nonempty"),
        CheckConstraint("description IS NULL OR length(description) <= 10000", name="ck_investigations_description_length"),
        Index("ix_investigations_owner_id", "owner_id"),
        Index("ix_investigations_status", "status"),
        Index("ix_investigations_updated_at", "updated_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(String(10000))
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="open", server_default="open")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    owner: Mapped[User] = relationship(back_populates="investigations")
    iocs: Mapped[list["InvestigationIOC"]] = relationship(back_populates="investigation", cascade="all, delete-orphan")
    findings: Mapped[list["InvestigationFinding"]] = relationship(back_populates="investigation", cascade="all, delete-orphan")
    evidence: Mapped[list["InvestigationEvidence"]] = relationship(back_populates="investigation", cascade="all, delete-orphan", foreign_keys="InvestigationEvidence.investigation_id")
    events: Mapped[list["InvestigationEvent"]] = relationship(back_populates="investigation", cascade="all, delete-orphan")


class InvestigationIOC(Base):
    __tablename__ = "investigation_iocs"
    __table_args__ = (
        CheckConstraint("confidence IS NULL OR confidence BETWEEN 0 AND 100", name="ck_investigation_iocs_confidence_range"),
        CheckConstraint("length(value) > 0", name="ck_investigation_iocs_value_nonempty"),
        Index("ix_investigation_iocs_investigation_id", "investigation_id"),
        Index("ix_investigation_iocs_ioc_type", "ioc_type"),
        Index("ix_investigation_iocs_normalized_value", "normalized_value"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    investigation_id: Mapped[int] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False)
    ioc_type: Mapped[str] = mapped_column(String(32), nullable=False)
    value: Mapped[str] = mapped_column(String(2048), nullable=False)
    normalized_value: Mapped[str | None] = mapped_column(String(2048))
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="manual", server_default="manual")
    confidence: Mapped[int | None] = mapped_column(Integer)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    investigation: Mapped[Investigation] = relationship(back_populates="iocs")


class InvestigationFinding(Base):
    __tablename__ = "investigation_findings"
    __table_args__ = (
        CheckConstraint("severity IN ('info', 'low', 'medium', 'high', 'critical')", name="ck_investigation_findings_severity"),
        CheckConstraint("status IN ('open', 'confirmed', 'dismissed', 'resolved')", name="ck_investigation_findings_status"),
        CheckConstraint("length(trim(title)) > 0", name="ck_investigation_findings_title_nonempty"),
        UniqueConstraint("id", "investigation_id", name="uq_investigation_findings_id_investigation"),
        Index("ix_investigation_findings_investigation_id", "investigation_id"),
        Index("ix_investigation_findings_severity", "severity"),
        Index("ix_investigation_findings_status", "status"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    investigation_id: Mapped[int] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(String(10000))
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="info", server_default="info")
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="open", server_default="open")
    source: Mapped[str | None] = mapped_column(String(32))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())

    investigation: Mapped[Investigation] = relationship(back_populates="findings")
    evidence: Mapped[list["InvestigationEvidence"]] = relationship(
        back_populates="finding", cascade="all, delete-orphan", foreign_keys="InvestigationEvidence.finding_id"
    )


class InvestigationEvidence(Base):
    __tablename__ = "investigation_evidence"
    __table_args__ = (
        ForeignKeyConstraint(
            ["finding_id", "investigation_id"],
            ["investigation_findings.id", "investigation_findings.investigation_id"],
            name="fk_investigation_evidence_finding_investigation",
            ondelete="CASCADE",
        ),
        Index("ix_investigation_evidence_investigation_id", "investigation_id"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    investigation_id: Mapped[int] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False)
    finding_id: Mapped[int | None] = mapped_column(Integer)
    evidence_type: Mapped[str] = mapped_column(String(32), nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str | None] = mapped_column(String(32))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    investigation: Mapped[Investigation] = relationship(back_populates="evidence", foreign_keys=[investigation_id])
    finding: Mapped[InvestigationFinding | None] = relationship(back_populates="evidence", foreign_keys=[finding_id])


class InvestigationEvent(Base):
    __tablename__ = "investigation_events"
    __table_args__ = (
        Index("ix_investigation_events_investigation_id", "investigation_id"),
        Index("ix_investigation_events_created_at", "created_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    investigation_id: Mapped[int] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False)
    event_type: Mapped[str] = mapped_column(String(40), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    investigation: Mapped[Investigation] = relationship(back_populates="events")
