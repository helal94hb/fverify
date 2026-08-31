"""Persistence models. This service has its OWN database — never the banking one.

Embeddings are stored only as Fernet ciphertext (LargeBinary). Images are
never uploaded and never stored anywhere.
"""

import uuid
from datetime import UTC, datetime

from sqlalchemy import DateTime, Index, LargeBinary, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def utcnow() -> datetime:
    """Naive UTC timestamp (SQLite-friendly)."""
    return datetime.now(UTC).replace(tzinfo=None)


class Base(DeclarativeBase):
    pass


class Enrollment(Base):
    __tablename__ = "enrollments"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    national_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    #: the T24-anchored identity (owner ruling 2026-08-31) — the customer id
    #: from the core and the REGISTERED mobile (never user-asserted).
    customer_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    mobile: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(16), default="awaiting_otp")

    # Consent is REQUIRED before any face data is accepted — recorded at its
    # own step AFTER the OTP proves the phone (nullable until then).
    consent_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    consent_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    # Fernet ciphertext of the JSON float vector. Never plaintext.
    embedding_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    enrolled_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class AuditEvent(Base):
    """Outcomes only. Never embeddings, never images, never secrets."""

    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    national_id: Mapped[str] = mapped_column(String(64))
    enrollment_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    event: Mapped[str] = mapped_column(String(32))  # enrollment | face | verification | otp
    # created | enrolled | verified | rejected | locked
    outcome: Mapped[str] = mapped_column(String(32))
    detail: Mapped[str | None] = mapped_column(String(200), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


Index("ix_audit_national_time", AuditEvent.national_id, AuditEvent.created_at)


class OtpRecord(Base):
    """fverify's own OTP record (owner ruling 2026-08-31) — salted hash only,
    TTL'd, single-use, attempt-capped. The raw code is never stored."""

    __tablename__ = "otp_records"

    enrollment_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    secret_hash: Mapped[str] = mapped_column(String(128))
    expires_at: Mapped[float] = mapped_column()
    attempts_left: Mapped[int] = mapped_column(default=5)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
