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
    #: PURE IDENTITY (owner ruling 2026-08-31): this blackbox knows ONLY user
    #: identity — username, credential, face, OTP. No customer ids, no core
    #: banking, no T24 anywhere in this schema; the username ↔ customer_id
    #: linkage lives in the mobile DB and is written through Agentys.
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(128))
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
    username: Mapped[str] = mapped_column(String(64))
    enrollment_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    event: Mapped[str] = mapped_column(String(32))  # enrollment | face | verification | otp
    # created | enrolled | verified | rejected | locked
    outcome: Mapped[str] = mapped_column(String(32))
    detail: Mapped[str | None] = mapped_column(String(200), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


Index("ix_audit_user_time", AuditEvent.username, AuditEvent.created_at)


class OtpRecord(Base):
    """fverify's own OTP record (owner ruling 2026-08-31) — salted hash only,
    TTL'd, single-use, attempt-capped. The raw code is never stored."""

    __tablename__ = "otp_records"

    enrollment_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    secret_hash: Mapped[str] = mapped_column(String(128))
    expires_at: Mapped[float] = mapped_column()
    attempts_left: Mapped[int] = mapped_column(default=5)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class VerifyChallenge(Base):
    """A single-use, TTL'd nonce that binds one verification to one moment.

    Without this, `/verifications` accepted any sealed embedding at any time:
    one captured envelope replayed forever. The nonce is minted here, folded
    into the envelope's AEAD tag by the client, and CONSUMED on first use --
    so a replay presents a nonce that is already spent.

    Rows are kept after consumption rather than deleted: `consumed_at` is the
    difference between "never issued" and "already used", and collapsing those
    two into a missing row would discard exactly the evidence a replay attempt
    leaves behind.
    """

    __tablename__ = "verify_challenges"

    nonce: Mapped[str] = mapped_column(String(64), primary_key=True)
    username: Mapped[str] = mapped_column(String(64), index=True)
    expires_at: Mapped[float] = mapped_column()
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class FaceTemplate(Base):
    """One biometric template, with a life of its own.

    ISO/IEC 24745 (which 800-63B requires) calls for templates to be RENEWABLE
    and REVOCABLE. Neither was possible while the template lived in a single
    column on the enrolment: a new face overwrote the old one in place, leaving
    no record that a previous face had ever existed, no way to say "that one no
    longer verifies", and nothing to audit.

    At most ONE row per enrolment has `revoked_at IS NULL` — that is the active
    template, and it is the only one verification will match against. Revoked
    rows are KEPT: a revoked template is the evidence that a re-enrolment
    happened, and deleting it would erase the very thing an investigator needs.

    `superseded_by` chains a revocation to the template that replaced it, so a
    replacement is distinguishable from a plain revocation with no successor
    (a lost-device lockout, say).
    """

    __tablename__ = "face_templates"

    id: Mapped[str] = mapped_column(String(36), primary_key=True,
                                    default=lambda: str(uuid.uuid4()))
    enrollment_id: Mapped[str] = mapped_column(String(36), index=True)
    embedding_encrypted: Mapped[bytes] = mapped_column(LargeBinary)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    revoked_reason: Mapped[str | None] = mapped_column(String(64), nullable=True)
    superseded_by: Mapped[str | None] = mapped_column(String(36), nullable=True)
