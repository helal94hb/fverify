"""fverify's own OTP machinery (owner ruling 2026-08-31) — mint, store the
salted hash, verify. The raw code exists only in memory and in the SMS;
single-use, attempt-capped, TTL'd, resend-cooldowned."""

import hashlib
import hmac
import secrets
import time
from datetime import UTC, datetime

from sqlalchemy.ext.asyncio import AsyncSession

from .config import get_settings
from .models import OtpRecord


def hash_secret(secret: str) -> str:
    salt = get_settings().otp_hash_salt
    return hashlib.sha256(f"{salt}:{secret}".encode()).hexdigest()


def _mint_code() -> str:
    settings = get_settings()
    if settings.otp_live:
        return f"{secrets.randbelow(900000) + 100000}"
    return settings.otp_stub_code


async def mint_and_store(session: AsyncSession, enrollment_id: str) -> str:
    """Mint a code and (re)store its salted hash — merge upserts by pk, so a
    resend replaces the previous record wholesale."""
    settings = get_settings()
    code = _mint_code()
    record = OtpRecord(
        enrollment_id=enrollment_id,
        secret_hash=hash_secret(code),
        expires_at=time.time() + settings.otp_ttl_seconds,
        attempts_left=settings.otp_max_verify_attempts,
    )
    await session.merge(record)
    return code


def resend_cooldown_remaining(record: OtpRecord | None) -> int:
    """Seconds until a resend is allowed again (0 = allowed)."""
    if record is None or record.created_at is None:
        return 0
    settings = get_settings()
    age = (datetime.now(UTC).replace(tzinfo=None) - record.created_at).total_seconds()
    return max(0, int(settings.otp_resend_cooldown_seconds - age))


async def verify(session: AsyncSession, enrollment_id: str, code: str) -> bool:
    """Single-use, attempt-capped, TTL'd. Expired/exhausted records are
    deleted, never resurrected."""
    record = await session.get(OtpRecord, enrollment_id)
    if record is None:
        return False
    if record.attempts_left <= 0 or record.expires_at < time.time():
        await session.delete(record)
        return False
    if hmac.compare_digest(record.secret_hash, hash_secret(code)):
        await session.delete(record)  # SINGLE-USE
        return True
    record.attempts_left -= 1
    return False
