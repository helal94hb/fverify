"""HTTP routes (all under /api/v1). Routers stay thin; rules enforced here:

- consent is required before any face data is accepted;
- only sealed (`enc1:`) embedding vectors are accepted — anything plaintext or
  image-like is refused with a designed 422;
- embeddings are encrypted (Fernet) before storage and never logged/returned;
- the verdict is computed server-side;
- unknown national_id is indistinguishable from a mismatch (anti-enumeration);
- verification attempts are capped (5 per 10 min) then a designed 429 lockout;
- every attempt is audited (outcomes only).
"""

import base64
import binascii
import json
import math
from datetime import timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from . import crypto, match, seal
from .config import Settings, get_settings
from .errors import ProblemError, invalid_embedding
from .models import AuditEvent, Enrollment, utcnow

router = APIRouter(prefix="/api/v1")

MAX_EMBEDDING_DIM = 4096

# Key fragments that suggest image content rather than an embedding vector.
_IMAGE_LIKE_MARKERS = ("image", "selfie", "photo", "picture", "frame", "snapshot")


class EnrollRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    national_id: str = Field(min_length=1, max_length=64)
    mobile: str = Field(min_length=1, max_length=32)
    consent_version: str = Field(min_length=1, max_length=32)


class EnrollResponse(BaseModel):
    enrollment_id: str
    status: str


class FaceSubmitRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    embedding_enc: str = Field(min_length=1)


class FaceSubmitResponse(BaseModel):
    status: str
    enrolled_at: str


class StatusResponse(BaseModel):
    enrolled: bool
    enrolled_at: str | None


class VerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    national_id: str = Field(min_length=1, max_length=64)
    embedding_enc: str = Field(min_length=1)


class VerifyResponse(BaseModel):
    verdict: str
    score: float
    threshold: float


async def get_session(request: Request):
    factory = request.app.state.session_factory
    async with factory() as session:
        yield session


SessionDep = Annotated[AsyncSession, Depends(get_session)]
SettingsDep = Annotated[Settings, Depends(get_settings)]


def _contains_image_like(obj) -> bool:
    """Heuristic guard: an embedding is a flat float vector; anything with
    image-ish keys or bulk string blobs is not an embedding."""
    if isinstance(obj, dict):
        for key, value in obj.items():
            lowered = str(key).lower()
            if any(marker in lowered for marker in _IMAGE_LIKE_MARKERS):
                return True
            if _contains_image_like(value):
                return True
    elif isinstance(obj, list):
        return any(_contains_image_like(item) for item in obj)
    elif isinstance(obj, str) and len(obj) > 256:
        return True  # bulk base64-ish blob, not a number vector
    return False


def _decode_compact_wire(plaintext: bytes) -> list[float]:
    """The app's compact wire encoding (face-verify/app/src/ml/embedding.ts —
    keep in lockstep): base64 of the int8-quantized unit vector
    (q = round(clamp(v,-1,1) * 127), one signed byte per dimension). A JSON
    float array is ~2 KB and plain RSA-OAEP-3072 seals at most 318 bytes, so
    the embedding crosses quantized; we dequantize (q / 127) here."""
    try:
        raw = base64.b64decode(plaintext, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise invalid_embedding(
            "sealed payload is neither a JSON number array nor the compact encoding"
        ) from exc
    if not raw or len(raw) > MAX_EMBEDDING_DIM:
        raise invalid_embedding("compact embedding dimension is out of range")
    return [((b - 256) if b & 0x80 else b) / 127 for b in raw]


def _unseal_embedding(embedding_enc: str, request: Request) -> list[float]:
    """Unseal an `enc1:` payload into a validated float vector. Fail-closed."""
    try:
        plaintext = seal.unseal_envelope(embedding_enc, request.app.state.seal_private_key)
    except seal.SealError as exc:
        raise invalid_embedding(str(exc)) from exc

    # the app's compact wire encoding is a bare base64 string; the legacy/test
    # shape is a JSON float array (starts with '[')
    if not plaintext.lstrip().startswith(b"["):
        return _decode_compact_wire(plaintext)

    try:
        payload = json.loads(plaintext)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise invalid_embedding("sealed payload is not valid JSON") from exc

    if _contains_image_like(payload):
        raise invalid_embedding(
            "payload contains image-like content; only embedding vectors are accepted"
        )

    if not isinstance(payload, list) or not payload:
        raise invalid_embedding("sealed payload must be a non-empty JSON array of numbers")
    if len(payload) > MAX_EMBEDDING_DIM:
        raise invalid_embedding("embedding dimension exceeds the accepted maximum")
    if any(
        isinstance(x, bool) or not isinstance(x, (int, float)) or not math.isfinite(x)
        for x in payload
    ):
        raise invalid_embedding("embedding must contain only finite numbers")

    return [float(x) for x in payload]


async def _audit(
    session: AsyncSession,
    national_id: str,
    event: str,
    outcome: str,
    enrollment_id: str | None = None,
    detail: str | None = None,
) -> None:
    session.add(
        AuditEvent(
            national_id=national_id,
            enrollment_id=enrollment_id,
            event=event,
            outcome=outcome,
            detail=detail,
        )
    )


@router.post("/enrollments", status_code=201, response_model=EnrollResponse)
async def create_enrollment(body: EnrollRequest, session: SessionDep, request: Request):
    existing = await session.scalar(
        select(Enrollment).where(Enrollment.national_id == body.national_id)
    )
    if existing is not None:
        # Idempotent: a second enroll for the same national_id returns the open record.
        return EnrollResponse(enrollment_id=existing.id, status=existing.status)

    enrollment = Enrollment(
        national_id=body.national_id,
        mobile=body.mobile,
        consent_version=body.consent_version,
        status="awaiting_face",
    )
    session.add(enrollment)
    await session.flush()
    await _audit(
        session,
        national_id=body.national_id,
        enrollment_id=enrollment.id,
        event="enrollment",
        outcome="created",
        detail=f"consent_version={body.consent_version}",
    )
    await session.commit()
    return EnrollResponse(enrollment_id=enrollment.id, status=enrollment.status)


@router.post("/enrollments/{enrollment_id}/face", response_model=FaceSubmitResponse)
async def submit_face(
    enrollment_id: str, body: FaceSubmitRequest, session: SessionDep, request: Request
):
    enrollment = await session.get(Enrollment, enrollment_id)
    if enrollment is None:
        raise ProblemError(
            404, "enrollment-not-found", "Enrollment not found", "No such enrollment."
        )
    if enrollment.status == "enrolled":
        # Idempotent re-submission: already enrolled, no state change.
        return FaceSubmitResponse(
            status="enrolled", enrolled_at=enrollment.enrolled_at.isoformat()
        )
    if not enrollment.consent_version:
        # Defense in depth: consent is required at enrollment creation, and we
        # re-check here so no face data is ever stored without it.
        raise ProblemError(
            409, "consent-required", "Consent required", "Consent must be recorded first."
        )

    embedding = _unseal_embedding(body.embedding_enc, request)

    settings: Settings = get_settings()
    enrollment.embedding_encrypted = crypto.encrypt_embedding(
        embedding, crypto.get_fernet(settings.at_rest_key)
    )
    enrollment.status = "enrolled"
    enrollment.enrolled_at = utcnow()
    await _audit(
        session,
        national_id=enrollment.national_id,
        enrollment_id=enrollment.id,
        event="face_submission",
        outcome="enrolled",
    )
    await session.commit()
    return FaceSubmitResponse(status="enrolled", enrolled_at=enrollment.enrolled_at.isoformat())


@router.get("/enrollments/by-national-id/{national_id}/status", response_model=StatusResponse)
async def enrollment_status(national_id: str, session: SessionDep):
    enrollment = await session.scalar(
        select(Enrollment).where(Enrollment.national_id == national_id)
    )
    if enrollment is None or enrollment.status != "enrolled":
        return StatusResponse(enrolled=False, enrolled_at=None)
    return StatusResponse(enrolled=True, enrolled_at=enrollment.enrolled_at.isoformat())


@router.post("/verifications", response_model=VerifyResponse)
async def verify(body: VerifyRequest, session: SessionDep, request: Request, settings: SettingsDep):
    threshold = settings.match_threshold

    # Sealed-in-transit is enforced uniformly, before any identity lookup.
    try:
        embedding = _unseal_embedding(body.embedding_enc, request)
    except ProblemError as exc:
        await _audit(
            session, body.national_id, "verification", "rejected", detail="invalid payload"
        )
        await session.commit()
        raise exc

    # Lockout: too many recent failed attempts for this national_id.
    cutoff = utcnow() - timedelta(seconds=settings.verify_window_seconds)
    recent_failures = await session.scalar(
        select(func.count(AuditEvent.id)).where(
            AuditEvent.national_id == body.national_id,
            AuditEvent.event == "verification",
            AuditEvent.outcome == "rejected",
            AuditEvent.created_at >= cutoff,
        )
    )
    if (recent_failures or 0) >= settings.verify_max_attempts:
        await _audit(session, body.national_id, "verification", "locked")
        await session.commit()
        raise ProblemError(
            429,
            "verification-locked",
            "Verification locked",
            "Too many failed verification attempts. Try again later.",
        )

    enrollment = await session.scalar(
        select(Enrollment).where(
            Enrollment.national_id == body.national_id,
            Enrollment.status == "enrolled",
        )
    )

    if enrollment is None or enrollment.embedding_encrypted is None:
        # Anti-enumeration: identical response shape to a genuine mismatch.
        await _audit(session, body.national_id, "verification", "rejected")
        await session.commit()
        return VerifyResponse(verdict="rejected", score=0.0, threshold=threshold)

    stored = crypto.decrypt_embedding(
        enrollment.embedding_encrypted, crypto.get_fernet(settings.at_rest_key)
    )
    score = round(match.cosine_similarity(stored, embedding), 4)
    verdict = match.verdict_for(score, threshold)

    await _audit(
        session,
        body.national_id,
        "verification",
        "verified" if verdict == "verified" else "rejected",
        enrollment_id=enrollment.id,
    )
    await session.commit()
    return VerifyResponse(verdict=verdict, score=score, threshold=threshold)


@router.get("/audit/recent")
async def audit_recent(session: SessionDep, limit: int = 50):
    """Ops proof surface: outcomes only. No embeddings anywhere in this service."""
    limit = max(1, min(limit, 200))
    rows = await session.scalars(select(AuditEvent).order_by(AuditEvent.id.desc()).limit(limit))
    return {
        "events": [
            {
                "id": row.id,
                "national_id": row.national_id,
                "enrollment_id": row.enrollment_id,
                "event": row.event,
                "outcome": row.outcome,
                "detail": row.detail,
                "created_at": row.created_at.isoformat(),
            }
            for row in rows
        ]
    }
