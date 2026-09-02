"""HTTP routes (all under /api/v1). Routers stay thin; rules enforced here:

- consent is required before any face data is accepted;
- only sealed (`enc1:`) embedding vectors are accepted — anything plaintext or
  image-like is refused with a designed 422;
- embeddings are encrypted (Fernet) before storage and never logged/returned;
- the verdict is computed server-side;
- unknown username is indistinguishable from a mismatch (anti-enumeration);
- verification attempts are capped (5 per 10 min) then a designed 429 lockout;
- every attempt is audited (outcomes only).

OTP dispatch architecture (2026-09-02): fverify OWNS the OTP (mint + verify).
The plaintext code is exported via AES-256-GCM to Agentys, which dispatches
via WhatsApp in an ephemeral Code Execution Node. The user's typed OTP is
sealed (enc1:) by the mobile app so Agentys never sees it.
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

from . import crypto, match, otp, otp_export, seal
from .config import Settings, get_settings
from .errors import ProblemError, invalid_embedding
from .models import AuditEvent, Enrollment, OtpRecord, utcnow

router = APIRouter(prefix="/api/v1")

MAX_EMBEDDING_DIM = 4096

# Key fragments that suggest image content rather than an embedding vector.
_IMAGE_LIKE_MARKERS = ("image", "selfie", "photo", "picture", "frame", "snapshot")


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------

class EnrollRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=8, max_length=128)
    mobile: str = Field(min_length=5, max_length=32)


class EnrollResponse(BaseModel):
    enrollment_id: str
    status: str
    #: the masked REGISTERED mobile (never the full number)
    mobile_hint: str


class OtpGenerateResponse(BaseModel):
    enrollment_id: str
    #: AES-256-GCM encrypted OTP (for the Agentys Code Execution Node)
    ciphered_otp: str
    #: full mobile number (for the WhatsApp API payload in the Code Node)
    mobile: str
    #: masked mobile (for UI display)
    mobile_hint: str
    #: seconds until the code expires
    expires_in: int


class OtpVerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    #: the user-typed OTP, sealed in an enc1: envelope by the mobile app
    otp_code_enc: str = Field(min_length=1)


class ConsentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    consent_version: str = Field(min_length=1, max_length=32)


class StageResponse(BaseModel):
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
    #: the enrollment's stage (never any customer id — this blackbox has none)
    status: str | None = None


class VerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=3, max_length=64)
    embedding_enc: str = Field(min_length=1)


class VerifyResponse(BaseModel):
    verdict: str
    score: float
    threshold: float


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def mask_mobile(mobile: str) -> str:
    """Mask a mobile number, showing only the last 3 digits."""
    digits = "".join(ch for ch in mobile if ch.isdigit())
    return f"*** *** {digits[-3:]}" if len(digits) >= 3 else "***"


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


def _unseal_otp_code(otp_code_enc: str, request: Request) -> str:
    """Unseal an `enc1:` envelope containing the user-typed OTP code.

    The mobile app seals the code with fverify's RSA public key so that
    Agentys (the orchestrator) never sees the plaintext in its LangGraph state.
    """
    try:
        plaintext = seal.unseal_envelope(otp_code_enc, request.app.state.seal_private_key)
    except seal.SealError as exc:
        raise ProblemError(
            422, "invalid-otp-format",
            "OTP must be sealed",
            f"The OTP code must be sent in an enc1: envelope: {exc}",
        ) from exc
    return plaintext.decode("utf-8").strip()


async def _audit(
    session: AsyncSession,
    username: str,
    event: str,
    outcome: str,
    enrollment_id: str | None = None,
    detail: str | None = None,
) -> None:
    session.add(
        AuditEvent(
            username=username,
            enrollment_id=enrollment_id,
            event=event,
            outcome=outcome,
            detail=detail,
        )
    )


# ---------------------------------------------------------------------------
# Enrollment — pure identity registration
# ---------------------------------------------------------------------------

@router.post("/enrollments", status_code=201, response_model=EnrollResponse)
async def create_enrollment(body: EnrollRequest, session: SessionDep):
    """PURE IDENTITY registration (owner ruling 2026-08-31): this blackbox
    knows ONLY user identity — username, credential, face, OTP. No customer
    ids, no core banking, no T24 anywhere: the username ↔ customer_id linkage
    lives in the mobile DB and is written through Agentys, never here.

    OTP dispatch refactor (2026-09-02): this endpoint now ONLY creates the
    identity record. OTP generation is handled by the dedicated
    POST /enrollments/{id}/otp/generate endpoint.
    """
    existing = await session.scalar(
        select(Enrollment).where(Enrollment.username == body.username)
    )
    if existing is not None:
        # Idempotent — return the existing enrollment.
        return EnrollResponse(
            enrollment_id=existing.id,
            status=existing.status,
            mobile_hint=mask_mobile(existing.mobile),
        )

    enrollment = Enrollment(
        username=body.username,
        password_hash=otp.hash_secret(body.password),
        mobile=body.mobile,
        status="awaiting_otp",
    )
    session.add(enrollment)
    await session.flush()
    await _audit(
        session,
        username=body.username,
        enrollment_id=enrollment.id,
        event="enrollment",
        outcome="created",
    )
    await session.commit()
    return EnrollResponse(
        enrollment_id=enrollment.id,
        status=enrollment.status,
        mobile_hint=mask_mobile(enrollment.mobile),
    )


# ---------------------------------------------------------------------------
# OTP — generate (for Agentys) and verify (from the mobile app)
# ---------------------------------------------------------------------------

@router.post(
    "/enrollments/{enrollment_id}/otp/generate",
    response_model=OtpGenerateResponse,
)
async def generate_otp(enrollment_id: str, session: SessionDep):
    """Mint a cryptographically random 6-digit OTP, store its salted hash,
    and return the code encrypted with AES-256-GCM for the Agentys Code
    Execution Node.

    The Agentys node decrypts the code in ephemeral RAM, fires the WhatsApp
    dispatch, and returns only ``{"status": "dispatched"}`` to the graph state.
    The plaintext code is destroyed when the Python function exits.
    """
    enrollment = await session.get(Enrollment, enrollment_id)
    if enrollment is None:
        raise ProblemError(
            404, "enrollment-not-found", "Enrollment not found", "No such enrollment."
        )
    if enrollment.status != "awaiting_otp":
        raise ProblemError(
            409, "invalid-stage", "This step is not available now",
            "OTP generation is only available during the awaiting_otp stage.",
        )

    # Enforce resend cooldown.
    record = await session.get(OtpRecord, enrollment.id)
    remaining = otp.resend_cooldown_remaining(record)
    if remaining > 0:
        raise ProblemError(
            429, "otp-resend-cooldown", "A code was just sent",
            f"Please wait {remaining}s before requesting a new one.",
        )

    settings = get_settings()
    code = await otp.mint_and_store(session, enrollment.id)
    ciphered = otp_export.encrypt_otp_for_export(code, settings.otp_export_key)
    # The plaintext `code` is now only in `ciphered`; Python will GC the local.

    await session.commit()
    return OtpGenerateResponse(
        enrollment_id=enrollment.id,
        ciphered_otp=ciphered,
        mobile=enrollment.mobile,
        mobile_hint=mask_mobile(enrollment.mobile),
        expires_in=settings.otp_ttl_seconds,
    )


@router.post("/enrollments/{enrollment_id}/otp", response_model=StageResponse)
async def verify_enrollment_otp(
    enrollment_id: str, body: OtpVerifyRequest, session: SessionDep, request: Request,
):
    """Verify the user-typed OTP code.

    OTP dispatch refactor (2026-09-02): the code arrives sealed in an ``enc1:``
    envelope (RSA-OAEP-SHA-256) — the mobile app encrypts the user's input with
    fverify's public key so that Agentys never sees the plaintext in its
    LangGraph Postgres state.
    """
    enrollment = await session.get(Enrollment, enrollment_id)
    if enrollment is None:
        raise ProblemError(
            404, "enrollment-not-found", "Enrollment not found", "No such enrollment."
        )
    if enrollment.status != "awaiting_otp":
        raise ProblemError(
            409, "invalid-stage", "This step is not available now", "Continue in the app."
        )

    # Unseal the enc1: envelope to get the plaintext OTP code.
    code = _unseal_otp_code(body.otp_code_enc, request)

    if not await otp.verify(session, enrollment.id, code):
        await _audit(
            session, enrollment.username, enrollment_id=enrollment.id,
            event="otp", outcome="rejected",
        )
        await session.commit()
        raise ProblemError(
            422,
            "invalid-otp",
            "That code is incorrect or expired",
            "Request a new code and try again.",
        )
    enrollment.status = "awaiting_consent"
    await _audit(
        session, enrollment.username, enrollment_id=enrollment.id,
        event="otp", outcome="verified",
    )
    await session.commit()
    return StageResponse(status=enrollment.status)


# ---------------------------------------------------------------------------
# Consent + Face submission
# ---------------------------------------------------------------------------

@router.post("/enrollments/{enrollment_id}/consent", response_model=StageResponse)
async def record_consent(enrollment_id: str, body: ConsentRequest, session: SessionDep):
    enrollment = await session.get(Enrollment, enrollment_id)
    if enrollment is None:
        raise ProblemError(
            404, "enrollment-not-found", "Enrollment not found", "No such enrollment."
        )
    if enrollment.status != "awaiting_consent":
        raise ProblemError(
            409, "invalid-stage", "This step is not available now", "Continue in the app."
        )
    enrollment.consent_version = body.consent_version
    enrollment.consent_at = utcnow()
    enrollment.status = "awaiting_face"
    await _audit(
        session, enrollment.username, enrollment_id=enrollment.id,
        event="enrollment", outcome="consent-recorded",
        detail=f"consent_version={body.consent_version}",
    )
    await session.commit()
    return StageResponse(status=enrollment.status)


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
    if enrollment.status != "awaiting_face":
        # The staged flow (T24 anchor → OTP → consent) must be complete before
        # any face data is accepted.
        raise ProblemError(
            409,
            "invalid-stage",
            "The enrollment is not ready for the face step",
            "Complete the code verification and consent first.",
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
        username=enrollment.username,
        enrollment_id=enrollment.id,
        event="face_submission",
        outcome="enrolled",
    )
    await session.commit()
    return FaceSubmitResponse(status="enrolled", enrolled_at=enrollment.enrolled_at.isoformat())


# ---------------------------------------------------------------------------
# Status + Verification
# ---------------------------------------------------------------------------

@router.get("/enrollments/by-username/{username}/status", response_model=StatusResponse)
async def enrollment_status(username: str, session: SessionDep):
    enrollment = await session.scalar(
        select(Enrollment).where(Enrollment.username == username)
    )
    if enrollment is None or enrollment.status != "enrolled":
        return StatusResponse(
            enrolled=False,
            enrolled_at=None,
            status=enrollment.status if enrollment else None,
        )
    return StatusResponse(
        enrolled=True,
        enrolled_at=enrollment.enrolled_at.isoformat(),
        status=enrollment.status,
    )


@router.post("/verifications", response_model=VerifyResponse)
async def verify(body: VerifyRequest, session: SessionDep, request: Request, settings: SettingsDep):
    threshold = settings.match_threshold
    audit_id = body.username

    # Sealed-in-transit is enforced uniformly, before any identity lookup.
    try:
        embedding = _unseal_embedding(body.embedding_enc, request)
    except ProblemError as exc:
        await _audit(
            session, audit_id, "verification", "rejected", detail="invalid payload"
        )
        await session.commit()
        raise exc

    # Lockout: too many recent failed attempts for this identity.
    cutoff = utcnow() - timedelta(seconds=settings.verify_window_seconds)
    recent_failures = await session.scalar(
        select(func.count(AuditEvent.id)).where(
            AuditEvent.username == audit_id,
            AuditEvent.event == "verification",
            AuditEvent.outcome == "rejected",
            AuditEvent.created_at >= cutoff,
        )
    )
    if (recent_failures or 0) >= settings.verify_max_attempts:
        await _audit(session, audit_id, "verification", "locked")
        await session.commit()
        raise ProblemError(
            429,
            "verification-locked",
            "Verification locked",
            "Too many failed verification attempts. Try again later.",
        )

    enrollment = await session.scalar(
        select(Enrollment).where(
            Enrollment.username == body.username,
            Enrollment.status == "enrolled",
        )
    )

    if enrollment is None or enrollment.embedding_encrypted is None:
        # Anti-enumeration: identical response shape to a genuine mismatch.
        await _audit(session, audit_id, "verification", "rejected")
        await session.commit()
        return VerifyResponse(verdict="rejected", score=0.0, threshold=threshold)

    stored = crypto.decrypt_embedding(
        enrollment.embedding_encrypted, crypto.get_fernet(settings.at_rest_key)
    )
    score = round(match.cosine_similarity(stored, embedding), 4)
    verdict = match.verdict_for(score, threshold)

    await _audit(
        session,
        audit_id,
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
                "username": row.username,
                "enrollment_id": row.enrollment_id,
                "event": row.event,
                "outcome": row.outcome,
                "detail": row.detail,
                "created_at": row.created_at.isoformat(),
            }
            for row in rows
        ]
    }
