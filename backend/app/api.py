"""HTTP routes (all under /api/v1). Routers stay thin; rules enforced here:

- consent is required before any face data is accepted;
- only sealed (`enc1:`/`enc2:`) embedding vectors are accepted — anything plaintext or
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
import os
import time
from datetime import timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from . import crypto, match, otp, otp_export, passwords, seal
from .config import Settings, get_settings
from .errors import ProblemError, invalid_embedding
from .models import AuditEvent, Enrollment, FaceTemplate, OtpRecord, VerifyChallenge, utcnow

router = APIRouter(prefix="/api/v1")

MAX_EMBEDDING_DIM = 4096

# Key fragments that suggest image content rather than an embedding vector.
_IMAGE_LIKE_MARKERS = ("image", "selfie", "photo", "picture", "frame", "snapshot")


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------

class EnrollRequest(BaseModel):
    """Registration intake. The CREDENTIAL arrives SEALED, never in the clear.

    The orchestrator (Agentys) forwards this envelope unopened and cannot read
    it: only fverify holds the fv-dev1 private half. That keeps the credential
    pair — username AND password — out of the engine's run state, which is
    persisted and browsable, exactly as the OTP and the face embedding already
    are.

    `mobile` stays in the clear on purpose: it is identity data, which the
    orchestrator legitimately handles. Authentication material is what never
    crosses it.
    """

    model_config = ConfigDict(extra="forbid")

    #: enc1: envelope sealed to fv-dev1, containing {"username": ..., "password": ...}
    credential_enc: str = Field(min_length=8, max_length=4096)
    mobile: str = Field(min_length=5, max_length=32)


class _Credential(BaseModel):
    """The unsealed pair. Validated exactly as the plaintext fields were, so
    the rules did not move when the transport did."""

    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=8, max_length=128)


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
    #: (enc1 is right here: a six-digit code has no need of a wrapped key)
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


class ChallengeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=3, max_length=64)


class ChallengeResponse(BaseModel):
    nonce: str
    expires_in: int


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


async def _active_template(session, enrollment: Enrollment) -> bytes | None:
    """The one template that may be matched against — or None.

    ONE definition, used by both verification and the revoke path, so the two
    can never disagree about which face is live. A revoked template returns
    None here, which is what makes revocation mean anything.

    Falls back to `Enrollment.embedding_encrypted` for rows written before
    templates had a table of their own. Those legacy rows have no revocation
    history, which is a limitation of when they were written, not a licence to
    treat them as unrevocable — `revoke_face` migrates one into the table
    before revoking it.
    """
    row = await session.scalar(
        select(FaceTemplate).where(
            FaceTemplate.enrollment_id == enrollment.id,
            FaceTemplate.revoked_at.is_(None),
        )
    )
    if row is not None:
        return row.embedding_encrypted
    return enrollment.embedding_encrypted


def _unseal_credential(credential_enc: str, request: Request) -> "_Credential":
    """Unseal an `enc1:` credential envelope into a validated username/password.

    Fail-closed in both directions: a payload that is not sealed is refused
    (so a caller cannot fall back to plaintext), and a sealed payload whose
    contents do not validate is refused too.
    """
    try:
        plaintext = seal.unseal_envelope(credential_enc, request.app.state.seal_private_key)
    except seal.SealError as exc:
        raise ProblemError(
            422, "invalid-credential-format",
            "Credential must be sealed",
            f"The credential must be sent in an enc1: envelope: {exc}",
        ) from exc

    try:
        payload = json.loads(plaintext)
    except json.JSONDecodeError as exc:
        raise ProblemError(
            422, "invalid-credential-format",
            "Credential must be sealed",
            "The sealed credential is not valid JSON.",
        ) from exc

    try:
        return _Credential.model_validate(payload)
    except ValidationError as exc:
        raise ProblemError(
            422, "invalid-credential",
            "Credential rejected",
            "The sealed credential does not meet the username/password rules.",
        ) from exc


def _unseal_embedding(embedding_enc: str, request: Request) -> list[float]:
    """Unseal a sealed payload into a validated float vector. Fail-closed.

    Accepts enc1: or enc2:. In practice a real embedding only fits enc2 — a
    512-dim vector is ~5.3KB against enc1's 190-byte ceiling — but the check
    here is on the CONTENT, not the envelope flavour, so a small vector sealed
    either way is equally valid.
    """
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
async def create_enrollment(body: EnrollRequest, session: SessionDep, request: Request):
    """PURE IDENTITY registration (owner ruling 2026-08-31): this blackbox
    knows ONLY user identity — username, credential, face, OTP. No customer
    ids, no core banking, no T24 anywhere: the username ↔ customer_id linkage
    lives in the mobile DB and is written through Agentys, never here.

    OTP dispatch refactor (2026-09-02): this endpoint now ONLY creates the
    identity record. OTP generation is handled by the dedicated
    POST /enrollments/{id}/otp/generate endpoint.
    """
    #: the credential is opened HERE and nowhere else — the orchestrator that
    #: carried it cannot read it, and it is never persisted in the clear.
    cred = _unseal_credential(body.credential_enc, request)

    existing = await session.scalar(
        select(Enrollment).where(Enrollment.username == cred.username)
    )
    if existing is not None:
        # Idempotent — return the existing enrollment.
        return EnrollResponse(
            enrollment_id=existing.id,
            status=existing.status,
            mobile_hint=mask_mobile(existing.mobile),
        )

    enrollment = Enrollment(
        username=cred.username,
        password_hash=passwords.hash_password(cred.password),
        mobile=body.mobile,
        status="awaiting_otp",
    )
    session.add(enrollment)
    await session.flush()
    await _audit(
        session,
        username=cred.username,
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
    sealed_at_rest = crypto.encrypt_embedding(
        embedding, crypto.get_fernet(settings.at_rest_key)
    )
    #: A NEW ROW, never an overwrite. If this enrolment has a revoked template
    #: from an earlier binding, that history survives beside the new one and
    #: the chain records which replaced which.
    template = FaceTemplate(
        enrollment_id=enrollment.id, embedding_encrypted=sealed_at_rest
    )
    session.add(template)
    prior = await session.scalars(
        select(FaceTemplate).where(
            FaceTemplate.enrollment_id == enrollment.id,
            FaceTemplate.revoked_at.is_not(None),
            FaceTemplate.superseded_by.is_(None),
        )
    )
    for old in prior:
        old.superseded_by = template.id
    #: kept in step for legacy readers; the template table is the authority
    enrollment.embedding_encrypted = sealed_at_rest
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

class RevokeFaceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    #: Why, in the record forever. Free text is refused: a reason nobody can
    #: aggregate is a reason nobody reads.
    reason: str = Field(pattern="^(lost_device|compromised|customer_request|"
                                "quality|staff_action|superseded)$")


@router.post("/enrollments/{enrollment_id}/face/revoke", response_model=StageResponse)
async def revoke_face(
    enrollment_id: str, body: RevokeFaceRequest, session: SessionDep
):
    """Revoke the active template. The face stops verifying immediately.

    AUTHORISATION LIVES UPSTREAM, AND THAT IS A DELIBERATE BOUNDARY, NOT A GAP.
    This service is reachable only from the orchestrator on a private network
    (owner ruling: fverify is never called by the BFF or a client). The decision
    that a revocation is WARRANTED -- step-up proofing, staff authority, a
    fraud hold -- is made before anyone gets here. If this service is ever
    exposed publicly, this endpoint is the first thing that needs a caller
    identity, because it can silently disable a customer's biometric.

    Revocation NEVER deletes. The row stays with its reason and timestamp,
    because a revoked template is the evidence that a re-binding happened.
    """
    enrollment = await session.get(Enrollment, enrollment_id)
    if enrollment is None:
        raise ProblemError(404, "enrollment-not-found", "Enrollment not found",
                           "No such enrollment.")

    active = await session.scalar(
        select(FaceTemplate).where(
            FaceTemplate.enrollment_id == enrollment.id,
            FaceTemplate.revoked_at.is_(None),
        )
    )

    #: A legacy row carries its template on the enrolment and has no table
    #: entry. Migrate it in FIRST so it can be revoked like any other -- the
    #: alternative is a class of template that cannot be revoked at all, which
    #: is precisely the property this endpoint exists to remove.
    if active is None and enrollment.embedding_encrypted is not None:
        active = FaceTemplate(
            enrollment_id=enrollment.id,
            embedding_encrypted=enrollment.embedding_encrypted,
        )
        session.add(active)
        await session.flush()

    if active is None:
        #: Idempotent: nothing live to revoke is the state the caller wanted.
        await _audit(session, enrollment.username, enrollment_id=enrollment.id,
                     event="face_revocation", outcome="noop")
        await session.commit()
        return StageResponse(status=enrollment.status)

    active.revoked_at = utcnow()
    active.revoked_reason = body.reason

    #: The enrolment returns to awaiting_face, which is what lets a NEW template
    #: be submitted through the ordinary stage gate. It does NOT go back to
    #: awaiting_otp: the customer already proved the phone and consented, and
    #: re-asking would be theatre rather than assurance.
    enrollment.status = "awaiting_face"
    enrollment.enrolled_at = None
    enrollment.embedding_encrypted = None      # legacy mirror must not linger

    await _audit(session, enrollment.username, enrollment_id=enrollment.id,
                 event="face_revocation", outcome="revoked",
                 detail=f"reason={body.reason}")
    await session.commit()
    return StageResponse(status=enrollment.status)


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


@router.post("/verifications/challenge", response_model=ChallengeResponse)
async def verification_challenge(
    body: ChallengeRequest, session: SessionDep, settings: SettingsDep
):
    """Mint a single-use nonce for one verification.

    ANTI-ENUMERATION: a nonce is issued for ANY username, enrolled or not. If
    this 404'd on unknown users it would become a free directory of who banks
    here -- and the verification itself already refuses unknown identities with
    a response shaped identically to a genuine mismatch.
    """
    nonce = seal.b64url_encode(os.urandom(24))
    session.add(
        VerifyChallenge(
            nonce=nonce,
            username=body.username,
            expires_at=time.time() + settings.verify_challenge_ttl_seconds,
        )
    )
    await session.commit()
    return ChallengeResponse(
        nonce=nonce, expires_in=settings.verify_challenge_ttl_seconds
    )


@router.post("/verifications", response_model=VerifyResponse)
async def verify(body: VerifyRequest, session: SessionDep, request: Request, settings: SettingsDep):
    threshold = settings.match_threshold
    audit_id = body.username

    #: FRESHNESS FIRST. Before the payload is even opened, the envelope must
    #: name a challenge that (a) exists, (b) was issued to THIS username, (c)
    #: has not expired and (d) has not been used. Consumption happens here, so
    #: a replay of a captured envelope loses at (d) regardless of how valid the
    #: biometric inside it is.
    #:
    #: The nonce is also inside the AEAD tag, so it cannot be swapped for a
    #: fresh one -- readable, not forgeable.
    claimed = seal.envelope_nonce(body.embedding_enc)
    if not claimed:
        await _audit(session, audit_id, "verification", "rejected",
                     detail="no challenge")
        await session.commit()
        raise ProblemError(
            400, "challenge-required", "Verification challenge required",
            "Request a challenge and seal it into the payload.",
        )

    challenge = await session.get(VerifyChallenge, claimed)
    now = time.time()
    bad = (
        challenge is None
        or challenge.username != body.username
        or challenge.consumed_at is not None
        or challenge.expires_at < now
    )
    if bad:
        #: One message for four causes, deliberately. Distinguishing "already
        #: used" from "never existed" tells a replayer whether their captured
        #: envelope was ever genuine.
        await _audit(session, audit_id, "verification", "rejected",
                     detail="challenge invalid")
        await session.commit()
        raise ProblemError(
            400, "challenge-invalid", "Verification challenge is not usable",
            "Request a new challenge and try again.",
        )

    challenge.consumed_at = utcnow()
    await session.commit()

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

    active = await _active_template(session, enrollment) if enrollment else None
    if enrollment is None or active is None:
        #: Anti-enumeration: identical response shape to a genuine mismatch.
        #: A REVOKED template lands here too, and deliberately looks the same --
        #: telling a caller "that face was revoked" would confirm the identity
        #: exists and volunteer its history.
        await _audit(session, audit_id, "verification", "rejected")
        await session.commit()
        return VerifyResponse(verdict="rejected", score=0.0, threshold=threshold)

    stored = crypto.decrypt_embedding(
        active, crypto.get_fernet(settings.at_rest_key)
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
