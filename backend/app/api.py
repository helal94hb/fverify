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
    #: NULLABLE since the stage machine gained `awaiting_activation`: a face
    #: submission no longer ends the enrolment, so at that point there is no
    #: finish time to report. Empty is the honest answer — a timestamp here
    #: would be the moment the CUSTOMER finished wearing the name of the moment
    #: the ENROLMENT did.
    enrolled_at: str | None = None


class StatusResponse(BaseModel):
    enrolled: bool
    enrolled_at: str | None
    #: the enrollment's stage (never any customer id — this blackbox has none)
    status: str | None = None


class CredentialVerifyRequest(BaseModel):
    """SIGN-IN, and it carries exactly what enrolment carried: one sealed
    envelope holding the username and the password.

    NO SEPARATE USERNAME FIELD, deliberately. Enrolment takes the name from
    INSIDE the envelope, so login does too — a username beside the envelope
    would be a second copy of the same fact, and two copies mean a mismatch
    case nobody would have a rule for.
    """

    model_config = ConfigDict(extra="forbid")

    credential_enc: str = Field(min_length=8, max_length=4096)


class CredentialVerifyResponse(BaseModel):
    """The verdict, and NOTHING that varies with why a rejection happened.

    `status` is present ONLY on a verified credential. A rejection that carried
    the identity's stage would answer "does this username exist" and "how far
    did they get" to anyone willing to guess — the same directory the challenge
    endpoint refuses to become. Whoever holds the correct password already knows
    the identity exists; everyone else learns nothing.
    """

    verdict: str
    status: str | None = None
    #: present ONLY on a verified credential, for the same reason `status`
    #: is: it names the identity that was proven, and a rejection proves
    #: nothing about any identity at all.
    user_ref: str | None = None


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


async def _find_duplicate(
    session, embedding: list[float], own_enrollment_id: str, settings: Settings
) -> tuple[str, float] | None:
    """1:N search of the enrolled gallery. Returns (enrollment_id, score) or None.

    THE CASE customer_id CANNOT SEE. A duplicate keyed on customer_id catches
    the same identity enrolling twice; this catches one HUMAN holding two
    different identities, which is the fraud that matters — splitting
    transactions, evading limits, and defeating the single customer view FATF
    Recommendation 10 requires.

    Only ACTIVE templates are searched. A revoked template belongs to a
    retired binding and must not block its owner from enrolling again.

    COST, STATED HONESTLY: this decrypts every active template on every
    enrolment — O(N) with the gallery. Correct and fast enough at this scale,
    and the wrong shape at national scale, where this becomes a vector index
    with a review queue in front of it. The threshold and the review workflow
    are the parts that need a risk owner, not the search.
    """
    if not settings.dedup_enabled:
        return None

    fernet = crypto.get_fernet(settings.at_rest_key)
    rows = await session.scalars(
        select(FaceTemplate).where(
            FaceTemplate.revoked_at.is_(None),
            FaceTemplate.enrollment_id != own_enrollment_id,
        )
    )
    best: tuple[str, float] | None = None
    for row in rows:
        try:
            other = crypto.decrypt_embedding(row.embedding_encrypted, fernet)
        except Exception:          # noqa: BLE001 - a corrupt row must not
            continue               # block enrolment, but must not match either
        if len(other) != len(embedding):
            continue               # different model or dimension: not comparable
        score = match.cosine_similarity(other, embedding)
        if best is None or score > best[1]:
            best = (row.enrollment_id, score)

    if best and best[1] >= settings.dedup_threshold:
        return best
    return None


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


def user_ref(username: str, key: str) -> str:
    """A verdict is about ONE identity; this is what says which one.

    HMAC rather than the username itself because the answer travels back through
    the orchestrator, which persists what it carries and is deliberately never
    told who is signing in. The bank knows the username it asked about, so it
    recomputes this and compares; nothing in between can read it or forge it.
    """
    import hashlib
    import hmac

    return hmac.new(key.encode(), username.strip().lower().encode(), hashlib.sha256).hexdigest()


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

async def _superseded(session: AsyncSession, enrollment: Enrollment) -> bool:
    """Does a NEW enrolment attempt replace this record?

    OWNER RULING 2026-09-11: yes, whenever the record is unfinished. A customer
    who starts again has started again — the attempt behind the old record is
    dead the moment they do, and holding it open is what strands them.

    This REPLACES a thirty-minute idle window. The window was the defect: run
    2915550e found this record at `awaiting_face` fifteen minutes after the
    attempt that left it there, handed it back, and the flow's next node — which
    always generates an OTP — was refused with 409 invalid-stage. The customer
    could neither continue (the stage was wrong) nor restart (the record was too
    recent). It also self-perpetuated, because every attempt that minted a code
    pushed the idle clock forward again.

    TWO cases are still excluded, and they are not timing rules:

    `enrolled` is FINISHED, not in flight. The customer did everything asked of
    them; erasing that because somebody typed the username again would destroy a
    real face binding (owner ruling 2026-09-10: erase the unfinished only).

    A record the BANK HAS PROVISIONED FOR has been enrolled before and sits at
    `awaiting_face` because its binding was REVOKED — someone replacing a lost
    phone, who has already proved their number and consented. Revocation
    deliberately does not send them back to the start.

    THAT TEST USED TO BE "has any template history", and the difference is the
    whole reason this ruling reaches anybody (2026-09-11). A customer waiting on
    an activation that never came HAS submitted a face, so they have template
    history, so the old test protected them from a restart they urgently needed
    — the exact stranding this function exists to prevent, arriving by the one
    route nobody had looked at. `activated_at` distinguishes the two directly
    rather than inferring it: it is set only by the bank's close-out, so it
    means "a profile exists for this identity" and never merely "a face was
    once submitted".
    NOTE, and it is a real gap rather than a settled decision: through the
    current flow that customer meets the SAME trap this ruling fixes, because
    the flow always asks for an OTP next and their record is past that stage.
    Erasing them here would fix the symptom by making them re-prove a phone they
    already proved, which is why it is NOT done on this ruling's authority.

    THE ACCEPTED COST: two devices. If the identity is genuinely mid-journey
    elsewhere, the newer attempt wins and the older one's code stops working.
    That is the ruling — a stranded customer is worse than an invalidated code.
    """
    if enrollment.status == "enrolled":
        return False
    return enrollment.activated_at is None


async def _erase_the_attempt(
    session: AsyncSession,
    enrollment: Enrollment,
    cred: "_Credential",
    mobile: str,
) -> None:
    """Wipe the abandoned attempt and put the record back at the beginning.

    Everything the attempt produced goes: the live code, the consent, the
    credential (they may well choose a different one this time), and the phone
    number they gave it.

    What survives is the AUDIT — this enrolment's history of attempts, and any
    revoked template that predates them. "Erase everything" cannot be allowed to
    mean erasing the evidence that any of it happened; an investigator asking
    "what did this identity do" must still get an answer.

    The row keeps its id on purpose, so that history reads as one identity
    making several attempts rather than as several unrelated identities.
    """
    record = await session.get(OtpRecord, enrollment.id)
    if record is not None:
        await session.delete(record)

    enrollment.password_hash = passwords.hash_password(cred.password)
    enrollment.mobile = mobile
    enrollment.consent_version = None
    enrollment.consent_at = None
    enrollment.embedding_encrypted = None
    enrollment.enrolled_at = None
    #: belt and braces: `_superseded` only sends never-activated records here,
    #: so this is already None. Cleared anyway so "erase the attempt" stays
    #: true if that rule ever loosens.
    enrollment.activated_at = None
    enrollment.status = "awaiting_otp"


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
        if await _superseded(session, existing):
            #: START AGAIN FROM THE BEGINNING (owner rulings 2026-09-10 and
            #: 2026-09-11). The attempt behind this record was never finished,
            #: so nobody was ever told they were enrolled and there is nothing
            #: here to protect. Handing it back is what trapped people: the
            #: record came back at, say, the face stage and the very next call
            #: refused it for not being at the OTP stage, leaving a customer who
            #: could neither continue nor restart. That used to require the
            #: record to be STALE; it no longer does, because a customer
            #: starting again is the only signal that matters.
            await _erase_the_attempt(session, existing, cred, body.mobile)
            await _audit(
                session,
                username=cred.username,
                enrollment_id=existing.id,
                event="enrollment",
                outcome="restarted",
            )
            await session.commit()
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


@router.post("/enrollments/{enrollment_id}/activate", response_model=FaceSubmitResponse)
async def activate_enrollment(enrollment_id: str, session: SessionDep):
    """THE LAST STEP, and the only one no customer performs.

    Called by the orchestrator once the bank has a profile for this identity.
    Until it lands the record sits at `awaiting_activation`: the customer has
    done everything asked of them and the enrolment is still not finished.

    WHY THIS EXISTS AT ALL. This service must never know about the bank (owner
    ruling 2026-09-08), so it cannot look and see whether a profile was made. It
    can only be TOLD. The alternative — treating a submitted face as the end —
    is what let an identity look complete while the bank had never heard of it,
    and left that customer unable to start again because `_superseded` protects
    the finished.

    IDEMPOTENT, because the caller is a workflow step and a workflow step gets
    retried. Finishing twice must cost nothing and must not move `enrolled_at`,
    which records when the enrolment finished and only ever happens once.
    """
    enrollment = await session.get(Enrollment, enrollment_id)
    if enrollment is None:
        raise ProblemError(
            404, "enrollment-not-found", "Enrollment not found", "No such enrollment."
        )
    if enrollment.status == "enrolled":
        return FaceSubmitResponse(
            status="enrolled",
            enrolled_at=enrollment.enrolled_at.isoformat() if enrollment.enrolled_at else None,
        )
    if enrollment.status != "awaiting_activation":
        #: FAIL CLOSED. Anything earlier means the customer has not finished,
        #: and marking such a record enrolled would hand out a working identity
        #: for a face that was never submitted.
        raise ProblemError(
            409,
            "invalid-stage",
            "This enrollment cannot be activated yet",
            "The face step has not been completed.",
        )

    enrollment.status = "enrolled"
    enrollment.enrolled_at = utcnow()
    #: the permanent half. `enrolled_at` says the enrolment is finished NOW and
    #: revocation clears it; this says the bank has provisioned for this
    #: identity AT ALL, which never stops being true.
    if enrollment.activated_at is None:
        enrollment.activated_at = enrollment.enrolled_at
    await _audit(
        session,
        username=enrollment.username,
        enrollment_id=enrollment.id,
        event="enrollment",
        outcome="enrolled",
    )
    await session.commit()
    return FaceSubmitResponse(
        status="enrolled", enrolled_at=enrollment.enrolled_at.isoformat()
    )


@router.post("/enrollments/{enrollment_id}/face", response_model=FaceSubmitResponse)
async def submit_face(
    enrollment_id: str, body: FaceSubmitRequest, session: SessionDep, request: Request
):
    enrollment = await session.get(Enrollment, enrollment_id)
    if enrollment is None:
        raise ProblemError(
            404, "enrollment-not-found", "Enrollment not found", "No such enrollment."
        )
    if enrollment.status in ("enrolled", "awaiting_activation"):
        #: IDEMPOTENT re-submission. Both states mean the face is already in —
        #: `awaiting_activation` is a customer who finished and is waiting on
        #: the bank, and re-sending their face must not disturb either one.
        return FaceSubmitResponse(
            status=enrollment.status,
            enrolled_at=(
                enrollment.enrolled_at.isoformat() if enrollment.enrolled_at else None
            ),
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

    #: DEDUP BEFORE STORING. Checked here rather than after, so a duplicate is
    #: never written and then cleaned up — the gallery must not briefly contain
    #: two faces for one person.
    duplicate = await _find_duplicate(session, embedding, enrollment.id, settings)
    if duplicate is not None:
        other_id, score = duplicate
        #: The matched identity goes in the AUDIT, never in the response. An
        #: enroller who learns WHICH identity they matched has been handed
        #: someone else's banking relationship.
        await _audit(
            session, username=enrollment.username, enrollment_id=enrollment.id,
            event="face_submission", outcome="duplicate",
            detail=f"matched={other_id} score={score:.4f}",
        )
        await session.commit()
        #: Non-specific on purpose. Confirming "this face is already enrolled"
        #: turns the endpoint into an oracle for whether a given person banks
        #: here. Reaching this point already costs a full identity journey, so
        #: the oracle is expensive — but it should not be free either.
        raise ProblemError(
            409,
            "enrollment-not-permitted",
            "This enrollment cannot be completed",
            "Please contact support to continue.",
        )

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
    #: THE CUSTOMER IS DONE — AND WHETHER EVERYTHING IS DEPENDS ON THE BANK
    #: (owner ruling 2026-09-11). This used to write `enrolled` unconditionally,
    #: which made a brand-new identity look complete while the bank had never
    #: heard of it.
    #:
    #: TWO CASES, and `activated_at` is what tells them apart:
    #:
    #: A FIRST ENROLMENT has no profile behind it, so the face is the last thing
    #: the CUSTOMER does and not the last thing that happens — it waits.
    #: `enrolled_at` stays empty for the same reason: it records when the
    #: enrolment finished, and it has not.
    #:
    #: A RE-BIND after a lost device already has one. Nothing needs creating,
    #: so making that customer wait would be waiting for an event that is never
    #: coming — the bank has no work to do and no reason to act.
    if enrollment.activated_at is not None:
        enrollment.status = "enrolled"
        enrollment.enrolled_at = utcnow()
    else:
        enrollment.status = "awaiting_activation"
    await _audit(
        session,
        username=enrollment.username,
        enrollment_id=enrollment.id,
        event="face_submission",
        outcome="enrolled" if enrollment.enrolled_at else "awaiting-activation",
    )
    await session.commit()
    return FaceSubmitResponse(
        status=enrollment.status,
        enrolled_at=enrollment.enrolled_at.isoformat() if enrollment.enrolled_at else None,
    )


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
    #: `activated_at` is deliberately NOT cleared. Losing a phone does not undo
    #: the bank having made a profile, and that is exactly what lets the
    #: replacement face go straight back to `enrolled` instead of waiting for an
    #: activation nobody is going to perform twice.
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


@router.post("/verifications/credential", response_model=CredentialVerifyResponse)
async def verify_credential(
    body: CredentialVerifyRequest,
    session: SessionDep,
    request: Request,
    settings: SettingsDep,
):
    """SIGN IN — is this username and password the one this identity enrolled with?

    THE FIRST READ OF `password_hash` IN THIS SERVICE'S LIFE. It has been
    written at every enrolment and consumed by nothing; `verify_password` was
    built ready for this caller and has been sitting unused. Nothing about the
    stored credential changes here — argon2id at the OWASP baseline, its own
    salt per row — only that something finally asks.

    WHY IT LIVES HERE AND NOT IN THE BANK (owner ruling, restated 2026-09-12:
    fverify IS the identity management system). The bank was checking passwords
    itself against hashes it kept, which made two identity stores and left the
    one that is supposed to be authoritative unable to answer the only question
    identity exists to answer.

    SEALED, LIKE EVERY OTHER CREDENTIAL ON THIS SEAM. The orchestrator persists
    its inputs in run state, so a password crossing it in the clear would be
    readable in a console afterwards. `_unseal_credential` fails closed on
    anything that is not an `enc1:` envelope, so a caller cannot fall back to
    plaintext by omission.

    WHAT IT DOES NOT DECIDE: whether a verified identity may actually sign in.
    A revoked face, an unfinished enrolment and a profile the bank has disabled
    are all correct-password cases with different answers, and those answers
    belong to the caller. This says the credential is right and what stage the
    identity is at; the policy is not this service's to hold.
    """
    #: UNSEAL FIRST, exactly as `/verifications` does with its embedding. The
    #: order matters for a reason worth stating: the username is INSIDE the
    #: envelope, so there is nothing to rate-limit on until it is open.
    cred = _unseal_credential(body.credential_enc, request)

    #: LOCKOUT, on the same mechanism the face factor uses — recent failures for
    #: this identity inside a window. A password endpoint without this is a
    #: guessing oracle, and argon2 slows an attacker down without stopping one.
    cutoff = utcnow() - timedelta(seconds=settings.verify_window_seconds)
    recent_failures = await session.scalar(
        select(func.count(AuditEvent.id)).where(
            AuditEvent.username == cred.username,
            AuditEvent.event == "credential",
            AuditEvent.outcome == "rejected",
            AuditEvent.created_at >= cutoff,
        )
    )
    if (recent_failures or 0) >= settings.verify_max_attempts:
        await _audit(session, cred.username, "credential", "locked")
        await session.commit()
        raise ProblemError(
            429,
            "credential-locked",
            "Sign-in locked",
            "Too many failed sign-in attempts. Try again later.",
        )

    enrollment = await session.scalar(
        select(Enrollment).where(Enrollment.username == cred.username)
    )

    #: AN UNKNOWN USERNAME COSTS THE SAME AS A WRONG PASSWORD. Without this the
    #: two are told apart by a stopwatch: a real row spends ~19 MiB and two
    #: argon2 passes, a missing one returns immediately. Verifying against a
    #: throwaway hash of the same parameters spends it anyway, so the service
    #: does not become a directory of who banks here.
    stored = enrollment.password_hash if enrollment is not None else passwords.decoy_hash()
    ok = passwords.verify_password(stored, cred.password)

    if enrollment is None or not ok:
        await _audit(session, cred.username, "credential", "rejected")
        await session.commit()
        return CredentialVerifyResponse(verdict="rejected")

    #: LEGACY ROWS UPGRADE ON THE ONE OCCASION THE PLAINTEXT IS IN HAND. A hash
    #: written under older parameters can only be re-made during a successful
    #: verification, which is why `needs_rehash` was built alongside the
    #: verifier rather than after it.
    if passwords.needs_rehash(enrollment.password_hash):
        enrollment.password_hash = passwords.hash_password(cred.password)

    await _audit(
        session, cred.username, "credential", "verified",
        enrollment_id=enrollment.id,
    )
    await session.commit()
    return CredentialVerifyResponse(
        verdict="verified",
        status=enrollment.status,
        #: BINDS THE VERDICT TO THIS USERNAME. Without it "verified" is a bare
        #: yes, and the caller can attach it to any username it likes.
        user_ref=user_ref(cred.username, settings.user_ref_key),
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
