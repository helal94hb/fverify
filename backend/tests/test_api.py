"""End-to-end API tests for the standalone face-verification backend.

PURE IDENTITY (owner ruling 2026-08-31): this blackbox knows ONLY user
identity — username, credential, face, OTP. No customer ids, no core banking,
no T24 anywhere; the username ↔ customer_id linkage lives in the mobile DB
and is written through Agentys, never here.

OTP dispatch refactor (2026-09-02): OTP generation is a dedicated endpoint
(/otp/generate) that returns an AES-256-GCM encrypted code for Agentys.
OTP verification accepts the user's code sealed in an enc1: envelope.
"""

import json
import sqlite3

from app import crypto

DEMO_USER = "face.user"
DEMO_MOBILE = "01000000000"
DEMO_PASSWORD = "Sup3r#Secret1"

VEC_A = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8]
VEC_A_CLOSE = [0.101, 0.199, 0.301, 0.4, 0.5, 0.6, 0.7, 0.8]
VEC_ORTHOGONAL = [0.8, -0.7, 0.6, -0.5, 0.4, -0.3, 0.2, -0.1]


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

def _enroll(harness, username=DEMO_USER, mobile=DEMO_MOBILE):
    return harness.client.post(
        "/api/v1/enrollments",
        json={"username": username, "password": DEMO_PASSWORD, "mobile": mobile},
    )


def _otp_generate(harness, enrollment_id):
    return harness.client.post(
        f"/api/v1/enrollments/{enrollment_id}/otp/generate",
    )


def _otp_verify(harness, enrollment_id, otp_code_enc):
    return harness.client.post(
        f"/api/v1/enrollments/{enrollment_id}/otp",
        json={"otp_code_enc": otp_code_enc},
    )


def _consent(harness, enrollment_id):
    return harness.client.post(
        f"/api/v1/enrollments/{enrollment_id}/consent", json={"consent_version": "v1"}
    )


def _face(harness, enrollment_id, vec=VEC_A):
    return harness.client.post(
        f"/api/v1/enrollments/{enrollment_id}/face",
        json={"embedding_enc": harness.seal(vec)},
    )


def _generate_and_verify_otp(harness, enrollment_id):
    """Generate an OTP, decrypt it (as Agentys would), seal it (as the mobile
    app would), and verify it against fverify."""
    gen = _otp_generate(harness, enrollment_id)
    assert gen.status_code == 200, gen.json()
    code = harness.decrypt_otp(gen.json()["ciphered_otp"])
    sealed_code = harness.seal_otp(code)
    verify = _otp_verify(harness, enrollment_id, sealed_code)
    assert verify.status_code == 200, verify.json()
    return verify


def _enroll_with_face(harness, username=DEMO_USER, vec=VEC_A):
    enrollment_id = _enroll(harness, username).json()["enrollment_id"]
    _generate_and_verify_otp(harness, enrollment_id)
    assert _consent(harness, enrollment_id).status_code == 200
    assert _face(harness, enrollment_id, vec).status_code == 200
    return enrollment_id


def _verify(harness, vec, username=DEMO_USER):
    return harness.client.post(
        "/api/v1/verifications",
        json={"username": username, "embedding_enc": harness.seal(vec)},
    )


# --- registration (pure identity) ----------------------------------------------


def test_enrollment_registers_pure_identity(harness):
    resp = _enroll(harness)
    assert resp.status_code == 201
    body = resp.json()
    assert body["status"] == "awaiting_otp"
    assert body["mobile_hint"].startswith("***"), "the response carries the masked hint only"
    # The registration endpoint must NOT return any OTP-related field.
    assert "ciphered_otp" not in body
    assert "otp" not in body


def test_enrollment_is_idempotent(harness):
    first = _enroll(harness)
    second = _enroll(harness)
    assert second.status_code == 201
    assert second.json()["enrollment_id"] == first.json()["enrollment_id"]


# --- OTP generation (new endpoint) -------------------------------------------


def test_otp_generate_returns_valid_aes256gcm_token(harness):
    enrollment_id = _enroll(harness).json()["enrollment_id"]
    gen = _otp_generate(harness, enrollment_id)
    assert gen.status_code == 200
    body = gen.json()
    assert body["ciphered_otp"].startswith("aes256gcm:")
    assert body["mobile"] == DEMO_MOBILE
    assert body["mobile_hint"].startswith("***")
    assert body["expires_in"] > 0
    # Decrypt and verify it's a 6-digit code.
    code = harness.decrypt_otp(body["ciphered_otp"])
    assert len(code) == 6
    assert code.isdigit()


def test_otp_generate_enforces_cooldown(harness):
    enrollment_id = _enroll(harness).json()["enrollment_id"]
    first = _otp_generate(harness, enrollment_id)
    assert first.status_code == 200
    # Immediate second call should be cooldown-refused.
    second = _otp_generate(harness, enrollment_id)
    assert second.status_code == 429
    assert second.json()["type"] == "urn:face-verify:problem:otp-resend-cooldown"


def test_otp_generate_rejected_after_otp_verified(harness):
    enrollment_id = _enroll(harness).json()["enrollment_id"]
    _generate_and_verify_otp(harness, enrollment_id)
    # The enrollment is now in awaiting_consent — generate should be refused.
    gen = _otp_generate(harness, enrollment_id)
    assert gen.status_code == 409


# --- OTP verification ---------------------------------------------------------


def test_otp_verify_accepts_sealed_code(harness):
    enrollment_id = _enroll(harness).json()["enrollment_id"]
    gen = _otp_generate(harness, enrollment_id)
    code = harness.decrypt_otp(gen.json()["ciphered_otp"])
    sealed_code = harness.seal_otp(code)
    verify = _otp_verify(harness, enrollment_id, sealed_code)
    assert verify.status_code == 200
    assert verify.json()["status"] == "awaiting_consent"


def test_otp_verify_rejects_plaintext_code(harness):
    enrollment_id = _enroll(harness).json()["enrollment_id"]
    _otp_generate(harness, enrollment_id)
    # Send the code as plain text (not enc1: sealed) — must be refused.
    resp = harness.client.post(
        f"/api/v1/enrollments/{enrollment_id}/otp",
        json={"otp_code_enc": "123456"},  # plain text, not sealed
    )
    assert resp.status_code == 422
    assert resp.json()["type"] == "urn:face-verify:problem:invalid-otp-format"


def test_otp_verify_rejects_wrong_code(harness):
    enrollment_id = _enroll(harness).json()["enrollment_id"]
    _otp_generate(harness, enrollment_id)
    # Seal a wrong code.
    wrong_sealed = harness.seal_otp("000000")
    resp = _otp_verify(harness, enrollment_id, wrong_sealed)
    assert resp.status_code == 422
    assert resp.json()["type"] == "urn:face-verify:problem:invalid-otp"


def test_otp_must_verify_before_any_later_step(harness):
    enrollment_id = _enroll(harness).json()["enrollment_id"]
    _otp_generate(harness, enrollment_id)
    # Consent is refused while the OTP is unproven.
    assert _consent(harness, enrollment_id).status_code == 409
    # Face is refused while the OTP is unproven.
    assert _face(harness, enrollment_id).status_code == 409


def test_otp_attempts_are_capped_and_the_record_dies_exhausted(harness):
    enrollment_id = _enroll(harness).json()["enrollment_id"]
    gen = _otp_generate(harness, enrollment_id)
    real_code = harness.decrypt_otp(gen.json()["ciphered_otp"])
    # Exhaust all 5 attempts with wrong codes.
    for _ in range(5):
        wrong = harness.seal_otp("000000")
        assert _otp_verify(harness, enrollment_id, wrong).status_code == 422
    # Attempts exhausted → even the RIGHT code fails now.
    right = harness.seal_otp(real_code)
    assert _otp_verify(harness, enrollment_id, right).status_code == 422


def test_otp_is_single_use(harness):
    enrollment_id = _enroll(harness).json()["enrollment_id"]
    gen = _otp_generate(harness, enrollment_id)
    code = harness.decrypt_otp(gen.json()["ciphered_otp"])
    sealed = harness.seal_otp(code)
    # First use succeeds.
    assert _otp_verify(harness, enrollment_id, sealed).status_code == 200
    # Second use of the same code is refused (stage has moved).
    assert _otp_verify(harness, enrollment_id, sealed).status_code == 409


# --- the full journey + the verdict ------------------------------------------


def test_full_journey_register_otp_consent_face_status_verify(harness):
    _enroll_with_face(harness)

    status = harness.client.get(f"/api/v1/enrollments/by-username/{DEMO_USER}/status")
    assert status.status_code == 200
    body = status.json()
    assert body["enrolled"] is True
    assert body["status"] == "enrolled"
    assert "customer_id" not in body, "this blackbox has no customer ids to leak"

    verify = _verify(harness, VEC_A_CLOSE)
    assert verify.status_code == 200
    result = verify.json()
    assert result["verdict"] == "verified"
    assert result["score"] >= result["threshold"] == 0.8


def test_mismatch_is_rejected(harness):
    _enroll_with_face(harness)
    verify = _verify(harness, VEC_ORTHOGONAL)
    assert verify.status_code == 200
    result = verify.json()
    assert result["verdict"] == "rejected"
    assert result["score"] < result["threshold"]


def test_unknown_identity_is_indistinguishable_from_mismatch(harness):
    _enroll_with_face(harness)
    unknown = _verify(harness, VEC_ORTHOGONAL, username="someone.else")
    mismatch = _verify(harness, VEC_ORTHOGONAL)
    assert unknown.status_code == 200
    assert set(unknown.json().keys()) == set(mismatch.json().keys())
    assert unknown.json()["verdict"] == mismatch.json()["verdict"] == "rejected"
    assert unknown.json()["threshold"] == mismatch.json()["threshold"]


def test_lockout_after_three_failed_attempts(harness):
    _enroll_with_face(harness)
    for _ in range(3):
        resp = _verify(harness, VEC_ORTHOGONAL)
        assert resp.status_code == 200
        assert resp.json()["verdict"] == "rejected"

    locked = _verify(harness, VEC_ORTHOGONAL)
    assert locked.status_code == 429
    assert locked.headers["content-type"].startswith("application/problem+json")
    assert locked.json()["type"] == "urn:face-verify:problem:verification-locked"

    # Even a CORRECT embedding is refused while locked out (fail-closed).
    still_locked = _verify(harness, VEC_A)
    assert still_locked.status_code == 429


# --- the guards that must never regress ----------------------------------------


def test_unsealed_embedding_is_refused(harness):
    enrollment_id = _enroll(harness).json()["enrollment_id"]
    _generate_and_verify_otp(harness, enrollment_id)
    assert _consent(harness, enrollment_id).status_code == 200
    face = harness.client.post(
        f"/api/v1/enrollments/{enrollment_id}/face",
        json={"embedding_enc": json.dumps(VEC_A)},  # plaintext, not enc1:-sealed
    )
    assert face.status_code == 422
    assert face.json()["type"] == "urn:face-verify:problem:invalid-embedding"

    # And the enrollment must NOT have progressed.
    status = harness.client.get(f"/api/v1/enrollments/by-username/{DEMO_USER}/status")
    assert status.json()["enrolled"] is False


def test_extra_image_like_fields_rejected_everywhere(harness):
    resp = harness.client.post(
        "/api/v1/enrollments",
        json={"username": DEMO_USER, "password": DEMO_PASSWORD, "mobile": DEMO_MOBILE,
              "selfie_base64": "AAAA"},
    )
    assert resp.status_code == 422

    enrollment_id = _enroll(harness).json()["enrollment_id"]
    _generate_and_verify_otp(harness, enrollment_id)
    assert _consent(harness, enrollment_id).status_code == 200
    face = harness.client.post(
        f"/api/v1/enrollments/{enrollment_id}/face",
        json={"embedding_enc": harness.seal(VEC_A), "photo": "AAAA"},
    )
    assert face.status_code == 422


def test_sealed_image_like_payload_is_refused(harness):
    enrollment_id = _enroll(harness).json()["enrollment_id"]
    _generate_and_verify_otp(harness, enrollment_id)
    assert _consent(harness, enrollment_id).status_code == 200
    face = harness.client.post(
        f"/api/v1/enrollments/{enrollment_id}/face",
        json={"embedding_enc": harness.seal({"image_base64": "A" * 100})},
    )
    assert face.status_code == 422
    assert face.json()["type"] == "urn:face-verify:problem:invalid-embedding"


def test_embedding_encrypted_at_rest(harness):
    _enroll_with_face(harness)

    # Raw DB read: the stored column is ciphertext, not floats.
    raw = sqlite3.connect(harness.db_path)
    (stored,) = raw.execute("SELECT embedding_encrypted FROM enrollments").fetchone()
    raw.close()
    assert isinstance(stored, bytes)
    assert b"0.1" not in stored
    assert json.dumps(VEC_A).encode() not in stored

    # It decrypts back to the original vector with the at-rest key.
    assert crypto.decrypt_embedding(stored, crypto.get_fernet(harness.at_rest_key)) == VEC_A


def test_embedding_never_returned_and_audit_has_outcomes_only(harness):
    _enroll_with_face(harness)
    _verify(harness, VEC_A)

    audit = harness.client.get("/api/v1/audit/recent")
    assert audit.status_code == 200
    events = audit.json()["events"]
    assert {e["outcome"] for e in events} >= {"created", "verified", "enrolled"}
    assert all("username" in e for e in events)

    # No endpoint response may contain the embedding (as numbers or JSON text).
    blob = json.dumps(audit.json())
    assert "embedding" not in blob
    assert "0.1" not in blob


# --- OTP export encryption tests (aes256gcm) ----------------------------------


def test_ciphered_otp_never_in_enrollment_response(harness):
    """POST /enrollments must NOT return any OTP material."""
    resp = _enroll(harness)
    body = resp.json()
    assert "ciphered_otp" not in body
    assert "otp_code" not in body


def test_face_before_the_stages_is_refused(harness):
    enrollment_id = _enroll(harness).json()["enrollment_id"]
    face = _face(harness, enrollment_id)
    assert face.status_code == 409
    assert face.json()["type"] == "urn:face-verify:problem:invalid-stage"
