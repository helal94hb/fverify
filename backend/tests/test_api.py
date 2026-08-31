"""End-to-end API tests for the standalone face-verification backend.

PURE IDENTITY (owner ruling 2026-08-31): this blackbox knows ONLY user
identity — username, credential, face, OTP. No customer ids, no core banking,
no T24 anywhere; the username ↔ customer_id linkage lives in the mobile DB
and is written through Agentys, never here.
"""

import json
import sqlite3

from app import crypto

DEMO_USER = "face.user"
DEMO_MOBILE = "01000000000"
DEMO_PASSWORD = "Sup3r#Secret1"
DEV_OTP = "123456"  # settings.otp_stub_code

VEC_A = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8]
VEC_A_CLOSE = [0.101, 0.199, 0.301, 0.4, 0.5, 0.6, 0.7, 0.8]
VEC_ORTHOGONAL = [0.8, -0.7, 0.6, -0.5, 0.4, -0.3, 0.2, -0.1]


def _enroll(harness, username=DEMO_USER, mobile=DEMO_MOBILE):
    return harness.client.post(
        "/api/v1/enrollments",
        json={"username": username, "password": DEMO_PASSWORD, "mobile": mobile},
    )


def _otp(harness, enrollment_id, code=DEV_OTP):
    return harness.client.post(
        f"/api/v1/enrollments/{enrollment_id}/otp", json={"otp_code": code}
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


def _enroll_with_face(harness, username=DEMO_USER, vec=VEC_A):
    enrollment_id = _enroll(harness, username).json()["enrollment_id"]
    assert _otp(harness, enrollment_id).status_code == 200
    assert _consent(harness, enrollment_id).status_code == 200
    assert _face(harness, enrollment_id, vec).status_code == 200
    return enrollment_id


def _verify(harness, vec, username=DEMO_USER):
    return harness.client.post(
        "/api/v1/verifications",
        json={"username": username, "embedding_enc": harness.seal(vec)},
    )


# --- registration (pure identity) ----------------------------------------------


def test_enrollment_registers_pure_identity_and_sends_otp(harness):
    resp = _enroll(harness)
    assert resp.status_code == 201
    body = resp.json()
    assert body["status"] == "awaiting_otp"
    assert body["mobile_hint"].startswith("***"), "the response carries the masked hint only"


def test_otp_must_verify_before_any_later_step(harness):
    enrollment_id = _enroll(harness).json()["enrollment_id"]
    wrong = _otp(harness, enrollment_id, "000000")
    assert wrong.status_code == 422
    assert wrong.json()["type"] == "urn:face-verify:problem:invalid-otp"
    # consent is refused while the OTP is unproven
    assert _consent(harness, enrollment_id).status_code == 409
    right = _otp(harness, enrollment_id)
    assert right.status_code == 200
    assert right.json()["status"] == "awaiting_consent"
    # single-use: the same code cannot verify twice
    assert _otp(harness, enrollment_id).status_code == 409


def test_otp_attempts_are_capped_and_the_record_dies_exhausted(harness):
    enrollment_id = _enroll(harness).json()["enrollment_id"]
    for _ in range(5):
        assert _otp(harness, enrollment_id, "000000").status_code == 422
    # attempts exhausted → the record was deleted; even the RIGHT code fails now
    assert _otp(harness, enrollment_id, DEV_OTP).status_code == 422


def test_immediate_resend_is_cooldown_refused(harness):
    first = _enroll(harness)
    again = _enroll(harness)
    assert again.status_code == 429
    assert again.json()["type"] == "urn:face-verify:problem:otp-resend-cooldown"
    assert first.json()["enrollment_id"]


def test_second_enroll_after_otp_returns_the_same_enrollment(harness):
    first = _enroll(harness)
    enrollment_id = first.json()["enrollment_id"]
    assert _otp(harness, enrollment_id).status_code == 200
    second = _enroll(harness)
    assert second.status_code == 201
    assert second.json()["enrollment_id"] == enrollment_id


def test_face_before_the_stages_is_refused(harness):
    enrollment_id = _enroll(harness).json()["enrollment_id"]
    face = _face(harness, enrollment_id)
    assert face.status_code == 409
    assert face.json()["type"] == "urn:face-verify:problem:invalid-stage"


# --- the full journey + the verdict --------------------------------------------


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
    assert _otp(harness, enrollment_id).status_code == 200
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
    assert _otp(harness, enrollment_id).status_code == 200
    assert _consent(harness, enrollment_id).status_code == 200
    face = harness.client.post(
        f"/api/v1/enrollments/{enrollment_id}/face",
        json={"embedding_enc": harness.seal(VEC_A), "photo": "AAAA"},
    )
    assert face.status_code == 422


def test_sealed_image_like_payload_is_refused(harness):
    enrollment_id = _enroll(harness).json()["enrollment_id"]
    assert _otp(harness, enrollment_id).status_code == 200
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
