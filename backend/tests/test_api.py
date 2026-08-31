"""End-to-end API tests for the standalone face-verification backend.

The staged enrollment (owner rulings 2026-08-31): national id → T24 anchor
(customer id + registered mobile) → fverify's own OTP → consent → face.
Verifications key by national_id OR customer_id; threshold 0.80, 3 retries.
"""

import json
import sqlite3

from app import crypto

DEMO_ID = "12345678901234"  # the t24 stub fixture's known customer
DEV_OTP = "123456"  # settings.otp_stub_code

VEC_A = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8]
VEC_A_CLOSE = [0.101, 0.199, 0.301, 0.4, 0.5, 0.6, 0.7, 0.8]
VEC_ORTHOGONAL = [0.8, -0.7, 0.6, -0.5, 0.4, -0.3, 0.2, -0.1]


def _enroll(harness, national_id=DEMO_ID):
    return harness.client.post("/api/v1/enrollments", json={"national_id": national_id})


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


def _enroll_with_face(harness, national_id=DEMO_ID, vec=VEC_A):
    enrollment_id = _enroll(harness, national_id).json()["enrollment_id"]
    assert _otp(harness, enrollment_id).status_code == 200
    assert _consent(harness, enrollment_id).status_code == 200
    assert _face(harness, enrollment_id, vec).status_code == 200
    return enrollment_id


def _verify(harness, vec, national_id=None, customer_id=None):
    body = {"embedding_enc": harness.seal(vec)}
    if national_id:
        body["national_id"] = national_id
    if customer_id:
        body["customer_id"] = customer_id
    return harness.client.post("/api/v1/verifications", json=body)


# --- the staged enrollment (T24 anchor + own OTP) ------------------------------


def test_enrollment_resolves_the_t24_anchor_and_sends_otp_to_the_registered_mobile(harness):
    resp = _enroll(harness)
    assert resp.status_code == 201
    body = resp.json()
    assert body["status"] == "awaiting_otp"
    assert body["mobile_hint"].startswith("***"), "the response carries the masked hint only"


def test_unknown_national_id_is_not_a_customer_and_no_enrollment_opens(harness):
    resp = _enroll(harness, "99999999999999")
    assert resp.status_code == 404
    assert resp.json()["type"] == "urn:face-verify:problem:not-a-customer"


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


def test_full_journey_anchor_otp_consent_face_status_verify(harness):
    _enroll_with_face(harness)

    status = harness.client.get(f"/api/v1/enrollments/by-national-id/{DEMO_ID}/status")
    assert status.status_code == 200
    body = status.json()
    assert body["enrolled"] is True
    assert body["customer_id"] == "cust-000123"
    assert body["status"] == "enrolled"

    verify = _verify(harness, VEC_A_CLOSE, national_id=DEMO_ID)
    assert verify.status_code == 200
    result = verify.json()
    assert result["verdict"] == "verified"
    assert result["score"] >= result["threshold"] == 0.8

    by_customer = _verify(harness, VEC_A_CLOSE, customer_id="cust-000123")
    assert by_customer.json()["verdict"] == "verified"


def test_mismatch_is_rejected(harness):
    _enroll_with_face(harness)
    verify = _verify(harness, VEC_ORTHOGONAL, national_id=DEMO_ID)
    assert verify.status_code == 200
    result = verify.json()
    assert result["verdict"] == "rejected"
    assert result["score"] < result["threshold"]


def test_unknown_identity_is_indistinguishable_from_mismatch(harness):
    _enroll_with_face(harness)
    unknown = _verify(harness, VEC_ORTHOGONAL, national_id="NID-UNKNOWN")
    mismatch = _verify(harness, VEC_ORTHOGONAL, national_id=DEMO_ID)
    assert unknown.status_code == 200
    assert set(unknown.json().keys()) == set(mismatch.json().keys())
    assert unknown.json()["verdict"] == mismatch.json()["verdict"] == "rejected"
    assert unknown.json()["threshold"] == mismatch.json()["threshold"]


def test_lockout_after_three_failed_attempts(harness):
    _enroll_with_face(harness)
    for _ in range(3):
        resp = _verify(harness, VEC_ORTHOGONAL, national_id=DEMO_ID)
        assert resp.status_code == 200
        assert resp.json()["verdict"] == "rejected"

    locked = _verify(harness, VEC_ORTHOGONAL, national_id=DEMO_ID)
    assert locked.status_code == 429
    assert locked.headers["content-type"].startswith("application/problem+json")
    assert locked.json()["type"] == "urn:face-verify:problem:verification-locked"

    # Even a CORRECT embedding is refused while locked out (fail-closed).
    still_locked = _verify(harness, VEC_A, national_id=DEMO_ID)
    assert still_locked.status_code == 429


def test_verification_requires_exactly_one_identity_key(harness):
    both = _verify(harness, VEC_A, national_id=DEMO_ID, customer_id="cust-000123")
    assert both.status_code == 422
    neither = _verify(harness, VEC_A)
    assert neither.status_code == 422


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
    status = harness.client.get(f"/api/v1/enrollments/by-national-id/{DEMO_ID}/status")
    assert status.json()["enrolled"] is False


def test_extra_image_like_fields_rejected_everywhere(harness):
    resp = harness.client.post(
        "/api/v1/enrollments",
        json={"national_id": DEMO_ID, "selfie_base64": "AAAA"},
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
    _verify(harness, VEC_A, national_id=DEMO_ID)

    audit = harness.client.get("/api/v1/audit/recent")
    assert audit.status_code == 200
    events = audit.json()["events"]
    assert {e["outcome"] for e in events} >= {"created", "verified", "enrolled"}

    # No endpoint response may contain the embedding (as numbers or JSON text).
    blob = json.dumps(audit.json())
    assert "embedding" not in blob
    assert "0.1" not in blob
