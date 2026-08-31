"""End-to-end API tests for the standalone face-verification backend."""

import json
import sqlite3

from app import crypto

VEC_A = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8]
VEC_A_CLOSE = [0.101, 0.199, 0.301, 0.4, 0.5, 0.6, 0.7, 0.8]
VEC_ORTHOGONAL = [0.8, -0.7, 0.6, -0.5, 0.4, -0.3, 0.2, -0.1]


def _enroll(harness, national_id="NID-1"):
    return harness.client.post(
        "/api/v1/enrollments",
        json={"national_id": national_id, "mobile": "+000000000", "consent_version": "v1"},
    )


def _enroll_with_face(harness, national_id="NID-1", vec=VEC_A):
    resp = _enroll(harness, national_id)
    enrollment_id = resp.json()["enrollment_id"]
    face = harness.client.post(
        f"/api/v1/enrollments/{enrollment_id}/face",
        json={"embedding_enc": harness.seal(vec)},
    )
    assert face.status_code == 200
    return enrollment_id


def _verify(harness, national_id, vec):
    return harness.client.post(
        "/api/v1/verifications",
        json={"national_id": national_id, "embedding_enc": harness.seal(vec)},
    )


def test_full_journey_enroll_face_status_verify(harness):
    resp = _enroll(harness)
    assert resp.status_code == 201
    body = resp.json()
    assert body["status"] == "awaiting_face"
    enrollment_id = body["enrollment_id"]

    face = harness.client.post(
        f"/api/v1/enrollments/{enrollment_id}/face",
        json={"embedding_enc": harness.seal(VEC_A)},
    )
    assert face.status_code == 200
    assert face.json()["status"] == "enrolled"
    assert face.json()["enrolled_at"]

    status = harness.client.get("/api/v1/enrollments/by-national-id/NID-1/status")
    assert status.status_code == 200
    assert status.json()["enrolled"] is True
    assert status.json()["enrolled_at"] == face.json()["enrolled_at"]

    verify = _verify(harness, "NID-1", VEC_A_CLOSE)
    assert verify.status_code == 200
    result = verify.json()
    assert result["verdict"] == "verified"
    assert result["score"] >= result["threshold"]


def test_mismatch_is_rejected(harness):
    _enroll_with_face(harness)
    verify = _verify(harness, "NID-1", VEC_ORTHOGONAL)
    assert verify.status_code == 200
    result = verify.json()
    assert result["verdict"] == "rejected"
    assert result["score"] < result["threshold"]


def test_unknown_national_id_is_indistinguishable_from_mismatch(harness):
    _enroll_with_face(harness, national_id="NID-KNOWN")
    unknown = _verify(harness, "NID-UNKNOWN", VEC_ORTHOGONAL)
    mismatch = _verify(harness, "NID-KNOWN", VEC_ORTHOGONAL)
    assert unknown.status_code == 200
    assert set(unknown.json().keys()) == set(mismatch.json().keys())
    assert unknown.json()["verdict"] == mismatch.json()["verdict"] == "rejected"
    assert unknown.json()["threshold"] == mismatch.json()["threshold"]


def test_lockout_after_five_failed_attempts(harness):
    _enroll_with_face(harness)
    for _ in range(5):
        resp = _verify(harness, "NID-1", VEC_ORTHOGONAL)
        assert resp.status_code == 200
        assert resp.json()["verdict"] == "rejected"

    locked = _verify(harness, "NID-1", VEC_ORTHOGONAL)
    assert locked.status_code == 429
    assert locked.headers["content-type"].startswith("application/problem+json")
    assert locked.json()["type"] == "urn:face-verify:problem:verification-locked"

    # Even a CORRECT embedding is refused while locked out (fail-closed).
    still_locked = _verify(harness, "NID-1", VEC_A)
    assert still_locked.status_code == 429


def test_consent_required_before_face(harness):
    # consent_version is a required field — no consent, no enrollment at all.
    resp = harness.client.post(
        "/api/v1/enrollments", json={"national_id": "NID-2", "mobile": "+000000000"}
    )
    assert resp.status_code == 422
    assert resp.headers["content-type"].startswith("application/problem+json")


def test_unsealed_embedding_is_refused(harness):
    resp = _enroll(harness)
    enrollment_id = resp.json()["enrollment_id"]
    face = harness.client.post(
        f"/api/v1/enrollments/{enrollment_id}/face",
        json={"embedding_enc": json.dumps(VEC_A)},  # plaintext, not enc1:-sealed
    )
    assert face.status_code == 422
    assert face.json()["type"] == "urn:face-verify:problem:invalid-embedding"

    # And the enrollment must NOT have progressed.
    status = harness.client.get("/api/v1/enrollments/by-national-id/NID-1/status")
    assert status.json()["enrolled"] is False


def test_extra_image_like_fields_rejected_everywhere(harness):
    resp = harness.client.post(
        "/api/v1/enrollments",
        json={
            "national_id": "NID-3",
            "mobile": "+000000000",
            "consent_version": "v1",
            "selfie_base64": "AAAA",
        },
    )
    assert resp.status_code == 422

    enrollment_id = _enroll(harness, "NID-3").json()["enrollment_id"]
    face = harness.client.post(
        f"/api/v1/enrollments/{enrollment_id}/face",
        json={"embedding_enc": harness.seal(VEC_A), "photo": "AAAA"},
    )
    assert face.status_code == 422


def test_sealed_image_like_payload_is_refused(harness):
    enrollment_id = _enroll(harness).json()["enrollment_id"]
    face = harness.client.post(
        f"/api/v1/enrollments/{enrollment_id}/face",
        json={"embedding_enc": harness.seal({"image_base64": "A" * 100})},
    )
    assert face.status_code == 422
    assert face.json()["type"] == "urn:face-verify:problem:invalid-embedding"


def test_second_enroll_is_idempotent(harness):
    first = _enroll(harness)
    second = _enroll(harness)
    assert first.json()["enrollment_id"] == second.json()["enrollment_id"]


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
    _verify(harness, "NID-1", VEC_A)

    audit = harness.client.get("/api/v1/audit/recent")
    assert audit.status_code == 200
    events = audit.json()["events"]
    assert {e["outcome"] for e in events} >= {"created", "enrolled", "verified"}

    # No endpoint response may contain the embedding (as numbers or JSON text).
    blob = json.dumps(audit.json())
    assert "embedding" not in blob
    assert "0.1" not in blob
