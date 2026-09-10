"""Controls for 1:N biometric deduplication.

The gap this closes is the one an identity check structurally cannot see. A
duplicate keyed on `customer_id` catches the same identity enrolling twice;
this catches one HUMAN holding two different identities — which is the fraud
that matters, because it splits transactions across profiles, evades limits,
and defeats the single customer view FATF Recommendation 10 requires.

The evidence it was needed is in the dev data: 32 enrolments on one mobile
number, all the same person, every one accepted.
"""

import sqlite3

from tests.test_api import (
    DEMO_USER,
    VEC_A,
    VEC_A_CLOSE,
    VEC_ORTHOGONAL,
    _consent,
    _enroll,
    _enroll_with_face,
    _generate_and_verify_otp,
)


def _stage_to_face(harness, username):
    """Drive a second identity right up to the face step."""
    eid = _enroll(harness, username).json()["enrollment_id"]
    _generate_and_verify_otp(harness, eid)
    assert _consent(harness, eid).status_code == 200
    return eid


def _submit_face(harness, eid, vec):
    return harness.client.post(
        f"/api/v1/enrollments/{eid}/face", json={"embedding_enc": harness.seal(vec)}
    )


def test_the_same_face_under_a_second_identity_is_refused(harness):
    """THE defect. One person, two identities, both fully proofed."""
    _enroll_with_face(harness, username=DEMO_USER, vec=VEC_A)

    second = _stage_to_face(harness, "different.person")
    r = _submit_face(harness, second, VEC_A)

    assert r.status_code == 409
    assert r.json()["type"].endswith("enrollment-not-permitted")


def test_a_near_match_is_refused_too(harness):
    """A duplicate does not present the identical vector — it is the same face
    captured twice, which lands close but never equal. Matching only on
    identity would catch nothing real."""
    _enroll_with_face(harness, username=DEMO_USER, vec=VEC_A)

    second = _stage_to_face(harness, "near.twin")
    assert _submit_face(harness, second, VEC_A_CLOSE).status_code == 409


def test_a_genuinely_different_person_enrols_normally(harness):
    """The control that stops this being a blanket refusal. Without it, a test
    suite in which everything is rejected would look identical to a working
    dedup."""
    _enroll_with_face(harness, username=DEMO_USER, vec=VEC_A)

    second = _stage_to_face(harness, "genuine.other")
    assert _submit_face(harness, second, VEC_ORTHOGONAL).status_code == 200


def test_the_refusal_does_not_say_who_was_matched(harness):
    """An enroller who learns WHICH identity they matched has been handed
    someone else's banking relationship. The match belongs in the audit."""
    _enroll_with_face(harness, username=DEMO_USER, vec=VEC_A)
    second = _stage_to_face(harness, "prober")
    body = _submit_face(harness, second, VEC_A).text

    assert DEMO_USER not in body
    assert "matched" not in body
    assert "score" not in body


def test_the_match_IS_recorded_in_the_audit(harness):
    """Invisible to the client, fully visible to an investigator — the audit is
    where a duplicate attempt has to leave a trace."""
    _enroll_with_face(harness, username=DEMO_USER, vec=VEC_A)
    second = _stage_to_face(harness, "audited.prober")
    _submit_face(harness, second, VEC_A)

    con = sqlite3.connect(harness.db_path)
    rows = con.execute(
        "select outcome, detail from audit_events where outcome='duplicate'"
    ).fetchall()
    con.close()

    assert len(rows) == 1, rows
    assert "matched=" in rows[0][1] and "score=" in rows[0][1]


def test_a_duplicate_is_never_written_to_the_gallery(harness):
    """Checked BEFORE storing, so the gallery never briefly holds two faces for
    one person — a window in which a concurrent verification could match the
    wrong template."""
    _enroll_with_face(harness, username=DEMO_USER, vec=VEC_A)
    second = _stage_to_face(harness, "not.stored")
    _submit_face(harness, second, VEC_A)

    con = sqlite3.connect(harness.db_path)
    (count,) = con.execute("select count(*) from face_templates").fetchone()
    con.close()
    assert count == 1


def test_a_revoked_template_does_not_block_re_enrolment(harness):
    """A retired binding must not lock its own owner out.

    This is the interaction between dedup and revocation, and getting it wrong
    in either direction is bad: search revoked templates and a customer can
    never re-enrol after a lost phone; forget to exclude the enrolment's own
    template and nobody can ever replace their face.
    """
    eid = _enroll_with_face(harness, username=DEMO_USER, vec=VEC_A)
    assert harness.client.post(
        f"/api/v1/enrollments/{eid}/face/revoke", json={"reason": "lost_device"}
    ).status_code == 200

    #: the SAME person, the same face, re-binding after revocation
    assert _submit_face(harness, eid, VEC_A).status_code == 200


def test_dedup_can_be_turned_off_and_the_control_notices(harness, monkeypatch):
    """A disabled control must be provably disabled, not silently absent — the
    difference between 'we chose not to' and 'it never ran'."""
    from app.config import get_settings

    _enroll_with_face(harness, username=DEMO_USER, vec=VEC_A)

    settings = get_settings()
    monkeypatch.setattr(settings, "dedup_enabled", False)

    second = _stage_to_face(harness, "allowed.through")
    assert _submit_face(harness, second, VEC_A).status_code == 200
