"""Controls for template revocation (ISO/IEC 24745 renewability and revocability).

Before this, a template lived in one column on the enrolment. There was no way
to say "that face no longer verifies", and a replacement would have overwritten
the original in place — leaving no evidence a previous face had ever existed.

The properties worth asserting are: a revoked face STOPS verifying, a replaced
face does not resurrect, the history SURVIVES, and none of it is visible to an
attacker probing from outside.
"""

import sqlite3

from tests.test_api import VEC_A, VEC_ORTHOGONAL, _enroll_with_face, _verify

#: a face that is unmistakably NOT the enrolled one, so a replacement
#: is provable by behaviour and not only by row inspection
VEC_B = VEC_ORTHOGONAL


def _templates(harness, enrollment_id=None):
    con = sqlite3.connect(harness.db_path)
    rows = con.execute(
        "select id, revoked_at, revoked_reason, superseded_by from face_templates"
    ).fetchall()
    con.close()
    return rows


def _revoke(harness, enrollment_id, reason="lost_device"):
    return harness.client.post(
        f"/api/v1/enrollments/{enrollment_id}/face/revoke", json={"reason": reason}
    )


def test_a_revoked_face_stops_verifying(harness):
    """The property the whole feature exists for."""
    eid = _enroll_with_face(harness, vec=VEC_A)
    assert _verify(harness, VEC_A).json()["verdict"] == "verified"

    assert _revoke(harness, eid).status_code == 200

    #: the SAME face, which was verifying a moment ago
    assert _verify(harness, VEC_A).json()["verdict"] == "rejected"


def test_revocation_keeps_the_history(harness):
    """Revoked never means deleted — the row is the evidence a re-binding
    happened, and an investigator needs it."""
    eid = _enroll_with_face(harness, vec=VEC_A)
    _revoke(harness, eid, reason="compromised")

    rows = _templates(harness)
    assert len(rows) == 1
    _id, revoked_at, reason, superseded_by = rows[0]
    assert revoked_at is not None
    assert reason == "compromised"
    assert superseded_by is None      # revoked, not yet replaced


def test_a_replacement_supersedes_rather_than_overwrites(harness):
    """Two rows afterwards, not one: the old face is still on record, and the
    chain says which template replaced it."""
    eid = _enroll_with_face(harness, vec=VEC_A)
    _revoke(harness, eid, reason="lost_device")

    #: re-bind with a DIFFERENT face
    assert harness.client.post(
        f"/api/v1/enrollments/{eid}/face",
        json={"embedding_enc": harness.seal(VEC_B)},
    ).status_code == 200

    rows = _templates(harness)
    assert len(rows) == 2, rows
    revoked = [r for r in rows if r[1] is not None]
    active = [r for r in rows if r[1] is None]
    assert len(revoked) == 1 and len(active) == 1
    assert revoked[0][3] == active[0][0], "the revoked row must name its successor"

    #: and the behaviour follows the data
    assert _verify(harness, VEC_B).json()["verdict"] == "verified"
    assert _verify(harness, VEC_A).json()["verdict"] == "rejected"


def test_the_old_face_never_comes_back(harness):
    """A revoked template must not resurrect when a new one is revoked in turn.

    This is the case a naive 'use the most recent row' implementation gets
    wrong: revoke the replacement and the ORIGINAL becomes newest-unrevoked
    again, silently re-arming a face that was retired for cause.
    """
    eid = _enroll_with_face(harness, vec=VEC_A)
    _revoke(harness, eid, reason="compromised")
    harness.client.post(f"/api/v1/enrollments/{eid}/face",
                        json={"embedding_enc": harness.seal(VEC_B)})
    _revoke(harness, eid, reason="lost_device")

    assert _verify(harness, VEC_A).json()["verdict"] == "rejected"
    assert _verify(harness, VEC_B).json()["verdict"] == "rejected"


def test_revocation_is_invisible_from_outside(harness):
    """A revoked identity must not be distinguishable from a mismatch.

    Reporting 'that face was revoked' would confirm the identity exists and
    volunteer its history to anyone who asks.
    """
    eid = _enroll_with_face(harness, vec=VEC_A)
    _revoke(harness, eid)

    revoked = _verify(harness, VEC_A).json()
    unknown = _verify(harness, VEC_A, username="never_existed").json()
    assert revoked["verdict"] == unknown["verdict"] == "rejected"
    assert revoked["score"] == unknown["score"] == 0.0


def test_a_reason_is_mandatory_and_constrained(harness):
    eid = _enroll_with_face(harness, vec=VEC_A)
    assert harness.client.post(
        f"/api/v1/enrollments/{eid}/face/revoke", json={}
    ).status_code == 422
    assert harness.client.post(
        f"/api/v1/enrollments/{eid}/face/revoke",
        json={"reason": "because I felt like it"},
    ).status_code == 422


def test_revoking_twice_is_a_no_op_not_an_error(harness):
    """Idempotent: 'nothing live to revoke' is the state the caller asked for.
    An error here would push callers into retry loops around a security action."""
    eid = _enroll_with_face(harness, vec=VEC_A)
    assert _revoke(harness, eid).status_code == 200
    assert _revoke(harness, eid).status_code == 200
    assert len(_templates(harness)) == 1


def test_revoking_an_unknown_enrolment_is_404(harness):
    assert _revoke(harness, "no-such-enrollment").status_code == 404
