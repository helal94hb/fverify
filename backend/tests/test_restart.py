"""AN ABANDONED SIGN-UP IS ERASED AND STARTS AGAIN (owner ruling 2026-09-10).

THE TRAP THIS CLOSES. Enrolment was idempotent per username in the simplest
way: an existing record came back untouched, at whatever stage it had reached.
The orchestrator's flows expire while they wait, so somebody who walked away at
the consent or face stage came back to a record sitting there — and the very
next call, which generates a code, refuses anything that is not at the OTP
stage. They could not continue, and they could not start over. Verified against
a real record before this was written: HTTP 409, `invalid-stage`.

THE RULE, in the owner's words: the flow did not finish, so nobody was ever
told they were enrolled, so erase it. What follows is that rule plus the three
cases it must NOT touch, each of which would be a worse defect than the one
being fixed.
"""

import sqlite3
from datetime import timedelta

from app.config import get_settings
from app.models import utcnow
from tests.test_api import (
    DEMO_MOBILE,
    DEMO_PASSWORD,
    DEMO_USER,
    VEC_A,
    _consent,
    _enroll,
    _enroll_with_face,
    _face,
    _generate_and_verify_otp,
    _otp_generate,
)


def _age(harness, enrollment_id: str, minutes: int) -> None:
    """Backdate every mark of activity on a record.

    Reaching past the API on purpose: the alternative is a test that sleeps for
    half an hour, and the thing under test is a DECISION about elapsed time, not
    the passage of it.
    """
    then = (utcnow() - timedelta(minutes=minutes)).isoformat(sep=" ")
    con = sqlite3.connect(harness.db_path)
    con.execute("update enrollments set created_at=?, consent_at=null where id=?",
                (then, enrollment_id))
    con.execute("update otp_records set created_at=? where enrollment_id=?",
                (then, enrollment_id))
    con.commit()
    con.close()


def _status(harness, username: str = DEMO_USER) -> str:
    return harness.client.get(f"/api/v1/enrollments/by-username/{username}/status").json()[
        "status"
    ]


def _restart(harness, password: str = DEMO_PASSWORD, mobile: str = DEMO_MOBILE):
    """Begin the journey again for the same username — what the graph does."""
    return harness.client.post(
        "/api/v1/enrollments",
        json={
            "credential_enc": harness.seal({"username": DEMO_USER, "password": password}),
            "mobile": mobile,
        },
    )


def test_an_abandoned_attempt_is_erased_and_begins_again(harness):
    """THE rule. Walked away after consent, came back later — and gets a clean
    start rather than a record the next step will refuse."""
    eid = _enroll(harness).json()["enrollment_id"]
    _generate_and_verify_otp(harness, eid)
    assert _consent(harness, eid).status_code == 200
    assert _status(harness) == "awaiting_face"

    _age(harness, eid, minutes=45)
    again = _restart(harness)

    assert again.status_code == 201
    assert again.json()["enrollment_id"] == eid, "one identity, several attempts"
    assert _status(harness) == "awaiting_otp"
    #: and the journey it refused before now runs
    assert _otp_generate(harness, eid).status_code == 200


def test_the_whole_journey_runs_again_after_a_restart(harness):
    """The proof that matters: not that a flag moved, but that the customer can
    actually get to the end this time."""
    eid = _enroll(harness).json()["enrollment_id"]
    _generate_and_verify_otp(harness, eid)
    assert _consent(harness, eid).status_code == 200
    _age(harness, eid, minutes=45)

    assert _restart(harness).status_code == 201
    _generate_and_verify_otp(harness, eid)
    assert _consent(harness, eid).status_code == 200
    assert _face(harness, eid, VEC_A).status_code == 200
    assert _status(harness) == "enrolled"


def test_the_erased_attempt_leaves_nothing_of_itself_behind(harness):
    """"Erase" has to mean it. The consent is gone, so it must be given again;
    the code that was live is gone, so it cannot be replayed."""
    eid = _enroll(harness).json()["enrollment_id"]
    gen = _otp_generate(harness, eid)
    old_code = harness.decrypt_otp(gen.json()["ciphered_otp"])
    _age(harness, eid, minutes=45)

    assert _restart(harness).status_code == 201

    con = sqlite3.connect(harness.db_path)
    row = con.execute(
        "select consent_version, consent_at, embedding_encrypted from enrollments where id=?",
        (eid,),
    ).fetchone()
    (otps,) = con.execute(
        "select count(*) from otp_records where enrollment_id=?", (eid,)
    ).fetchone()
    con.close()

    assert row == (None, None, None), "the attempt's consent and face must not survive"
    assert otps == 0, "the code that was live must not survive its own attempt"

    #: and the old code cannot be spent against the new attempt
    replayed = harness.client.post(
        f"/api/v1/enrollments/{eid}/otp",
        json={"otp_code_enc": harness.seal_otp(old_code)},
    )
    assert replayed.status_code != 200


def test_the_restart_takes_the_new_credential(harness):
    """They are starting again — they may well choose a different password, and
    the record must hold the one they just typed, not the one they abandoned."""
    eid = _enroll(harness).json()["enrollment_id"]
    con = sqlite3.connect(harness.db_path)
    (before,) = con.execute(
        "select password_hash from enrollments where id=?", (eid,)
    ).fetchone()
    con.close()

    _age(harness, eid, minutes=45)
    assert _restart(harness, password="A-Completely-Different-1").status_code == 201

    con = sqlite3.connect(harness.db_path)
    (after,) = con.execute(
        "select password_hash from enrollments where id=?", (eid,)
    ).fetchone()
    con.close()
    assert after != before


def test_the_restart_is_recorded(harness):
    """An identity that quietly resets itself is indistinguishable from one that
    was tampered with. The attempt is erased; the fact of it is not."""
    eid = _enroll(harness).json()["enrollment_id"]
    _age(harness, eid, minutes=45)
    _restart(harness)

    con = sqlite3.connect(harness.db_path)
    outcomes = [
        r[0]
        for r in con.execute(
            "select outcome from audit_events where enrollment_id=? order by id", (eid,)
        )
    ]
    con.close()
    assert "created" in outcomes and "restarted" in outcomes


# --- the three things it must never erase ------------------------------------


def test_a_finished_enrolment_is_never_erased(harness):
    """Owner ruling: erase the UNFINISHED only. This customer did every step;
    if the last message never reached them, the bank's sign-in check completes
    it. Erasing here would destroy a real face binding over a lost notification.
    """
    eid = _enroll_with_face(harness, username=DEMO_USER, vec=VEC_A)
    _age(harness, eid, minutes=600)

    again = _restart(harness)

    assert again.status_code == 201
    assert again.json()["status"] == "enrolled"
    assert _status(harness) == "enrolled"


def test_a_revoked_enrolment_is_never_erased(harness):
    """Someone replacing a lost phone sits at `awaiting_face` having ALREADY
    proved their number and consented — revocation deliberately does not send
    them back to the start. They look exactly like an abandoner by stage, and
    are told apart by their template history."""
    eid = _enroll_with_face(harness, username=DEMO_USER, vec=VEC_A)
    assert harness.client.post(
        f"/api/v1/enrollments/{eid}/face/revoke", json={"reason": "lost_device"}
    ).status_code == 200
    assert _status(harness) == "awaiting_face"
    _age(harness, eid, minutes=600)

    assert _restart(harness).status_code == 201

    assert _status(harness) == "awaiting_face", "a rebinding customer keeps their progress"
    con = sqlite3.connect(harness.db_path)
    (consent,) = con.execute(
        "select consent_version from enrollments where id=?", (eid,)
    ).fetchone()
    con.close()
    assert consent == "v1", "re-asking for a consent already given is theatre"


def test_a_live_attempt_is_never_erased(harness):
    """Two devices, or one slow customer. Erasing the attempt out from under a
    running journey would invalidate the code they are in the middle of typing —
    so recency is checked, not just the stage."""
    eid = _enroll(harness).json()["enrollment_id"]
    _generate_and_verify_otp(harness, eid)
    assert _consent(harness, eid).status_code == 200

    again = _restart(harness)

    assert again.status_code == 201
    assert again.json()["status"] == "awaiting_face", "the live journey is handed back"
    assert _status(harness) == "awaiting_face"


def test_the_window_is_configurable_and_the_control_notices(harness, monkeypatch):
    """The default follows the orchestrator's own wait window. A deployment that
    moves one must be able to move the other — and a setting nothing reads is
    indistinguishable from one that is ignored."""
    settings = get_settings()
    eid = _enroll(harness).json()["enrollment_id"]
    _generate_and_verify_otp(harness, eid)
    assert _consent(harness, eid).status_code == 200
    _age(harness, eid, minutes=45)

    #: an hour's patience: the same record is NOT yet abandoned
    monkeypatch.setattr(settings, "enrolment_restart_after_seconds", 3600)
    assert _restart(harness).json()["status"] == "awaiting_face"

    #: the shipped window: it is
    monkeypatch.setattr(settings, "enrolment_restart_after_seconds", 1800)
    assert _restart(harness).json()["status"] == "awaiting_otp"
