"""THE LAST STEP: an enrolment is not finished until the BANK says so.

Owner ruling 2026-09-11. A face submission is the last thing the CUSTOMER does,
not the last thing that happens. Calling it `enrolled` made an identity look
complete while the bank had never heard of it, and — worse — protected that
customer from starting again, because this service protects the finished.

    awaiting_face
          |  the customer submits their face
    awaiting_activation      <- the customer is done, the bank is not
          |  the bank provisions, then the orchestrator says so
    enrolled                 <- the whole thing is finished

This service must never know about the bank, so it cannot look and see whether
a profile was made. It can only be TOLD, which is what the activate step is.
"""
import sqlite3

from tests.test_api import (
    DEMO_USER,
    VEC_A,
    VEC_A_CLOSE,
    VEC_ORTHOGONAL,
    _activate,
    _enroll,
    _enroll_up_to_face,
    _enroll_with_face,
    _face,
    _verify,
)


def _row(harness, eid, column):
    con = sqlite3.connect(harness.db_path)
    try:
        return con.execute(
            f"select {column} from enrollments where id=?", (eid,)
        ).fetchone()[0]
    finally:
        con.close()


def _revoke(harness, eid, reason="lost_device"):
    return harness.client.post(
        f"/api/v1/enrollments/{eid}/face/revoke", json={"reason": reason}
    )


def _status_body(harness, username=DEMO_USER):
    return harness.client.get(
        f"/api/v1/enrollments/by-username/{username}/status"
    ).json()


# --- the customer's half stops short ----------------------------------------


def test_a_submitted_face_does_not_finish_the_enrolment(harness):
    """THE RULING, stated once. The response says so rather than reporting a
    finish time it does not have."""
    eid = _enroll_up_to_face(harness)

    assert _row(harness, eid, "status") == "awaiting_activation"
    assert _row(harness, eid, "enrolled_at") is None, (
        "a finish time for an enrolment that has not finished would be a lie "
        "with a timestamp on it"
    )


def test_an_unactivated_identity_cannot_be_used_to_sign_in(harness):
    """The point of stopping short. A half-finished identity must not verify —
    otherwise the new state would be a label with no consequence.

    REFUSED AS A MISMATCH, not as an error, and that is deliberate: the verify
    endpoint looks up `status == "enrolled"` and answers an unfound identity
    with the same rejected/0.0 shape it gives a wrong face. Saying "that
    enrolment is not activated yet" would confirm the username exists and
    volunteer where in the journey it is.
    """
    _enroll_up_to_face(harness)

    verify = _verify(harness, VEC_A_CLOSE)

    assert verify.status_code == 200
    assert verify.json()["verdict"] == "rejected", (
        "the face MATCHES the one on file — it is the missing activation that "
        "refuses it, which is the whole assertion"
    )
    assert _status_body(harness)["enrolled"] is False


def test_the_bank_finishes_it_and_then_the_identity_works(harness):
    """And the other side of the same fact: activation is the whole difference
    between an identity that works and one that does not."""
    eid = _enroll_up_to_face(harness)

    assert _activate(harness, eid).status_code == 200

    assert _row(harness, eid, "status") == "enrolled"
    body = _status_body(harness)
    assert body["enrolled"] is True
    assert body["status"] == "enrolled"
    assert _verify(harness, VEC_A_CLOSE).json()["verdict"] == "verified"


# --- the step is a workflow node, so it gets retried ------------------------


def test_activating_twice_costs_nothing_and_does_not_move_the_finish_time(harness):
    """The caller is a workflow step and a workflow step gets retried.

    Asserted on the TIMESTAMP, not merely on the status code: a second
    activation that returned 200 while re-stamping the finish time would pass a
    status check and still have rewritten when this enrolment finished.
    """
    eid = _enroll_up_to_face(harness)
    first = _activate(harness, eid)
    assert first.status_code == 200
    finished_at = _row(harness, eid, "enrolled_at")
    assert finished_at is not None

    second = _activate(harness, eid)

    assert second.status_code == 200
    assert second.json() == first.json()
    assert _row(harness, eid, "enrolled_at") == finished_at, "the FIRST finish stands"


def test_an_enrolment_that_has_not_reached_the_face_step_cannot_be_activated(harness):
    """FAILS CLOSED. Activating early would hand out a working identity for a
    face that was never submitted — the worst thing this service could do."""
    eid = _enroll(harness).json()["enrollment_id"]

    refused = _activate(harness, eid)

    assert refused.status_code == 409, refused.text
    assert _row(harness, eid, "status") == "awaiting_otp"


def test_activating_something_that_does_not_exist_is_404(harness):
    assert _activate(harness, "no-such-enrollment").status_code == 404


# --- the stranding this ruling exists to prevent ----------------------------


def test_a_customer_the_bank_never_activated_CAN_START_AGAIN(harness):
    """THE CASE THE RULING WAS MADE FOR, and the one that nearly stayed broken.

    Someone whose activation never came has done everything asked of them and
    has nothing to show for it. They must be able to start over.

    This very nearly did not work. `_superseded` used to refuse any record with
    template history, and this customer HAS a template — they submitted a face.
    The protection meant for a lost-phone re-binder would have caught exactly
    the person it was never about.
    """
    eid = _enroll_up_to_face(harness)
    assert _row(harness, eid, "status") == "awaiting_activation"

    again = _enroll(harness)

    assert again.status_code == 201
    assert again.json()["enrollment_id"] == eid, "same identity, same record"
    assert _row(harness, eid, "status") == "awaiting_otp", (
        "the dead attempt is erased and the customer begins again"
    )


def test_a_finished_customer_is_still_protected_from_being_erased(harness):
    """The other half, without which the test above proves only that the guard
    was removed. A finished enrolment is never destroyed by somebody typing the
    username again."""
    eid = _enroll_with_face(harness)

    again = _enroll(harness)

    assert again.status_code == 201
    assert again.json()["status"] == "enrolled"
    assert _row(harness, eid, "status") == "enrolled"


def test_a_lost_phone_re_binder_is_still_protected_from_being_erased(harness):
    """And the case the old template-history test was actually for: revoked,
    sitting at `awaiting_face`, already provisioned. Still not erasable."""
    eid = _enroll_with_face(harness)
    assert _revoke(harness, eid).status_code == 200
    assert _row(harness, eid, "status") == "awaiting_face"

    again = _enroll(harness)

    assert again.status_code == 201
    assert _row(harness, eid, "status") == "awaiting_face", (
        "a revoked customer is mid-replacement, not mid-abandonment"
    )


# --- a re-bind does not wait for work the bank has already done -------------


def test_a_replacement_face_goes_straight_back_to_enrolled(harness):
    """No second activation, because there is nothing to provision twice.

    Making this customer wait would be waiting for an event that is never
    coming: the bank has no work to do and no reason to act. `activated_at` is
    what makes that decidable here — revocation clears the finish time, so
    without it the record could not tell a re-binder from a first-timer.
    """
    eid = _enroll_with_face(harness, vec=VEC_A)
    assert _revoke(harness, eid).status_code == 200

    rebind = _face(harness, eid, VEC_ORTHOGONAL)

    assert rebind.status_code == 200
    assert rebind.json()["status"] == "enrolled"
    assert rebind.json()["enrolled_at"] is not None
    assert _verify(harness, VEC_ORTHOGONAL).json()["verdict"] == "verified"


def test_revocation_keeps_the_record_that_the_bank_once_provisioned(harness):
    """Stated directly on the column, because every behaviour above rests on
    it. Losing a phone does not undo the bank having made a profile."""
    eid = _enroll_with_face(harness)
    before = _row(harness, eid, "activated_at")
    assert before is not None

    assert _revoke(harness, eid).status_code == 200

    assert _row(harness, eid, "enrolled_at") is None, "not finished right now"
    assert _row(harness, eid, "activated_at") == before, "but it did happen"
