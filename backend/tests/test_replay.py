"""Controls for the verification replay hole.

Before this, `/verifications` took {username, embedding_enc} with no notion of
freshness: ONE captured envelope authenticated that customer's face for as long
as the enrolment lived. Nothing about it looked wrong — it was a valid envelope
containing a genuine embedding, and it would pass every time.

Each control here asserts the refusal AND, where it can, shows the same payload
succeeding once first — a replay test that never demonstrates the original
success has not shown that replay was possible.
"""

from tests.test_api import (  # noqa: F401
    DEMO_USER,
    VEC_A,
    VEC_ORTHOGONAL,
    _challenge,
    _enroll_with_face,
    _verify,
)


def test_the_same_envelope_cannot_be_used_twice(harness):
    """THE defect. The first submission succeeds; the identical bytes fail."""
    _enroll_with_face(harness)
    nonce = _challenge(harness)
    envelope = harness.seal_v2(VEC_A, nonce)

    first = harness.client.post(
        "/api/v1/verifications",
        json={"username": DEMO_USER, "embedding_enc": envelope},
    )
    assert first.status_code == 200, first.json()
    assert first.json()["verdict"] == "verified"

    #: byte-for-byte the same request, which is exactly what a captured
    #: envelope is
    replay = harness.client.post(
        "/api/v1/verifications",
        json={"username": DEMO_USER, "embedding_enc": envelope},
    )
    assert replay.status_code == 400
    assert replay.json()["type"].endswith("challenge-invalid")


def test_a_payload_with_no_challenge_is_refused(harness):
    """An enc2 envelope with no nonce at all — and, by extension, every enc1
    envelope, which has nowhere to put one."""
    _enroll_with_face(harness)
    r = harness.client.post(
        "/api/v1/verifications",
        json={"username": DEMO_USER, "embedding_enc": harness.seal_v2(VEC_A)},
    )
    assert r.status_code == 400
    assert r.json()["type"].endswith("challenge-required")

    r1 = harness.client.post(
        "/api/v1/verifications",
        json={"username": DEMO_USER, "embedding_enc": harness.seal(VEC_A)},
    )
    assert r1.status_code == 400


def test_a_nonce_swapped_onto_a_captured_envelope_breaks_the_tag(harness):
    """The attack the DB check alone would not stop.

    A replayer holding a captured envelope can request a fresh nonce of their
    own. If the nonce merely travelled BESIDE the payload they would splice it
    in and replay successfully. It is inside the AEAD tag, so the splice
    destroys the ciphertext's authenticity.
    """
    import base64
    import json

    _enroll_with_face(harness)
    captured = harness.seal_v2(VEC_A, _challenge(harness))
    fresh = _challenge(harness)

    raw = captured[len("enc2:"):]
    body = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
    body["n"] = fresh                     # splice in a nonce that IS valid
    spliced = "enc2:" + base64.urlsafe_b64encode(
        json.dumps(body).encode()
    ).rstrip(b"=").decode()

    r = harness.client.post(
        "/api/v1/verifications",
        json={"username": DEMO_USER, "embedding_enc": spliced},
    )
    #: the challenge is real and unused, so the DB check PASSES — and the
    #: cryptography still refuses. That is the point of binding over adjacency.
    assert r.status_code != 200 or r.json()["verdict"] != "verified"


def test_a_challenge_issued_to_one_user_does_not_work_for_another(harness):
    _enroll_with_face(harness, username=DEMO_USER)
    #: a DIFFERENT face. Two people cannot share one, and since 1:N dedup
    #: landed the service refuses the attempt outright -- which is the correct
    #: behaviour and made this setup invalid.
    _enroll_with_face(harness, username="other_person", vec=VEC_ORTHOGONAL)

    stolen = _challenge(harness, username="other_person")
    r = harness.client.post(
        "/api/v1/verifications",
        json={"username": DEMO_USER,
              "embedding_enc": harness.seal_v2(VEC_A, stolen)},
    )
    assert r.status_code == 400
    assert r.json()["type"].endswith("challenge-invalid")


def test_an_expired_challenge_is_refused(harness):
    import time as _t

    from app.models import VerifyChallenge

    _enroll_with_face(harness)
    nonce = _challenge(harness)

    #: age it past the TTL rather than sleeping through it
    import sqlite3

    con = sqlite3.connect(harness.db_path)
    con.execute("update verify_challenges set expires_at=? where nonce=?",
                (_t.time() - 1, nonce))
    con.commit()
    con.close()

    r = harness.client.post(
        "/api/v1/verifications",
        json={"username": DEMO_USER, "embedding_enc": harness.seal_v2(VEC_A, nonce)},
    )
    assert r.status_code == 400
    assert r.json()["type"].endswith("challenge-invalid")
    assert VerifyChallenge is not None


def test_a_challenge_is_issued_for_an_unknown_user(harness):
    """Anti-enumeration: refusing here would turn the endpoint into a directory
    of who banks with us. The verification itself still refuses the identity,
    with a response shaped like an ordinary mismatch."""
    r = harness.client.post("/api/v1/verifications/challenge",
                            json={"username": "nobody_at_all"})
    assert r.status_code == 200
    assert r.json()["nonce"]
