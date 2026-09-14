"""SIGN IN — verifying the credential this identity enrolled with.

WHY THIS ENDPOINT EXISTS (owner ruling, restated 2026-09-12: fverify IS the
bank's identity management system, so everything authenticates against it).

Until now nothing in this service read `password_hash`. It was written at every
enrolment and consumed by nothing, while the BANK kept its own password hashes
and checked them itself — two identity stores, with the authoritative one unable
to answer the only question identity exists to answer. Measured the same day:
the web sign-in ran entirely on the bank's stub, and the mobile "real" path went
out to the orchestrator and came straight back to that same stub through a
cloudflare tunnel that no longer resolves. Nothing verified anything.

WHAT IS ASSERTED HERE, in order of how badly it would hurt to get wrong:
  * the right password is accepted and the wrong one is not (the positive
    control first, because an endpoint that refused everything would satisfy
    every other test in this file);
  * a rejection tells you NOTHING about why — an unknown username and a wrong
    password are the same answer, in the same shape;
  * the guessing is capped, on the same mechanism the face factor uses;
  * plaintext is refused, so a caller cannot fall back out of the envelope.
"""

DEMO_USER = "cred.user"
DEMO_MOBILE = "01000000001"
DEMO_PASSWORD = "Sup3r#Secret1"

VERIFY = "/api/v1/verifications/credential"


def _enroll(harness, username=DEMO_USER, password=DEMO_PASSWORD, mobile=DEMO_MOBILE):
    return harness.client.post(
        "/api/v1/enrollments",
        json={
            "credential_enc": harness.seal({"username": username, "password": password}),
            "mobile": mobile,
        },
    )


def _verify(harness, username, password):
    return harness.client.post(
        VERIFY,
        json={"credential_enc": harness.seal({"username": username, "password": password})},
    )


def test_the_enrolled_credential_is_accepted(harness):
    """THE POSITIVE CONTROL, and it goes first deliberately: every refusal test
    below is satisfied by an endpoint that refuses everybody."""
    _enroll(harness)

    res = _verify(harness, DEMO_USER, DEMO_PASSWORD)

    assert res.status_code == 200
    body = res.json()
    assert body["verdict"] == "verified"
    #: the stage travels with a VERIFIED credential, because the caller has to
    #: tell "right password, enrolment unfinished" from "right password, ready"
    assert body["status"] == "awaiting_otp"


def test_a_wrong_password_is_rejected(harness):
    _enroll(harness)

    res = _verify(harness, DEMO_USER, "Wr0ng#Password1")

    assert res.status_code == 200
    assert res.json()["verdict"] == "rejected"


def test_an_unknown_username_is_rejected_IDENTICALLY(harness):
    """ANTI-ENUMERATION, and the assertion is on the WHOLE body rather than the
    verdict alone. A rejection that carried the stage, or a 404, or any extra
    key, would answer "does this person bank here" to anyone willing to guess —
    the same directory `/verifications/challenge` deliberately refuses to be.
    """
    _enroll(harness)

    wrong_password = _verify(harness, DEMO_USER, "Wr0ng#Password1")
    no_such_user = _verify(harness, "nobody.here", DEMO_PASSWORD)

    assert wrong_password.status_code == no_such_user.status_code == 200
    assert wrong_password.json() == no_such_user.json()
    #: `subject_enc` is null here and that is load-bearing, not incidental: it
    #: SEALS the identity that was proven, so a rejection carrying one would
    #: answer "does this username exist" to anyone willing to guess — the very
    #: question this test exists to keep unanswered. (It replaced the earlier
    #: `user_ref` HMAC in the login cleanse; same role, same null-on-rejection.)
    #: The whole-body form is what catches a field being added or renamed.
    assert no_such_user.json() == {
        "verdict": "rejected",
        "status": None,
        "subject_enc": None,
    }


def test_plaintext_is_refused_rather_than_treated_as_a_password(harness):
    """FAIL CLOSED OUT OF THE ENVELOPE. The orchestrator persists its inputs in
    run state, so a password crossing in the clear is readable in a console
    afterwards. A caller must not be able to opt out by simply not sealing."""
    _enroll(harness)

    res = harness.client.post(
        VERIFY,
        json={"credential_enc": f'{{"username": "{DEMO_USER}", "password": "{DEMO_PASSWORD}"}}'},
    )

    assert res.status_code == 422
    #: and it is NOT a rejection — a malformed envelope is not a wrong
    #: password, and telling them apart is what stops a bad client looking
    #: like a bad customer
    assert "verdict" not in res.text


def test_guessing_is_capped(harness):
    """The face factor locks after repeated failures; a password endpoint
    without the same cap is a guessing oracle, and argon2 slows an attacker
    down without stopping one."""
    _enroll(harness)

    codes = [_verify(harness, DEMO_USER, f"Wr0ng#Guess{i}").status_code for i in range(5)]

    assert 429 in codes, f"never locked out: {codes}"
    #: and the lock holds against the CORRECT password too — otherwise the cap
    #: is advisory and the attacker simply keeps going until they are right
    assert _verify(harness, DEMO_USER, DEMO_PASSWORD).status_code == 429


def test_the_lockout_is_per_identity(harness):
    """One customer being attacked must not lock everybody else out — which is
    the shape of a denial-of-service dressed as a security control."""
    _enroll(harness)
    _enroll(harness, username="other.user", mobile="01000000002")

    for i in range(5):
        _verify(harness, DEMO_USER, f"Wr0ng#Guess{i}")

    assert _verify(harness, DEMO_USER, DEMO_PASSWORD).status_code == 429
    assert _verify(harness, "other.user", DEMO_PASSWORD).json()["verdict"] == "verified"


def test_an_unknown_username_still_spends_the_hashing_work(harness, monkeypatch):
    """THE TIMING EQUALISER, AND IT HAD NO TEST UNTIL THIS ONE.

    A negative control found it: deleting `decoy_hash` and returning early on a
    missing row left every other test in this file green. The endpoint would
    then answer an unknown username in microseconds and a known one after a full
    argon2 verification — ~19 MiB and two passes — and a stopwatch tells them
    apart. That turns the service into the directory of who banks here that
    `/verifications/challenge` deliberately refuses to be.

    ASSERTED ON THE WORK, NOT THE CLOCK. A wall-clock test of an argon2 delta is
    flaky on a shared machine and would eventually be deleted for being flaky —
    which is how a real control gets removed for a good-sounding reason. What is
    deterministic is that the verification RAN: no row, and `verify_password` is
    still called exactly once.
    """
    from app import passwords

    calls = []
    real = passwords.verify_password
    monkeypatch.setattr(
        passwords, "verify_password",
        lambda stored, plaintext: calls.append(stored) or real(stored, plaintext),
    )

    res = _verify(harness, "nobody.here", DEMO_PASSWORD)

    assert res.json()["verdict"] == "rejected"
    assert len(calls) == 1, "a missing row must cost what a present one costs"
    assert calls[0] == passwords.decoy_hash(), "it must be the decoy that was spent"


def test_both_outcomes_are_audited(harness):
    """An authentication service that does not record its verdicts cannot be
    asked afterwards what happened — and the lockout above is COUNTED from
    these rows, so the audit is load-bearing, not decorative."""
    _enroll(harness)
    _verify(harness, DEMO_USER, "Wr0ng#Password1")
    _verify(harness, DEMO_USER, DEMO_PASSWORD)

    events = harness.client.get("/api/v1/audit/recent").json()["events"]
    outcomes = [e["outcome"] for e in events if e.get("event") == "credential"]

    assert "rejected" in outcomes
    assert "verified" in outcomes
