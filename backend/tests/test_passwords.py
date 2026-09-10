"""Controls for the credential hashing.

Each asserts the FIXED behaviour and, where it can, reproduces the defect it
replaced — a control that only demonstrates the good case cannot tell a fix
from a test that never exercised the bug.
"""

from app import passwords
from app.otp import hash_secret

PW = "Str0ngPass!23"


def test_two_customers_with_the_same_password_get_different_hashes():
    """THE defect, stated as a property.

    Under the old scheme this was FALSE: one global salt meant one password
    always produced one digest, so the database disclosed which customers
    shared a password. The dev data showed it plainly — four users, one hash.
    """
    assert passwords.hash_password(PW) != passwords.hash_password(PW)

    #: and the reproduction, so the control can fail if the property regresses
    assert hash_secret(PW) == hash_secret(PW), (
        "the legacy scheme is expected to be deterministic; if this ever fails "
        "the comparison this test draws is no longer meaningful"
    )


def test_it_is_argon2id_not_a_bare_digest():
    h = passwords.hash_password(PW)
    assert h.startswith("$argon2id$"), h[:20]
    #: parameters are part of the stored hash, so a future tuning is detectable
    #: per-row rather than guessed at
    assert "m=19456" in h and "t=2" in h and "p=1" in h


def test_round_trip_and_refusal():
    h = passwords.hash_password(PW)
    assert passwords.verify_password(h, PW) is True
    assert passwords.verify_password(h, PW + "x") is False
    assert passwords.verify_password(h, "") is False


def test_it_fits_the_column():
    """String(128). 97 today; asserted so a parameter change that overflows the
    column is caught here rather than as a truncated hash in production."""
    assert len(passwords.hash_password(PW)) <= 128


def test_a_legacy_row_still_verifies_and_is_flagged_for_rehash():
    """Rows written before this module must not become unverifiable — that
    would lock customers out in the name of security."""
    legacy = hash_secret(PW)
    assert passwords.verify_password(legacy, PW) is True
    assert passwords.verify_password(legacy, "wrong") is False
    assert passwords.needs_rehash(legacy) is True
    assert passwords.needs_rehash(passwords.hash_password(PW)) is False


def test_garbage_never_raises():
    """A malformed stored hash is a refusal, not a 500."""
    for bad in ("", "not-a-hash", "$argon2id$broken", "x" * 200):
        assert passwords.verify_password(bad, PW) is False


def test_the_enrolment_path_uses_it():
    """Ties the controls above to the shipped code: the unit tests exercise the
    module, this asserts the module is what enrolment actually calls."""
    from pathlib import Path

    src = (Path(__file__).parent.parent / "app" / "api.py").read_text(encoding="utf-8")
    assert "passwords.hash_password(cred.password)" in src
    assert "otp.hash_secret(cred.password)" not in src, (
        "enrolment is still hashing the credential with the OTP digest"
    )
