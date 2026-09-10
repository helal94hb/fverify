"""Password hashing for the stored credential — argon2id.

WHY THIS MODULE EXISTS
    The credential was hashed with `otp.hash_secret()`: one SHA-256 round over
    a SINGLE GLOBAL salt read from config. Three consequences, all measurable:

      - identical passwords produce identical hashes, so the database itself
        discloses which customers share a password (this was visible in the dev
        data: four users, one shared prefix);
      - one global salt means one rainbow table covers every row, and the salt
        lives in config rather than in the row;
      - a single SHA-256 round is a few nanoseconds on a GPU, so a stolen
        database is enumerable at billions of guesses per second.

    The give-away is where that function lives: `otp.py`. It was written for OTP
    codes, and for those it is CORRECT — a six-digit code that expires in ten
    minutes, is single-use and attempt-capped does not need stretching, because
    the attacker has no time to spend. A password at rest is the opposite: it is
    long-lived, reused across services, and the attacker has forever. Reusing
    one for the other is the mistake, not the function.

    `otp.hash_secret` is deliberately left in place and unchanged for OTPs.

PARAMETERS
    argon2id at the OWASP baseline: m=19 MiB, t=2, p=1. argon2id is the hybrid
    variant — Argon2i's side-channel resistance on the first pass, Argon2d's
    GPU resistance thereafter — and is the variant recommended for password
    storage by both OWASP and RFC 9106.

    Each hash carries its OWN random salt inside the PHC string, so two rows
    with the same password are indistinguishable. That is the property the old
    scheme did not have and could not be tuned into having.

CURRENT REALITY, STATED SO NOBODY ASSUMES OTHERWISE
    Nothing in this service verifies a password today: `password_hash` is
    written at enrolment and never read. `verify_password` exists so that when
    that changes, the legacy rows are handled correctly rather than discovered
    at the worst moment.
"""

from __future__ import annotations

import hmac
import re

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from argon2.low_level import Type

#: OWASP Password Storage Cheat Sheet baseline for argon2id.
#: memory is the expensive dimension for an attacker with GPUs; raise it before
#: raising time_cost if this is ever tuned.
_HASHER = PasswordHasher(
    time_cost=2,
    memory_cost=19456,      # 19 MiB
    parallelism=1,
    hash_len=32,
    salt_len=16,
    type=Type.ID,
)

#: The scheme this replaces: a bare 64-character hex SHA-256 digest, no prefix,
#: no salt of its own. Recognised ONLY so existing rows can still be verified.
_LEGACY_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def hash_password(plaintext: str) -> str:
    """Return a PHC-format argon2id hash. Every call returns a different value
    for the same input — that is the point, not a bug."""
    return _HASHER.hash(plaintext)


def verify_password(stored: str, plaintext: str) -> bool:
    """True when `plaintext` matches `stored`. Never raises on a bad hash.

    Handles the legacy digest so a row written before this module can still be
    checked. Legacy comparison is constant-time; a hash-shaped string is still
    a secret comparison.
    """
    if not stored:
        return False

    if _LEGACY_SHA256.match(stored):
        from .otp import hash_secret  # local import: legacy path only
        return hmac.compare_digest(stored, hash_secret(plaintext))

    try:
        return _HASHER.verify(stored, plaintext)
    except (VerificationError, InvalidHashError):
        return False


def needs_rehash(stored: str) -> bool:
    """True when `stored` is legacy, or argon2 with parameters below current.

    Rehashing requires the plaintext, so it can only happen during a successful
    verification — which is why this is a question and not an action.
    """
    if not stored or _LEGACY_SHA256.match(stored):
        return True
    try:
        return _HASHER.check_needs_rehash(stored)
    except (InvalidHashError, ValueError):
        return True
