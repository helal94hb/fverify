"""Generate the production secrets fverify needs.

RUN THIS IN A SECURE PLACE. It prints real keys to the screen. Do not run it
where the output is logged or shared, do not paste the output into git, and do
not run it in this project's chat session. Pipe the values straight into your
secrets manager (AWS Secrets Manager / Parameter Store).

    python scripts/generate_keys.py

Five secrets, four of them plain random values. Two are keypairs whose halves
live in different services, so the script prints both halves and says where each
one goes.

GENERATE ONCE. `FV_AT_REST_KEY` encrypts stored face templates — lose it or
change it and every stored template becomes permanently unreadable. Treat all of
these as generate-once-and-vault, not rotate-casually.
"""

import base64
import os
import secrets

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def _rsa_pair() -> tuple[str, str]:
    """Return (private_pem, public_pem) for a fresh 3072-bit RSA key."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    public_pem = (
        key.public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )
    return private_pem, public_pem


def _rule(title: str) -> None:
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)


def main() -> None:
    at_rest_key = Fernet.generate_key().decode()
    otp_hash_salt = secrets.token_urlsafe(32)
    otp_export_key = base64.b64encode(os.urandom(32)).decode()
    seal_private_pem, seal_public_pem = _rsa_pair()
    bank_private_pem, bank_public_pem = _rsa_pair()
    bank_key_id = "bank-prod1"

    print(
        "\nfverify production secrets — generated fresh.\n"
        "Store these in your secrets manager. Never commit them. Never rerun this\n"
        "for a service that already has data — a new FV_AT_REST_KEY loses every\n"
        "stored face template."
    )

    _rule("1) fverify environment  (FV_* — the five it refuses to boot without)")
    print(f"FV_AT_REST_KEY={at_rest_key}")
    print(f"FV_OTP_HASH_SALT={otp_hash_salt}")
    print(f"FV_OTP_EXPORT_KEY={otp_export_key}")
    print(f"FV_BANK_KEY_ID={bank_key_id}")
    print("\nFV_SEAL_PRIVATE_KEY_PEM=  (fverify's own private key — opens inbound envelopes)")
    print(seal_private_pem.rstrip())
    print("\nFV_BANK_PUBLIC_KEY_PEM=  (the bank's PUBLIC half — seals verified names)")
    print(bank_public_pem.rstrip())

    _rule("2) BFF / backend  (the OTHER half of the bank pair — opens sealed names)")
    print("Give this private key to the BFF, matched to FV_BANK_KEY_ID above.")
    print("The two halves must be from THIS run, or sign-in fails closed.")
    print(bank_private_pem.rstrip())

    _rule("3) The app bundle  (the PUBLIC half of fverify's seal pair)")
    print("Ships in the app (ml/seal.ts) so the client can seal to fverify.")
    print(seal_public_pem.rstrip())

    _rule("Where each goes — one line")
    print("  FV_AT_REST_KEY, FV_OTP_HASH_SALT, FV_OTP_EXPORT_KEY  -> fverify only")
    print("  FV_SEAL_PRIVATE_KEY_PEM  -> fverify   | its public half -> app bundle")
    print("  FV_BANK_PUBLIC_KEY_PEM   -> fverify   | its private half -> BFF")
    print("  FV_BANK_KEY_ID           -> both fverify and the BFF, identical")
    print("\nFor a .env file, multi-line PEMs use literal \\n escapes; a secrets")
    print("manager takes them as-is. Done — vault these and delete this output.\n")


if __name__ == "__main__":
    main()
